// Xister.m — panel externo Free Fire iOS (arm64)
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <QuartzCore/QuartzCore.h>
#import <mach/mach.h>
#import <mach/vm_region.h>
#import <mach/vm_map.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <stdatomic.h>
#import <stdbool.h>
#import <math.h>
#import <string.h>
#import <dlfcn.h>
#import <sys/sysctl.h>
#import "fishhook.h"

#pragma mark - IOHID (API privada, declarada a mano)

typedef struct __IOHIDEvent *IOHIDEventRef;
typedef struct __IOHIDEventSystemClient *IOHIDEventSystemClientRef;
typedef uint32_t IOHIDDigitizerEventMask;
typedef uint32_t IOHIDEventField;

extern IOHIDEventRef IOHIDEventCreateDigitizerFingerEvent(CFAllocatorRef a, uint64_t ts,
    uint32_t index, uint32_t identity, double x, double y, double z,
    double pressure, double twist, bool range, bool touch,
    IOHIDDigitizerEventMask mask, uint32_t *changed);
extern void IOHIDEventSystemClientDispatchEvent(IOHIDEventSystemClientRef c, IOHIDEventRef e);
extern IOHIDEventSystemClientRef IOHIDEventSystemClientCreate(CFAllocatorRef a);
extern void IOHIDEventSetIntegerValue(IOHIDEventRef e, IOHIDEventField f, CFIndex v);

#define XS_FIELD_DISPLAY_INTEGRATED 0x000B001Du

#pragma mark - Matemáticas

typedef struct { float x, y; }    Vec2;
typedef struct { float x, y, z; } Vec3;

static inline Vec2  v2(float x, float y){ return (Vec2){x,y}; }
static inline Vec3  v3(float x, float y, float z){ return (Vec3){x,y,z}; }
static inline float v2len(Vec2 a){ return sqrtf(a.x*a.x + a.y*a.y); }
static inline Vec3  v3sub(Vec3 a, Vec3 b){ return v3(a.x-b.x, a.y-b.y, a.z-b.z); }
static inline float v3dist(Vec3 a, Vec3 b){ return sqrtf(v3sub(a,b).x*v3sub(a,b).x + v3sub(a,b).y*v3sub(a,b).y + v3sub(a,b).z*v3sub(a,b).z); }

static inline float clampf(float v, float lo, float hi){ return v < lo ? lo : (v > hi ? hi : v); }
static inline float lerpf(float a, float b, float t){ return a + (b-a)*t; }
static inline float smoothstepf(float t){ t = clampf(t,0.f,1.f); return t*t*(3.f-2.f*t); }

static inline float wrapdeg(float d){
    while (d > 180.f)  d -= 360.f;
    while (d < -180.f) d += 360.f;
    return d;
}

static inline uint32_t xsrng(uint32_t *s){
    uint32_t x = *s ? *s : 0x9E3779B9u;
    x ^= x << 13; x ^= x >> 17; x ^= x << 5;
    *s = x; return x;
}
static inline float xsgauss(uint32_t *s){
    float a = (float)(xsrng(s) & 0xFFFF) / 65535.f;
    float b = (float)(xsrng(s) & 0xFFFF) / 65535.f;
    return (a + b) - 1.f;
}

static inline bool xs_project(const float m[16], Vec3 p, float sw, float sh, Vec2 *o){
    float cx = m[0]*p.x + m[4]*p.y + m[8]*p.z  + m[12];
    float cy = m[1]*p.x + m[5]*p.y + m[9]*p.z  + m[13];
    float cw = m[3]*p.x + m[7]*p.y + m[11]*p.z + m[15];
    if (cw < 0.01f) return false;
    o->x = ((cx/cw) * 0.5f + 0.5f) * sw;
    o->y = (1.f - ((cy/cw) * 0.5f + 0.5f)) * sh;
    return true;
}

#pragma mark - Memoria

static inline mach_port_t xs_task(void){ return mach_task_self(); }

static bool xs_readable(uintptr_t addr, size_t len){
    if (!addr || addr < 0x100000000ULL || addr > 0x00007FFFFFFFFFFFULL) return false;
    if (!len || len > (64u << 20)) return false;
    mach_vm_address_t a = (mach_vm_address_t)addr;
    mach_vm_size_t sz = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t obj = MACH_PORT_NULL;
    kern_return_t kr = mach_vm_region(xs_task(), &a, &sz, VM_REGION_BASIC_INFO_64,
                                      (vm_region_info_t)&info, &cnt, &obj);
    if (obj != MACH_PORT_NULL) mach_port_deallocate(xs_task(), obj);
    if (kr != KERN_SUCCESS) return false;
    if (!(info.protection & VM_PROT_READ)) return false;
    return a <= (mach_vm_address_t)addr && (mach_vm_address_t)(addr + len) <= a + sz;
}

static bool xs_read(void *dst, uintptr_t src, size_t len){
    if (!xs_readable(src, len)) return false;
    mach_vm_size_t out = 0;
    return mach_vm_read_overwrite(xs_task(), (mach_vm_address_t)src, len,
                                  (mach_vm_address_t)dst, &out) == KERN_SUCCESS && out == len;
}

static bool xs_write(uintptr_t dst, const void *src, size_t len){
    if (!xs_readable(dst, len)) return false;
    return mach_vm_write(xs_task(), (mach_vm_address_t)dst, (vm_offset_t)src,
                         (mach_msg_type_number_t)len) == KERN_SUCCESS;
}

#define XSRD(T, addr, fb) ({ T _v = (fb); xs_read(&_v, (uintptr_t)(addr), sizeof(T)) ? _v : (fb); })

#pragma mark - Escáner AOB

static size_t xs_parse_sig(const char *sig, uint8_t *bytes, uint8_t *mask, size_t max){
    size_t n = 0;
    const char *p = sig;
    while (*p && n < max){
        while (*p == ' ') p++;
        if (!*p) break;
        if (p[0] == '?'){
            bytes[n] = 0; mask[n] = 0;
            p += (p[1] == '?') ? 2 : 1;
        } else {
            unsigned v = 0;
            for (int i = 0; i < 2; i++){
                char c = p[i]; unsigned d;
                if      (c >= '0' && c <= '9') d = c - '0';
                else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
                else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
                else return 0;
                v = (v << 4) | d;
            }
            bytes[n] = (uint8_t)v; mask[n] = 0xFF;
            p += 2;
        }
        n++;
    }
    return n;
}

static uintptr_t xs_scan_range(uintptr_t start, size_t len, const uint8_t *b,
                               const uint8_t *m, size_t pl){
    if (!start || !pl || pl > len) return 0;
    const uint8_t *end = (const uint8_t *)(start + len - pl);
    for (const uint8_t *cur = (const uint8_t *)start; cur <= end; cur++){
        const uint8_t *hit = memchr(cur, b[0], (size_t)(end - cur) + 1);
        if (!hit) return 0;
        cur = hit;
        size_t i = 1;
        for (; i < pl; i++) if (m[i] && cur[i] != b[i]) break;
        if (i == pl) return (uintptr_t)cur;
    }
    return 0;
}

static uintptr_t xs_scan_image(const char *image, const char *sig){
    uint8_t b[256], m[256];
    size_t pl = xs_parse_sig(sig, b, m, sizeof(b));
    if (!pl) return 0;
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++){
        const char *nm = _dyld_get_image_name(i);
        if (!nm || !strstr(nm, image)) continue;
        const struct mach_header_64 *h = (const struct mach_header_64 *)_dyld_get_image_header(i);
        if (!h) continue;
        intptr_t slide = _dyld_get_image_vmaddr_slide(i);
        const struct segment_command_64 *seg = (const struct segment_command_64 *)(h + 1);
        for (uint32_t c = 0; c < h->ncmds; c++){
            if (seg->cmd == LC_SEGMENT_64 && !strcmp(seg->segname, "__TEXT")){
                uintptr_t r = xs_scan_range((uintptr_t)(seg->vmaddr + slide),
                                            (size_t)seg->vmsize, b, m, pl);
                if (r) return r;
                break;
            }
            seg = (const struct segment_command_64 *)((const uint8_t *)seg + seg->cmdsize);
        }
    }
    return 0;
}

#pragma mark - Tabla de firmas

typedef enum { XS_SYM_CAMERA = 0, XS_SYM_LOCAL, XS_SYM_LIST, XS_SYM_VMAT, XS_SYM_AIM, XS_SYM_COUNT } XSSymID;

typedef struct {
    const char *name;
    const char *sig;
    int32_t pre;
    int32_t rip;
    uintptr_t addr;
    bool found;
} XSSym;

static XSSym gSym[XS_SYM_COUNT] = {
    [XS_SYM_CAMERA] = { "camera",     "48 8B 05 ?? ?? ?? ?? 48 8B 88 ?? ?? ?? ?? 48 85 C9 74", 0, 3, 0, false },
    [XS_SYM_LOCAL]  = { "local",      "48 8B 0D ?? ?? ?? ?? 48 85 C9 74 ?? 48 8B 01 48 8B 80 ?? ?? ?? ?? FF 50", 0, 3, 0, false },
    [XS_SYM_LIST]   = { "list",       "48 8B 1D ?? ?? ?? ?? 48 85 DB 74 ?? 45 31 E4", 0, 3, 0, false },
    [XS_SYM_VMAT]   = { "viewMatrix", "F3 0F 10 05 ?? ?? ?? ?? F3 0F 10 0D ?? ?? ?? ?? 0F 28", 0, 4, 0, false },
    [XS_SYM_AIM]    = { "aimRot",     "F3 0F 11 83 ?? ?? ?? ?? F3 0F 11 8B ?? ?? ?? ?? F3 0F 11 93", -6, -1, 0, false },
};

static uintptr_t xs_follow(uintptr_t at, int32_t disp){
    int32_t rel = 0;
    if (!xs_read(&rel, at + disp, 4)) return 0;
    return at + disp + 4 + (intptr_t)rel;
}

static int xs_resolve(void){
    int ok = 0;
    for (int i = 0; i < XS_SYM_COUNT; i++){
        XSSym *s = &gSym[i];
        uintptr_t hit = xs_scan_image("UnityFramework", s->sig);
        if (!hit) continue;
        if (s->pre) hit += s->pre;
        if (s->rip >= 0){
            uintptr_t t = xs_follow(hit, s->rip);
            if (!t) continue;
            s->addr = t;
        } else s->addr = hit;
        s->found = true;
        ok++;
    }
    return ok;
}

#pragma mark - Entidades

#define XS_MAX_ENT 64

typedef struct {
    uintptr_t ptr;
    Vec3 origin, head, neck, chest;
    float dist;
    bool visible, alive;
} XSEnt;

static XSEnt gEnt[XS_MAX_ENT];
static int   gEntCount = 0;
static float gVMat[16];
static Vec3  gLocalEye;
static bool  gHasCam = false;

static uintptr_t xs_global(XSSymID id){
    uintptr_t slot = gSym[id].addr;
    if (!slot) return 0;
    return XSRD(uintptr_t, slot, 0);
}

static bool xs_bone(uintptr_t ent, int idx, Vec3 *out){
    if (!ent) return false;
    uintptr_t arr = XSRD(uintptr_t, ent + 0x88, 0);
    if (!arr) return false;
    uintptr_t m = XSRD(uintptr_t, arr + (uintptr_t)idx * 0x30, 0);
    if (!m) return false;
    out->x = XSRD(float, m + 0x20, 0.f);
    out->y = XSRD(float, m + 0x24, 0.f);
    out->z = XSRD(float, m + 0x28, 0.f);
    return true;
}

static void xs_game_tick(void){
    gEntCount = 0;
    gHasCam = false;

    uintptr_t vm = gSym[XS_SYM_VMAT].addr;
    if (vm && xs_read(gVMat, vm, sizeof(gVMat))) gHasCam = true;

    uintptr_t cam = xs_global(XS_SYM_CAMERA);
    uintptr_t local = cam ? XSRD(uintptr_t, cam + 0x10, 0) : 0;
    if (local){
        Vec3 eye = {0};
        if (xs_bone(local, 8, &eye)) gLocalEye = eye;
    }

    uintptr_t cur = xs_global(XS_SYM_LIST);
    for (int i = 0; i < XS_MAX_ENT && cur; i++){
        uintptr_t next = XSRD(uintptr_t, cur + 0x08, 0);
        uintptr_t ent  = XSRD(uintptr_t, cur + 0x10, 0);
        if (ent){
            XSEnt *e = &gEnt[gEntCount];
            memset(e, 0, sizeof(*e));
            e->ptr = ent;
            if (xs_bone(ent, 0, &e->origin) && xs_bone(ent, 8, &e->head) &&
                xs_bone(ent, 7, &e->neck)   && xs_bone(ent, 6, &e->chest)){
                e->dist    = v3dist(gLocalEye, e->head);
                e->alive   = XSRD(uint8_t, ent + 0x54, 0) != 0;
                e->visible = XSRD(uint8_t, ent + 0x50, 0) != 0;
                if (e->alive && ent != local && e->dist > 0.5f && e->dist < 400.f) gEntCount++;
            }
        }
        if (next == cur) break;
        cur = next;
    }
}

static void xs_get_aim(Vec2 *o){
    uintptr_t r = gSym[XS_SYM_AIM].addr;
    o->x = r ? XSRD(float, r, 0.f) : 0.f;
    o->y = r ? XSRD(float, r + 4, 0.f) : 0.f;
}

static void xs_set_aim(Vec2 in){
    uintptr_t r = gSym[XS_SYM_AIM].addr;
    if (!r) return;
    xs_write(r, &in.x, 4);
    xs_write(r + 4, &in.y, 4);
}

static void xs_screen(float *w, float *h){
    CGSize s = UIScreen.mainScreen.bounds.size;
    CGFloat sc = UIScreen.mainScreen.nativeScale;
    *w = (float)(s.width * sc);
    *h = (float)(s.height * sc);
}

#pragma mark - Perfiles

typedef enum { P_CONS = 0, P_MED, P_AGR, P_HACK, P_COUNT } XSProfID;

typedef struct {
    const char *name, *desc;
    bool aimHead, aimNeck, aimDrag;
    float fov, speed, curve, overshoot, jitter, deadzone, maxStep, hyst;
    bool esp, boxes, skel, dist, names, line;
    float range;
} XSProf;

static XSProf gTab[P_COUNT] = {
    [P_CONS] = { "Conservador", "Casi indistinguible de un jugador manual",
        true, false, false, 6.f, 55.f, 2.4f, 0.06f, 0.55f, 0.9f, 1.6f, 2.2f,
        false, false, false, false, false, false, 60.f },
    [P_MED] = { "Medio", "Se nota, pero se defiende como lectura de juego",
        true, true, false, 14.f, 95.f, 1.9f, 0.11f, 0.38f, 0.6f, 3.2f, 1.5f,
        true, true, false, true, false, false, 90.f },
    [P_AGR] = { "Agresivo", "Full aim, ESP completo, algo de disimulo",
        true, true, true, 26.f, 150.f, 1.4f, 0.16f, 0.22f, 0.35f, 6.f, 0.9f,
        true, true, true, true, true, false, 150.f },
    [P_HACK] = { "Hacker", "Sin disimulo: snap duro y ESP total",
        true, true, true, 180.f, 420.f, 1.f, 0.22f, 0.05f, 0.05f, 45.f, 0.2f,
        true, true, true, true, true, true, 400.f },
};

static XSProf gP;
static _Atomic int gProfIdx = P_CONS;

static void xs_prof_apply(XSProfID id){
    if (id < 0 || id >= P_COUNT) return;
    gP = gTab[id];
    atomic_store(&gProfIdx, id);
}

#pragma mark - Toque inyectado

static IOHIDEventSystemClientRef xs_hid(void){
    static IOHIDEventSystemClientRef c;
    static dispatch_once_t o;
    dispatch_once(&o, ^{ c = IOHIDEventSystemClientCreate(kCFAllocatorDefault); });
    return c;
}

static void xs_send(int phase, Vec2 p, float pressure){
    CGFloat sc = UIScreen.mainScreen.nativeScale;
    IOHIDEventRef e = IOHIDEventCreateDigitizerFingerEvent(kCFAllocatorDefault,
        mach_absolute_time(), 1, 2, p.x * sc, p.y * sc, 0.0,
        pressure, 0.0, true, phase == 1, (IOHIDDigitizerEventMask)0, NULL);
    if (!e) return;
    IOHIDEventSetIntegerValue(e, XS_FIELD_DISPLAY_INTEGRATED, 1);
    IOHIDEventSystemClientDispatchEvent(xs_hid(), e);
    CFRelease(e);
}

static void xs_drag(Vec2 from, Vec2 to, double dur){
    xs_send(1, from, 0.7f);
    for (int i = 1; i <= 10; i++){
        float t = smoothstepf(i / 10.f);
        xs_send(2, v2(lerpf(from.x, to.x, t), lerpf(from.y, to.y, t)), 0.7f);
        usleep((useconds_t)(dur * 1e5));
    }
    xs_send(4, to, 0.f);
}

#pragma mark - Aim

static uintptr_t gTarget = 0;
static uint32_t  gRng = 0x1F2E3D4C;
static bool      gPulsed = false;
static float     gRemX, gRemY;

static float xs_score(const XSEnt *e, Vec2 cur, float *ang){
    Vec3 pt = (gP.boneIdxNeck()) ? e->neck : e->head;
    Vec3 d = v3sub(pt, gLocalEye);
    float yaw = atan2f(d.x, d.z) * 57.29578f;
    float pitch = atan2f(d.y, sqrtf(d.x*d.x + d.z*d.z)) * 57.29578f;
    float a = sqrtf(powf(wrapdeg(yaw - cur.x), 2) + powf(wrapdeg(pitch - cur.y), 2));
    *ang = a;
    if (a > gP.fov) return -1.f;
    float s = a + e->dist * 0.06f;
    if (!e->visible) s += 14.f;
    if (e->ptr == gTarget) s -= gP.hyst;
    return s;
}

static void xs_aim_tick(double dt){
    if (gEntCount == 0 || (!gP.aimHead && !gP.aimNeck && !gP.aimDrag)){ gTarget = 0; return; }

    Vec2 cur;
    xs_get_aim(&cur);

    const XSEnt *best = NULL;
    float bestS = 1e9f, bestA = 0.f;
    for (int i = 0; i < gEntCount; i++){
        float a = 0.f;
        float s = xs_score(&gEnt[i], cur, &a);
        if (s >= 0.f && s < bestS){ bestS = s; best = &gEnt[i]; bestA = a; }
    }
    if (!best){ gTarget = 0; gPulsed = false; return; }

    if (best->ptr != gTarget){ gTarget = best->ptr; gPulsed = false; }

    Vec3 d = v3sub(best->head, gLocalEye);
    float yaw   = atan2f(d.x, d.z) * 57.29578f;
    float pitch = atan2f(d.y, sqrtf(d.x*d.x + d.z*d.z)) * 57.29578f;
    Vec2 delta = v2(wrapdeg(yaw - cur.x), wrapdeg(pitch - cur.y));

    float len = v2len(delta);
    if (len > gP.deadzone){
        float step = fminf(fminf(len, gP.speed * (float)dt), gP.maxStep);
        float t = powf(smoothstepf(step / len), gP.curve);
        float over = len > 4.f ? 1.f + gP.overshoot : 1.f;
        gRemX = delta.x * t * over + xsgauss(&gRng) * gP.jitter;
        gRemY = delta.y * t * over + xsgauss(&gRng) * gP.jitter;
        xs_set_aim(v2(wrapdeg(cur.x + gRemX), clampf(cur.y + gRemY, -89.f, 89.f)));

        if (gP.aimDrag && !gPulsed && bestA < 2.5f && bestA > 0.4f){
            float sw, sh;
            xs_screen(&sw, &sh);
            Vec2 tp;
            if (xs_project(gVMat, best->head, sw, sh, &tp)){
                CGFloat sc = UIScreen.mainScreen.nativeScale;
                xs_drag(v2(sw/sc/2, sh/sc/2), v2(tp.x/sc, tp.y/sc), 0.05);
                gPulsed = true;
            }
        }
    }
}

#pragma mark - Overlay ESP

static UIWindow *gOvWin;
static UIView   *gOvRoot;
static CAShapeLayer *gLBox, *gLBone, *gLLine;
static NSMutableArray *gLabels;

static UIColor *cGold(void){ return [UIColor colorWithRed:0.94 green:0.83 blue:0.54 alpha:1]; }
static UIColor *cTeal(void){ return [UIColor colorWithRed:0.44 green:0.89 blue:0.75 alpha:1]; }

static UIWindowScene *xs_scene(void){
    for (UIScene *s in UIApplication.sharedApplication.connectedScenes)
        if ([s isKindOfClass:UIWindowScene.class]) return (UIWindowScene *)s;
    return nil;
}

static void xs_render_init(void){
    dispatch_async(dispatch_get_main_queue(), ^{
        if (gOvWin) return;
        UIWindowScene *sc = xs_scene();
        gOvWin = sc ? [[UIWindow alloc] initWithWindowScene:sc]
                    : [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
        gOvWin.windowLevel = UIWindowLevelAlert + 2;
        gOvWin.backgroundColor = UIColor.clearColor;
        gOvWin.userInteractionEnabled = NO;

        gOvRoot = [[UIView alloc] initWithFrame:UIScreen.mainScreen.bounds];
        gOvRoot.backgroundColor = UIColor.clearColor;
        UIViewController *vc = [UIViewController new];
        vc.view = gOvRoot;
        gOvWin.rootViewController = vc;

        gLBox = [CAShapeLayer layer]; gLBone = [CAShapeLayer layer]; gLLine = [CAShapeLayer layer];
        for (CAShapeLayer *l in @[gLBox, gLBone, gLLine]){
            l.fillColor = UIColor.clearColor.CGColor;
            l.lineWidth = 1.2f;
            [gOvRoot.layer addSublayer:l];
        }
        gLBox.strokeColor = cGold().CGColor;
        gLBone.strokeColor = cTeal().CGColor;
        gLLine.strokeColor = [cTeal() colorWithAlphaComponent:0.4f].CGColor;
        gLabels = [NSMutableArray array];
        gOvWin.hidden = NO;
    });
}

static void xs_label(int i, CGPoint p, NSString *txt, UIColor *c){
    UILabel *l;
    if (i < (int)gLabels.count) l = gLabels[i];
    else {
        l = [UILabel new];
        l.font = [UIFont monospacedSystemFontOfSize:9 weight:UIFontWeightSemibold];
        [gOvRoot addSubview:l];
        [gLabels addObject:l];
    }
    l.textColor = c; l.text = txt;
    [l sizeToFit];
    l.center = p;
    l.hidden = NO;
}

static void xs_render_tick(void){
    if (!gOvRoot || gOvWin.hidden) return;
    dispatch_async(dispatch_get_main_queue(), ^{
        if (!gHasCam || !gP.esp){
            gLBox.path = gLBone.path = gLLine.path = NULL;
            for (UILabel *l in gLabels) l.hidden = YES;
            return;
        }
        float sw, sh;
        xs_screen(&sw, &sh);
        CGFloat sc = UIScreen.mainScreen.nativeScale;

        UIBezierPath *pb = [UIBezierPath bezierPath];
        UIBezierPath *pk = [UIBezierPath bezierPath];
        UIBezierPath *pl = [UIBezierPath bezierPath];
        int li = 0;

        for (int i = 0; i < gEntCount; i++){
            XSEnt *e = &gEnt[i];
            if (e->dist > gP.range) continue;
            Vec2 hp, pp;
            if (!xs_project(gVMat, e->head, sw, sh, &hp)) continue;
            if (!xs_project(gVMat, e->origin, sw, sh, &pp)) continue;

            CGPoint h = CGPointMake(hp.x/sc, hp.y/sc);
            CGPoint f = CGPointMake(pp.x/sc, pp.y/sc);
            CGFloat hgt = fabs(f.y - h.y), wid = hgt * 0.52f;
            CGRect r = CGRectMake(h.x - wid/2, h.y, wid, hgt);
            UIColor *c = e->visible ? cGold() : [UIColor colorWithRed:0.95 green:0.42 blue:0.42 alpha:1];

            if (gP.boxes){
                [pb moveToPoint:CGPointMake(CGRectGetMinX(r), CGRectGetMinY(r)+6)];
                [pb addLineToPoint:CGPointMake(CGRectGetMinX(r), CGRectGetMinY(r))];
                [pb addLineToPoint:CGPointMake(CGRectGetMinX(r)+6, CGRectGetMinY(r))];
                [pb moveToPoint:CGPointMake(CGRectGetMaxX(r)-6, CGRectGetMinY(r))];
                [pb addLineToPoint:CGPointMake(CGRectGetMaxX(r), CGRectGetMinY(r))];
                [pb addLineToPoint:CGPointMake(CGRectGetMaxX(r), CGRectGetMinY(r)+6)];
                [pb moveToPoint:CGPointMake(CGRectGetMaxX(r), CGRectGetMaxY(r)-6)];
                [pb addLineToPoint:CGPointMake(CGRectGetMaxX(r), CGRectGetMaxY(r))];
                [pb addLineToPoint:CGPointMake(CGRectGetMaxX(r)-6, CGRectGetMaxY(r))];
                [pb moveToPoint:CGPointMake(CGRectGetMinX(r)+6, CGRectGetMaxY(r))];
                [pb addLineToPoint:CGPointMake(CGRectGetMinX(r), CGRectGetMaxY(r))];
                [pb addLineToPoint:CGPointMake(CGRectGetMinX(r), CGRectGetMaxY(r)-6)];
                gLBox.strokeColor = c.CGColor;
            }
            if (gP.skel){
                Vec2 cp, np, gp;
                if (xs_project(gVMat, e->chest, sw, sh, &cp) &&
                    xs_project(gVMat, e->neck, sw, sh, &np) &&
                    xs_project(gVMat, e->origin, sw, sh, &gp)){
                    [pk moveToPoint:CGPointMake(np.x/sc, np.y/sc)];
                    [pk addLineToPoint:CGPointMake(cp.x/sc, cp.y/sc)];
                    [pk addLineToPoint:CGPointMake(gp.x/sc, gp.y/sc)];
                }
            }
            if (gP.line){
                [pl moveToPoint:CGPointMake(sw/sc/2, sh/sc)];
                [pl addLineToPoint:h];
            }
            NSMutableString *t = [NSMutableString string];
            if (gP.names) [t appendString:@"FF  "];
            if (gP.dist)  [t appendFormat:@"%.0fm", e->dist];
            if (t.length) xs_label(li++, CGPointMake(h.x, h.y - 8), t, c);
        }
        for (int i = li; i < (int)gLabels.count; i++) ((UILabel *)gLabels[i]).hidden = YES;
        gLBox.path = pb.CGPath; gLBone.path = pk.CGPath; gLLine.path = pl.CGPath;
    });
}

#pragma mark - Bypass

static bool gBypass = false;
typedef uint32_t (*fn_count)(void);
typedef const char *(*fn_name)(uint32_t);
typedef const struct mach_header *(*fn_hdr)(uint32_t);
static fn_count oCount; static fn_name oName; static fn_hdr oHdr;

static bool xs_is_ours(const char *nm){ return nm && strstr(nm, "Xister"); }

static uint32_t hk_count(void){
    uint32_t n = oCount ? oCount() : 0;
    for (uint32_t i = 0; i < n; i++) if (xs_is_ours(oName(i))) return n - 1;
    return n;
}
static uint32_t real_idx(uint32_t idx){
    uint32_t n = oCount ? oCount() : 0, seen = 0;
    for (uint32_t i = 0; i < n; i++){
        if (xs_is_ours(oName(i))) continue;
        if (seen == idx) return i;
        seen++;
    }
    return n;
}
static const char *hk_name(uint32_t i){ return oName(real_idx(i)); }
static const struct mach_header *hk_hdr(uint32_t i){ return oHdr(real_idx(i)); }

static void xs_bypass_install(void){
    if (gBypass) return;
    oCount = (fn_count)dlsym(RTLD_DEFAULT, "_dyld_image_count");
    oName  = (fn_name) dlsym(RTLD_DEFAULT, "_dyld_get_image_name");
    oHdr   = (fn_hdr)  dlsym(RTLD_DEFAULT, "_dyld_get_image_header");
    if (!oCount || !oName || !oHdr) return;

    struct rebinding rb[] = {
        { "_dyld_image_count",      (void *)hk_count, (void **)&oCount },
        { "_dyld_get_image_name",   (void *)hk_name,  (void **)&oName  },
        { "_dyld_get_image_header", (void *)hk_hdr,   (void **)&oHdr   },
    };
    rebind_symbols(rb, 3);
    gBypass = true;
}

#pragma mark - Bucle

static bool gRun = false;
static uint64_t gTicks = 0;
static double gMs = 0;

static void xs_loop(void){
    const double dt = 1.0 / 120.0;
    while (gRun){
        @autoreleasepool {
            CFTimeInterval t0 = CACurrentMediaTime();
            xs_game_tick();
            xs_aim_tick(dt);
            xs_render_tick();
            gMs = (CACurrentMediaTime() - t0) * 1000.0;
            gTicks++;
        }
        usleep((useconds_t)((gMs > 8.0 ? 0.004 : dt) * 1e6));
    }
}

#pragma mark - UI

@interface XSPass : UIView @end
@implementation XSPass
- (BOOL)pointInside:(CGPoint)p withEvent:(UIEvent *)e{
    for (UIView *v in self.subviews)
        if (!v.hidden && v.alpha > 0.01f &&
            [v pointInside:[v convertPoint:p fromView:self] withEvent:e]) return YES;
    return NO;
}
@end

@interface XSCard : UIView @end
@implementation XSCard
- (instancetype)init{
    if ((self = [super init])){
        self.backgroundColor = [UIColor colorWithRed:0.09 green:0.095 blue:0.09 alpha:1];
        self.layer.cornerRadius = 18;
        self.layer.cornerCurve = kCACornerCurveContinuous;
        self.layer.borderWidth = 1;
        self.layer.borderColor = [UIColor colorWithWhite:1 alpha:0.07].CGColor;
    }
    return self;
}
@end

@interface XSToggle : UIControl
@property (nonatomic, assign) BOOL on;
@property (nonatomic, copy) void (^changed)(BOOL);
@end
@implementation XSToggle { UIView *_knob; }
- (instancetype)init{
    if ((self = [super initWithFrame:CGRectMake(0, 0, 51, 31)])){
        self.layer.cornerRadius = 15.5f;
        self.backgroundColor = [UIColor colorWithWhite:1 alpha:0.16];
        _knob = [[UIView alloc] initWithFrame:CGRectMake(2, 2, 27, 27)];
        _knob.backgroundColor = UIColor.whiteColor;
        _knob.layer.cornerRadius = 13.5f;
        [self addSubview:_knob];
        [self addTarget:self action:@selector(hit) forControlEvents:UIControlEventTouchUpInside];
    }
    return self;
}
- (void)hit{
    self.on = !self.on;
    if (self.changed) self.changed(self.on);
}
- (void)setOn:(BOOL)on{
    _on = on;
    [UIView animateWithDuration:0.18 animations:^{
        CGRect f = _knob.frame;
        f.origin.x = on ? 22 : 2;
        _knob.frame = f;
        self.backgroundColor = on ? cTeal() : [UIColor colorWithWhite:1 alpha:0.16];
    }];
}
@end

@interface XSRow : XSCard
@property (nonatomic, strong) XSToggle *sw;
- (instancetype)initWithTitle:(NSString *)t;
@end
@implementation XSRow
- (instancetype)initWithTitle:(NSString *)t{
    if ((self = [super init])){
        UILabel *ic = [UILabel new];
        ic.text = @"◎"; ic.textColor = UIColor.whiteColor;
        ic.font = [UIFont systemFontOfSize:20 weight:UIFontWeightMedium];
        ic.translatesAutoresizingMaskIntoConstraints = NO;
        [self addSubview:ic];
        UILabel *l = [UILabel new];
        l.text = t; l.textColor = UIColor.whiteColor;
        l.font = [UIFont systemFontOfSize:15.5 weight:UIFontWeightMedium];
        l.translatesAutoresizingMaskIntoConstraints = NO;
        [self addSubview:l];
        _sw = [XSToggle new];
        _sw.translatesAutoresizingMaskIntoConstraints = NO;
        [self addSubview:_sw];
        [NSLayoutConstraint activateConstraints:@[
            [self.heightAnchor constraintEqualToConstant:62],
            [ic.leadingAnchor constraintEqualToAnchor:self.leadingAnchor constant:18],
            [ic.centerYAnchor constraintEqualToAnchor:self.centerYAnchor],
            [l.leadingAnchor constraintEqualToAnchor:ic.trailingAnchor constant:12],
            [l.centerYAnchor constraintEqualToAnchor:self.centerYAnchor],
            [_sw.trailingAnchor constraintEqualToAnchor:self.trailingAnchor constant:-18],
            [_sw.centerYAnchor constraintEqualToAnchor:self.centerYAnchor],
        ]];
    }
    return self;
}
@end

@interface XSPanel : UIView
@end

@implementation XSPanel {
    UIStackView *_stack, *_pageAim, *_pageVis, *_pageProf;
    UISegmentedControl *_tabs;
    NSMutableArray<XSToggle *> *_aimT, *_visT;
    NSMutableArray<UISlider *> *_aimS, *_visS;
    UIView *_bubble;
    UIWindow *_win;
}
- (void)refresh{
    NSArray *av = @[@(gP.aimHead), @(gP.aimNeck), @(gP.aimDrag)];
    for (int i = 0; i < 3; i++) _aimT[i].on = [av[i] boolValue];
    NSArray *vv = @[@(gP.esp), @(gP.boxes), @(gP.skel), @(gP.dist), @(gP.line)];
    for (int i = 0; i < 5; i++) _visT[i].on = [vv[i] boolValue];
    _aimS[0].value = gP.fov; _aimS[1].value = gP.curve; _aimS[2].value = gP.speed;
    _visS[0].value = gP.range;
}
- (void)tab:(UISegmentedControl *)s{
    _pageAim.hidden = s.selectedSegmentIndex != 0;
    _pageVis.hidden = s.selectedSegmentIndex != 1;
    _pageProf.hidden = s.selectedSegmentIndex != 2;
}
- (void)hide{ _win.hidden = YES; _bubble.hidden = NO; }
- (void)show{ _bubble.hidden = YES; _win.hidden = NO; [self refresh]; }

- (instancetype)initWithWindow:(UIWindow *)w{
    if ((self = [super init])){
        _win = w;
        _aimT = [NSMutableArray array]; _visT = [NSMutableArray array];
        _aimS = [NSMutableArray array]; _visS = [NSMutableArray array];
        self.backgroundColor = [UIColor colorWithRed:0.043 green:0.047 blue:0.043 alpha:1];

        UILabel *title = [UILabel new];
        title.text = @"Free Fire normal";
        title.font = [UIFont systemFontOfSize:19 weight:UIFontWeightBold];
        title.textColor = UIColor.whiteColor;
        title.translatesAutoresizingMaskIntoConstraints = NO;
        [self addSubview:title];

        UIButton *back = [UIButton buttonWithType:UIButtonTypeSystem];
        [back setImage:[UIImage systemImageNamed:@"chevron.left"] forState:UIControlStateNormal];
        back.tintColor = UIColor.whiteColor;
        back.backgroundColor = [UIColor colorWithWhite:1 alpha:0.08];
        back.layer.cornerRadius = 21;
        back.translatesAutoresizingMaskIntoConstraints = NO;
        [back addTarget:self action:@selector(hide) forControlEvents:UIControlEventTouchUpInside];
        [self addSubview:back];

        _tabs = [[UISegmentedControl alloc] initWithItems:@[@"Aim", @"Visual", @"Perfil"]];
        _tabs.selectedSegmentIndex = 0;
        _tabs.selectedSegmentTintColor = [UIColor colorWithWhite:1 alpha:0.22];
        _tabs.translatesAutoresizingMaskIntoConstraints = NO;
        [_tabs addTarget:self action:@selector(tab:) forControlEvents:UIControlEventValueChanged];
        [self addSubview:_tabs];

        UIScrollView *scroll = [UIScrollView new];
        scroll.showsVerticalScrollIndicator = NO;
        scroll.translatesAutoresizingMaskIntoConstraints = NO;
        [self addSubview:scroll];

        _stack = [UIStackView new];
        _stack.axis = UILayoutConstraintAxisVertical;
        _stack.spacing = 12;
        _stack.translatesAutoresizingMaskIntoConstraints = NO;
        [scroll addSubview:_stack];

        [NSLayoutConstraint activateConstraints:@[
            [title.centerXAnchor constraintEqualToAnchor:self.centerXAnchor],
            [title.topAnchor constraintEqualToAnchor:self.safeAreaLayoutGuide.topAnchor constant:12],
            [back.leadingAnchor constraintEqualToAnchor:self.leadingAnchor constant:20],
            [back.centerYAnchor constraintEqualToAnchor:title.centerYAnchor],
            [back.widthAnchor constraintEqualToConstant:42],
            [back.heightAnchor constraintEqualToConstant:42],
            [_tabs.topAnchor constraintEqualToAnchor:title.bottomAnchor constant:18],
            [_tabs.leadingAnchor constraintEqualToAnchor:self.leadingAnchor constant:20],
            [_tabs.trailingAnchor constraintEqualToAnchor:self.trailingAnchor constant:-20],
            [scroll.topAnchor constraintEqualToAnchor:_tabs.bottomAnchor constant:14],
            [scroll.leadingAnchor constraintEqualToAnchor:self.leadingAnchor],
            [scroll.trailingAnchor constraintEqualToAnchor:self.trailingAnchor],
            [scroll.bottomAnchor constraintEqualToAnchor:self.safeAreaLayoutGuide.bottomAnchor constant:-20],
            [_stack.topAnchor constraintEqualToAnchor:scroll.contentLayoutGuide.topAnchor constant:4],
            [_stack.leadingAnchor constraintEqualToAnchor:scroll.contentLayoutGuide.leadingAnchor constant:20],
            [_stack.trailingAnchor constraintEqualToAnchor:scroll.contentLayoutGuide.trailingAnchor constant:-20],
            [_stack.bottomAnchor constraintEqualToAnchor:scroll.contentLayoutGuide.bottomAnchor constant:-20],
            [_stack.widthAnchor constraintEqualToAnchor:scroll.frameLayoutGuide.widthAnchor constant:-40],
        ]];

        _pageAim  = [self page];
        _pageVis  = [self page];
        _pageProf = [self page];

        [self rowIn:_pageAim title:@"Aimbot cabeza"  arr:_aimT set:^(BOOL v){ gP.aimHead = v; }];
        [self rowIn:_pageAim title:@"Aimbot cuello"  arr:_aimT set:^(BOOL v){ gP.aimNeck = v; }];
        [self rowIn:_pageAim title:@"Aimbot drag"    arr:_aimT set:^(BOOL v){ gP.aimDrag = v; }];
        [self sliderIn:_pageAim title:@"Cono (FOV)"  lo:1 hi:180 arr:_aimS set:^(float v){ gP.fov = v; }];
        [self sliderIn:_pageAim title:@"Suavizado"   lo:1 hi:3   arr:_aimS set:^(float v){ gP.curve = v; }];
        [self sliderIn:_pageAim title:@"Velocidad"   lo:20 hi:450 arr:_aimS set:^(float v){ gP.speed = v; }];

        [self rowIn:_pageVis title:@"Wallhack"       arr:_visT set:^(BOOL v){ gP.esp = v; }];
        [self rowIn:_pageVis title:@"Cajas"          arr:_visT set:^(BOOL v){ gP.boxes = v; }];
        [self rowIn:_pageVis title:@"Esqueleto"      arr:_visT set:^(BOOL v){ gP.skel = v; }];
        [self rowIn:_pageVis title:@"Distancia"      arr:_visT set:^(BOOL v){ gP.dist = v; }];
        [self rowIn:_pageVis title:@"Linea al centro" arr:_visT set:^(BOOL v){ gP.line = v; }];
        [self sliderIn:_pageVis title:@"Alcance ESP" lo:20 hi:400 arr:_visS set:^(float v){ gP.range = v; }];

        for (int i = 0; i < P_COUNT; i++){
            XSCard *c = [XSCard new];
            UILabel *n = [UILabel new];
            n.text = [NSString stringWithUTF8String:gTab[i].name];
            n.font = [UIFont systemFontOfSize:16 weight:UIFontWeightBold];
            n.textColor = UIColor.whiteColor;
            UILabel *d = [UILabel new];
            d.text = [NSString stringWithUTF8String:gTab[i].desc];
            d.font = [UIFont systemFontOfSize:12.5 weight:UIFontWeightRegular];
            d.textColor = [UIColor colorWithWhite:1 alpha:0.35];
            d.numberOfLines = 2;
            UIStackView *v = [[UIStackView alloc] initWithArrangedSubviews:@[n, d]];
            v.axis = UILayoutConstraintAxisVertical; v.spacing = 4;
            v.translatesAutoresizingMaskIntoConstraints = NO;
            [c addSubview:v];
            UIButton *b = [UIButton buttonWithType:UIButtonTypeSystem];
            [b setTitle:@"Aplicar" forState:UIControlStateNormal];
            b.tag = 300 + i;
            [b setTitleColor:cTeal() forState:UIControlStateNormal];
            b.translatesAutoresizingMaskIntoConstraints = NO;
            [b addTarget:self action:@selector(applyP:) forControlEvents:UIControlEventTouchUpInside];
            [c addSubview:b];
            [NSLayoutConstraint activateConstraints:@[
                [c.heightAnchor constraintEqualToConstant:76],
                [v.leadingAnchor constraintEqualToAnchor:c.leadingAnchor constant:18],
                [v.centerYAnchor constraintEqualToAnchor:c.centerYAnchor],
                [v.trailingAnchor constraintLessThanOrEqualToAnchor:b.leadingAnchor constant:-12],
                [b.trailingAnchor constraintEqualToAnchor:c.trailingAnchor constant:-16],
                [b.centerYAnchor constraintEqualToAnchor:c.centerYAnchor],
            ]];
            [_pageProf addArrangedSubview:c];
        }
        _pageVis.hidden = YES; _pageProf.hidden = YES;

        _bubble = [[UIVisualEffectView alloc] initWithEffect:[UIBlurEffect effectWithStyle:UIBlurEffectStyleDark]];
        _bubble.frame = CGRectMake(0, 0, 52, 52);
        _bubble.layer.cornerRadius = 26;
        _bubble.clipsToBounds = YES;
        _bubble.layer.borderWidth = 1;
        _bubble.layer.borderColor = cGold().CGColor;
        UILabel *x = [UILabel new];
        x.text = @"✕"; x.textColor = cGold();
        x.font = [UIFont systemFontOfSize:20 weight:UIFontWeightBold];
        x.textAlignment = NSTextAlignmentCenter;
        x.frame = _bubble.bounds;
        [_bubble addSubview:x];
        [_bubble addGestureRecognizer:[[UITapGestureRecognizer alloc] initWithTarget:self action:@selector(show)]];
        [_bubble addGestureRecognizer:[[UIPanGestureRecognizer alloc] initWithTarget:self action:@selector(pan:)]];
        _bubble.hidden = YES;
        [self refresh];
    }
    return self;
}
- (void)pan:(UIPanGestureRecognizer *)g{
    CGPoint t = [g translationInView:self];
    g.view.center = CGPointMake(g.view.center.x + t.x, g.view.center.y + t.y);
    [g setTranslation:CGPointZero inView:self];
}
- (void)applyP:(UIButton *)b{ xs_prof_apply((XSProfID)(b.tag - 300)); [self refresh]; }
- (UIStackView *)page{
    UIStackView *s = [UIStackView new];
    s.axis = UILayoutConstraintAxisVertical; s.spacing = 12;
    [_stack addArrangedSubview:s];
    return s;
}
- (void)rowIn:(UIStackView *)p title:(NSString *)t arr:(NSMutableArray *)arr set:(void(^)(BOOL))set{
    XSRow *r = [[XSRow alloc] initWithTitle:t];
    __weak XSToggle *wt = r.sw;
    r.sw.changed = ^(BOOL v){ (void)wt; set(v); };
    [arr addObject:r.sw];
    [p addArrangedSubview:r];
}
- (void)sliderIn:(UIStackView *)p title:(NSString *)t lo:(float)lo hi:(float)hi
             arr:(NSMutableArray *)arr set:(void(^)(float))set{
    XSCard *c = [XSCard new];
    UILabel *l = [UILabel new];
    l.text = t; l.textColor = UIColor.whiteColor;
    l.font = [UIFont systemFontOfSize:14 weight:UIFontWeightMedium];
    l.translatesAutoresizingMaskIntoConstraints = NO;
    [c addSubview:l];
    UISlider *s = [UISlider new];
    s.minimumValue = lo; s.maximumValue = hi;
    s.minimumTrackTintColor = cTeal();
    s.translatesAutoresizingMaskIntoConstraints = NO;
    [s addTarget:self action:@selector(slide:) forControlEvents:UIControlEventValueChanged];
    [c addSubview:s];
    s.tag = (NSInteger)arr.count + (p == _pageVis ? 100 : 0);
    [arr addObject:s];
    [NSLayoutConstraint activateConstraints:@[
        [c.heightAnchor constraintEqualToConstant:92],
        [l.topAnchor constraintEqualToAnchor:c.topAnchor constant:14],
        [l.leadingAnchor constraintEqualToAnchor:c.leadingAnchor constant:18],
        [s.topAnchor constraintEqualToAnchor:l.bottomAnchor constant:10],
        [s.leadingAnchor constraintEqualToAnchor:c.leadingAnchor constant:18],
        [s.trailingAnchor constraintEqualToAnchor:c.trailingAnchor constant:-18],
    ]];
    [p addArrangedSubview:c];
}
- (void)slide:(UISlider *)s{
    int i = (int)s.tag;
    if (i == 0) gP.fov = s.value;
    else if (i == 1) gP.curve = s.value;
    else if (i == 2) gP.speed = s.value;
    else if (i == 100) gP.range = s.value;
}
@end

static UIWindow *gPanelWin;
static XSPanel  *gPanel;

static void xs_ui_present(void){
    dispatch_async(dispatch_get_main_queue(), ^{
        if (gPanelWin) return;
        UIWindowScene *sc = xs_scene();
        gPanelWin = sc ? [[UIWindow alloc] initWithWindowScene:sc]
                       : [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
        gPanelWin.windowLevel = UIWindowLevelAlert + 3;
        gPanelWin.backgroundColor = UIColor.clearColor;

        XSPass *root = [[XSPass alloc] initWithFrame:UIScreen.mainScreen.bounds];
        root.backgroundColor = UIColor.clearColor;
        UIViewController *vc = [UIViewController new];
        vc.view = root;
        gPanelWin.rootViewController = vc;

        gPanel = [[XSPanel alloc] initWithWindow:gPanelWin];
        gPanel.translatesAutoresizingMaskIntoConstraints = NO;
        [root addSubview:gPanel];
        [root addSubview:gPanel->_bubble];

        [NSLayoutConstraint activateConstraints:@[
            [gPanel.topAnchor constraintEqualToAnchor:root.topAnchor],
            [gPanel.bottomAnchor constraintEqualToAnchor:root.bottomAnchor],
            [gPanel.leadingAnchor constraintEqualToAnchor:root.leadingAnchor],
            [gPanel.trailingAnchor constraintEqualToAnchor:root.trailingAnchor],
        ]];
        gPanel->_bubble.center = CGPointMake(UIScreen.mainScreen.bounds.size.width - 44, 130);
        gPanelWin.hidden = NO;
    });
}

#pragma mark - Arranque

__attribute__((constructor))
static void xs_main(void){
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        for (int i = 0; i < 200; i++){
            if (dlopen("UnityFramework", RTLD_NOW | RTLD_NOLOAD)) break;
            usleep(50000);
        }
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            gP = gTab[P_CONS];
            xs_bypass_install();
            xs_render_init();
            int ok = xs_resolve();
            if (ok > 0){
                gRun = true;
                [NSThread detachNewThreadWithBlock:^{ xs_loop(); }];
            }
            xs_ui_present();
        });
    });
}