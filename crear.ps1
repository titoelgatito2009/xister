# crear.ps1 — genera el proyecto Xister completo
$root = Join-Path $PWD "xister"
New-Item -ItemType Directory -Force -Path $root, "$root\src", "$root\vendor", "$root\.github\workflows" | Out-Null
function W($p, $c) { [System.IO.File]::WriteAllText($p, $c, (New-Object System.Text.UTF8Encoding $false)) }

W "$root\README.md" @'
# Xister
Panel externo para Free Fire (iOS). Compila un .dylib arm64 y lo inyecta en la IPA.
Ver build.sh y .github/workflows/build.yml
'@

W "$root\entitlements.plist" @'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>application-identifier</key>
	<string>TEAMID.com.dts.freefireth</string>
	<key>com.apple.developer.team-identifier</key>
	<string>TEAMID</string>
	<key>keychain-access-groups</key>
	<array>
		<string>TEAMID.com.dts.freefireth</string>
	</array>
	<key>get-task-allow</key>
	<true/>
</dict>
</plist>
'@

W "$root\build.sh" @'
#!/bin/bash
set -e
SDK=$(xcrun --sdk iphoneos --show-sdk-path)
mkdir -p build
xcrun --sdk iphoneos clang -arch arm64 -isysroot "$SDK" -miphoneos-version-min=15.0 \
  -fobjc-arc -O2 -fvisibility=hidden -fno-exceptions -Wall -Wextra -Wno-unused-parameter \
  -Ivendor -dynamiclib -o build/Xister.dylib src/Xister.m vendor/fishhook.c \
  -framework Foundation -framework UIKit -framework CoreGraphics -framework QuartzCore -framework IOKit
strip -x build/Xister.dylib
ldid -Sentitlements.plist build/Xister.dylib
echo "OK build/Xister.dylib"
'@

W "$root\.github\workflows\build.yml" @'
name: build
on:
  push:
  workflow_dispatch:

permissions:
  contents: read

jobs:
  build:
    runs-on: macos-14
    steps:
      - uses: actions/checkout@v4

      - name: Herramientas
        run: |
          brew install ldid
          git clone --depth 1 https://github.com/Tyilo/insert_dylib
          cd insert_dylib
          xcodebuild -project insert_dylib.xcodeproj -configuration Release -derivedDataPath dd >/dev/null
          cp dd/Build/Products/Release/insert_dylib /usr/local/bin/
          chmod +x /usr/local/bin/insert_dylib

      - name: Compilar
        run: bash build.sh

      - name: Descargar IPA
        run: |
          mkdir -p out
          curl -fL -o ipa.zip "https://github.com/${{ github.repository }}/releases/download/ipa/input.ipa"
          unzip -q ipa.zip -d w

      - name: Inyectar
        run: |
          BIN=$(find w/Payload -maxdepth 2 -type f -perm -111 ! -name '*.dylib' | head -1)
          echo "binario: $BIN"
          cp build/Xister.dylib "$(dirname "$BIN")/Xister.dylib"
          insert_dylib --strip-codesig --inplace @executable_path/Xister.dylib "$BIN"
          ldid -Sentitlements.plist "$BIN"
          ( cd w && zip -qry ../out/Xister-injected.ipa Payload )
          cp build/Xister.dylib out/Xister.dylib

      - uses: actions/upload-artifact@v4
        with:
          name: Xister
          path: out/
'@

Write-Host ""
Write-Host "Listo. Archivos creados en: $root" -ForegroundColor Green