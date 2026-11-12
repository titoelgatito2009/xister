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