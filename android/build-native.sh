#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
JNI_DIR="$SCRIPT_DIR/rust-jni"
OUT_DIR="$SCRIPT_DIR/app/src/main/jniLibs"

echo "==> Building vs-vpn JNI library for Android..."
echo "    Source: $JNI_DIR"
echo "    Output: $OUT_DIR"

cd "$JNI_DIR"

cargo ndk \
    -t arm64-v8a \
    -t armeabi-v7a \
    -t x86_64 \
    -t x86 \
    -o "$OUT_DIR" \
    build --release

echo "==> Done. Libraries placed in $OUT_DIR"
