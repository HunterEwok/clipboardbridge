#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok
#
# Builds the Rust core's group rules for the phones and writes their UniFFI
# bindings:
#   bind.sh ios OUT          OUT/CbbCore.xcframework and OUT/cbb_ffi.swift (needs Xcode)
#   bind.sh android OUT      OUT/jniLibs/<abi>/libcbb_ffi.so and OUT/kotlin (needs
#                            ANDROID_NDK_HOME and cargo-ndk)
#   bind.sh jvm OUT          OUT/<host library> and OUT/kotlin, for the kits' JVM tests
# OUT is made absolute; nothing it writes belongs in git.
set -eu
if [ $# -ne 2 ]; then
	echo "usage: bind.sh ios|android|jvm OUT" >&2
	exit 2
fi
target=$1
case $2 in
/*) out=$2 ;;
*) out=$(pwd)/$2 ;;
esac
lite=$(cd "$(dirname "$0")/.." && pwd)
cd "$lite"
mkdir -p "$out"

# The bindings come from the metadata in a library built without stripping;
# the release profile strips, so they are read from a debug build of the host.
bindings() {
	cargo build --locked -p clipboardbridge-ffi
	lib=
	for f in target/debug/libcbb_ffi.so target/debug/libcbb_ffi.dylib; do
		if [ -f "$f" ]; then lib=$f; fi
	done
	cargo run --locked -q -p clipboardbridge-ffi --features bindgen --bin uniffi-bindgen -- \
		generate --no-format --library "$lib" --language "$1" --out-dir "$2"
}

case $target in
ios)
	targets="aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios"
	for t in $targets; do
		rustup target add "$t" >/dev/null
		IPHONEOS_DEPLOYMENT_TARGET=17.0 cargo build --locked -p clipboardbridge-ffi --release --target "$t"
	done
	gen=$(mktemp -d)
	trap 'rm -rf "$gen"' EXIT
	bindings swift "$gen"
	mkdir -p "$gen/headers"
	cp "$gen/cbb_ffiFFI.h" "$gen/headers/"
	cp "$gen/cbb_ffiFFI.modulemap" "$gen/headers/module.modulemap"
	lipo -create target/aarch64-apple-ios-sim/release/libcbb_ffi.a target/x86_64-apple-ios/release/libcbb_ffi.a \
		-output "$gen/libcbb_ffi_sim.a"
	rm -rf "$out/CbbCore.xcframework"
	xcodebuild -create-xcframework \
		-library target/aarch64-apple-ios/release/libcbb_ffi.a -headers "$gen/headers" \
		-library "$gen/libcbb_ffi_sim.a" -headers "$gen/headers" \
		-output "$out/CbbCore.xcframework"
	cp "$gen/cbb_ffi.swift" "$out/"
	;;
android)
	for abi in arm64-v8a armeabi-v7a x86_64; do
		cargo ndk --platform 29 -t "$abi" -o "$out/jniLibs" build --locked -p clipboardbridge-ffi --release
	done
	bindings kotlin "$out/kotlin"
	;;
jvm)
	cargo build --locked -p clipboardbridge-ffi --release
	cp target/release/libcbb_ffi.so target/release/libcbb_ffi.dylib "$out/" 2>/dev/null || true
	bindings kotlin "$out/kotlin"
	;;
*)
	echo "bind.sh: unknown target $target" >&2
	exit 2
	;;
esac
