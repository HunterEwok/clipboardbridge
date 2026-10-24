#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# Runs the firmware's self-test in Espressif's QEMU (the ESP32-S3 machine):
# builds the QEMU test build, writes a flash image with espflash, boots it
# and waits for the self-test's result on UART0.
#   QEMU=path/to/qemu-system-xtensa ESPFLASH=path/to/espflash ./qemu-test.sh
set -eu
cd "$(dirname "$0")"
: "${QEMU:=qemu-system-xtensa}" "${ESPFLASH:=espflash}" "${TIMEOUT:=300}"

cargo +esp build --locked --release --no-default-features --features qemu
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
"$ESPFLASH" save-image --chip esp32s3 --merge target/xtensa-esp32s3-none-elf/release/cbb-esp32 "$work/flash.bin"
touch "$work/uart.txt"
"$QEMU" -nographic -machine esp32s3 -drive "file=$work/flash.bin,if=mtd,format=raw" \
	-serial "file:$work/uart.txt" -monitor none </dev/null >"$work/qemu.log" 2>&1 &
qemu=$!
result=1
i=0
while [ "$i" -lt "$TIMEOUT" ]; do
	if grep -q 'self-test passed' "$work/uart.txt"; then result=0; break; fi
	if grep -q -e 'self-test failed' -e 'PANIC' "$work/uart.txt"; then break; fi
	if ! kill -0 "$qemu" 2>/dev/null; then break; fi
	sleep 1
	i=$((i + 1))
done
kill "$qemu" 2>/dev/null || true
grep -v '^I (' "$work/uart.txt" || true
if [ "$result" -ne 0 ]; then
	echo "qemu-test: the self-test did not pass" >&2
	cat "$work/qemu.log" >&2
fi
exit "$result"
