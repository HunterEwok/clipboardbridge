#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

"""Drives the QEMU test build's console over UART0, as qemu-test.sh asks:
boots the flash image three times and checks that the settings typed in
one boot are there in the next, and that the self-test passes.

    qemu-test.py QEMU FLASH_IMAGE WORK_DIR
"""

import os
import socket
import subprocess
import sys
import time

QEMU, FLASH, WORK = sys.argv[1:4]
TIMEOUT = float(os.environ.get("TIMEOUT", "300"))
PROMPT = b"cbb> "
transcript = []


class Board:
    def __init__(self, n):
        self.sock = os.path.join(WORK, f"uart{n}.sock")
        self.log = open(os.path.join(WORK, f"qemu{n}.log"), "wb")
        self.qemu = subprocess.Popen(
            [QEMU, "-nographic", "-machine", "esp32s3",
             "-drive", f"file={FLASH},if=mtd,format=raw",
             "-chardev", f"socket,id=uart,path={self.sock},server=on,wait=on",
             "-serial", "chardev:uart", "-monitor", "none"],
            stdin=subprocess.DEVNULL, stdout=self.log, stderr=subprocess.STDOUT)
        deadline = time.time() + 30
        while not os.path.exists(self.sock):
            if time.time() > deadline or self.qemu.poll() is not None:
                fail("QEMU did not start")
            time.sleep(0.1)
        self.uart = socket.socket(socket.AF_UNIX)
        self.uart.connect(self.sock)
        self.uart.settimeout(0.5)
        self.out = b""
        self.expect(PROMPT)

    def expect(self, want, timeout=TIMEOUT):
        """Reads until want, and then the next prompt, have come."""
        deadline = time.time() + timeout
        while want not in self.out or not self.out.rstrip().endswith(PROMPT.rstrip()):
            if b"PANIC" in self.out:
                fail("the firmware panicked")
            if time.time() > deadline:
                fail(f"no {want!r}")
            try:
                data = self.uart.recv(4096)
            except socket.timeout:
                continue
            if not data:
                fail("QEMU closed the UART")
            self.out += data
        transcript.append(self.out.decode(errors="replace"))
        self.out = b""

    def type(self, line, want, timeout=TIMEOUT):
        self.uart.sendall(line.encode() + b"\r")
        self.expect(want.encode(), timeout)

    def answer(self, line, question):
        """Types a line that the board answers with another question."""
        self.uart.sendall(line.encode() + b"\r")
        deadline = time.time() + TIMEOUT
        while question.encode() not in self.out:
            if time.time() > deadline:
                fail(f"no {question!r}")
            try:
                self.out += self.uart.recv(4096)
            except socket.timeout:
                pass

    def stop(self):
        self.qemu.kill()
        self.qemu.wait()
        self.uart.close()
        os.remove(self.sock)


def fail(why):
    sys.stdout.write("\n".join(transcript))
    sys.exit(f"qemu-test: {why}")


b = Board(1)
b.type("status", "group: none, type join")
b.type("join", "the QEMU build has no network to join a group over")
b.answer("wifi", "Wi-Fi network name: ")
b.answer("Test Net", "Password (empty for an open network): ")
b.type("password1", "Saved. Joining Test Net.")
b.type("debug on", "Error details are on.")
b.type("selftest", "self-test passed")
b.type("layout ru", "The keyboard types for the layout ru now")
# "Wi-Fi: dom" (house), and "Privet, mir!" (hello, world) in Cyrillic.
b.type("type Wi-Fi: \u0434\u043e\u043c", "The layout ru has no keys for: WiF")
b.type("type \u041f\u0440\u0438\u0432\u0435\u0442, \u043c\u0438\u0440!", "the QEMU build has no USB keyboard")
b.type("rate 30", "The keyboard types 30 characters a second now.")
b.type("rate 100", "A rate is 5 to 60 characters a second.")
b.stop()

# The settings stay in flash across a restart.
b = Board(2)
b.type("status", "Wi-Fi network: Test Net")
assert "error details: on" in transcript[-1], "debug mode was not kept"
assert "USB port: console; layout ru, 30 characters a second" in transcript[-1], "the keyboard's settings were not kept"
b.type("wifi forget", "Forgot the Wi-Fi network.")
b.stop()

b = Board(3)
b.type("status", "Wi-Fi network: none set")
b.stop()

sys.stdout.write("\n".join(transcript))
print("\nqemu-test: passed")
