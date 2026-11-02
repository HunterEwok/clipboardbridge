# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 HunterEwok

# .cbb, the dot command for the ZX Spectrum Next (README.md).
#   make        build/CBB and build/PIBRIDGE with z88dk (zcc on the PATH, ZCCCFG set)
#   make test   the host tests of the frame parser with cc

ZCC ?= zcc
CC ?= cc
SRC := src/cbb.c src/link.c src/frame.c

all: build/CBB build/PIBRIDGE

build/CBB: $(SRC) src/frame.h src/link.h
	mkdir -p build
	cd build && $(ZCC) +zxn -vn -O2 -clib=new -subtype=dotn -startup=30 -I../src \
		$(addprefix ../,$(SRC)) -o cbb -create-app

build/PIBRIDGE: src/pibridge.c src/link.c src/link.h src/frame.c src/frame.h
	mkdir -p build
	cd build && $(ZCC) +zxn -vn -O2 -clib=new -subtype=dotn -startup=30 -I../src \
		../src/pibridge.c ../src/link.c ../src/frame.c -o pibridge -create-app

test: build/frame_test
	./build/frame_test

build/frame_test: src/frame.c src/frame.h test/frame_test.c
	mkdir -p build
	$(CC) -std=c99 -Wall -Wextra -Werror -Isrc src/frame.c test/frame_test.c -o $@

clean:
	rm -rf build

.PHONY: all test clean
