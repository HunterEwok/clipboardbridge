// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// .cbb: the clipboardbridge dot command for the ZX Spectrum Next. It talks
// to the lite member on the Next's own Raspberry Pi over the UART between
// them, by typing `cbb next ...` at NextPi's shell (docs/roadmap.md, item 14;
// the frames are in lite/README.md, "ZX Spectrum Next").

#include <arch/zxn.h>
#include <arch/zxn/esxdos.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "frame.h"
#include "link.h"

#define VERSION "0.1.0"
// The lite member on the Pi; the NextPi set-up puts it on the shell's PATH.
#define CBB_LITE "cbb"
// The longest text pasted or copied.
#define MAX_TEXT 8192
// How long the lite member may take to answer, in seconds; join waits for the phone.
#define ANSWER_SECONDS 20
#define JOIN_SECONDS 330

static uint8_t text[MAX_TEXT];
static char line[200];
static uint8_t debug;

static void usage(void)
{
    printf("clipboardbridge " VERSION "\n\n"
           ".cbb paste [FILE]  show the group's\n"
           "                   text, or save it\n"
           ".cbb copy FILE     send a file\n"
           ".cbb text WORDS    send the words\n"
           ".cbb copy -s FILE  send a secret,\n"
           ".cbb text -s WORDS such as a password\n"
           ".cbb join          join the group:\n"
           "                   scan the code with\n"
           "                   the phone app\n"
           ".cbb -d ...        show error details\n");
}

// Shows a short message, and in debug mode the cause under it.
static int fail(const char *msg, const char *detail)
{
    printf("cbb: %s\n", msg);
    if (debug && detail && *detail) printf("  (%s)\n", detail);
    return 1;
}

static int link_fail(uint8_t err)
{
    if (err == LINK_BREAK) {
        link_send(3); // Ctrl-C stops the lite member on the Pi
        return fail("stopped", 0);
    }
    return fail("the Pi stopped answering", "timeout");
}

// Types a command for the lite member at NextPi's shell.
static int command(const char *args)
{
    if (link_shell()) {
        return fail("the Pi does not answer; is NextPi running? (.pisend -q)", "no SUP> prompt");
    }
    link_send_str(CBB_LITE);
    if (debug) link_send_str(" -debug");
    link_send_str(" next ");
    link_send_str(args);
    link_send('\n');
    return 0;
}

// Reads lines until a frame of one of the kinds wanted, an OK or an error;
// LINE_OK or the kind, or 255 when it failed (and said why).
static uint8_t expect(uint8_t want, uint32_t *len, uint32_t *crc, uint16_t seconds)
{
    uint8_t kind, err;
    for (;;) {
        err = link_line(line, sizeof line, seconds);
        if (err) {
            link_fail(err);
            return 255;
        }
        kind = frame_line(line, len, crc);
        if (kind == LINE_ERR) {
            fail(line[6] ? line + 7 : "cbb failed", 0);
            link_prompt();
            return 255;
        }
        if (kind == want || kind == LINE_OK) return kind;
    }
}

// Eight lowercase hex digits, as the lite member writes a CRC-32.
static void hex8(char *out, uint32_t v)
{
    int8_t i;
    for (i = 7; i >= 0; i--) {
        out[i] = "0123456789abcdef"[v & 15];
        v >>= 4;
    }
    out[8] = 0;
}

static void show(const uint8_t *p, uint16_t n)
{
    while (n--) {
        uint8_t c = *p++;
        putchar(c == '\r' ? '\n' : c);
    }
    putchar('\n');
}

static int paste(const char *file)
{
    uint32_t len, crc;
    uint16_t got;
    uint8_t c, err, fh;
    sprintf(line, "paste -max %u", MAX_TEXT);
    if (command(line)) return 1;
    if (expect(LINE_TEXT, &len, &crc, ANSWER_SECONDS) != LINE_TEXT) return 1;
    if (len > MAX_TEXT) {
        link_send(3);
        return fail("the text is too long", "longer than -max");
    }
    for (got = 0; got < len; got++) {
        err = link_recv(&c, ANSWER_SECONDS);
        if (err) return link_fail(err);
        text[got] = c;
    }
    if (expect(LINE_OK, &len, &crc, ANSWER_SECONDS) != LINE_OK) return 1;
    link_prompt();
    if (crc32_update(0, text, got) != crc) return fail("the text arrived damaged; try again", "CRC-32 mismatch");
    if (!file) {
        show(text, got);
        return 0;
    }
    errno = 0;
    fh = esx_f_open(file, ESX_MODE_W | ESX_MODE_OPEN_CREAT_TRUNC);
    if (errno) return fail("cannot create the file", file);
    if (esx_f_write(fh, text, got) != got) {
        esx_f_close(fh);
        return fail("cannot write the file", file);
    }
    esx_f_close(fh);
    printf("%u bytes saved to %s\n", got, file);
    return 0;
}

// Whether copy and text send a secret: the group's devices keep it out of
// their histories and clear it from their clipboards after a while.
static uint8_t secret;

static int copy(uint16_t len)
{
    uint32_t n, crc;
    uint16_t i;
    char crc_hex[9];
    hex8(crc_hex, crc32_update(0, text, len));
    sprintf(line, secret ? "copy -secret %u %s" : "copy %u %s", len, crc_hex);
    if (command(line)) return 1;
    if (expect(LINE_GO, &n, &crc, ANSWER_SECONDS) != LINE_GO) return 1;
    for (i = 0; i < len; i++) link_send(text[i]);
    if (expect(LINE_OK, &n, &crc, ANSWER_SECONDS) != LINE_OK) return 1;
    link_prompt();
    printf(secret ? "%u bytes sent to the group as a secret\n" : "%u bytes sent to the group\n", len);
    return 0;
}

static int copy_file(const char *file)
{
    uint8_t fh;
    uint16_t len;
    errno = 0;
    fh = esx_f_open(file, ESX_MODE_R | ESX_MODE_OPEN_EXIST);
    if (errno) return fail("cannot open the file", file);
    len = esx_f_read(fh, text, MAX_TEXT);
    esx_f_close(fh);
    return copy(len);
}

static int copy_words(int argc, char **argv)
{
    uint16_t len = 0, n;
    int i;
    for (i = 0; i < argc; i++) {
        n = strlen(argv[i]);
        if (len + n + 1 > MAX_TEXT) return fail("the text is too long", 0);
        if (i) text[len++] = ' ';
        memcpy(text + len, argv[i], n);
        len += n;
    }
    return copy(len);
}

// Sets one pixel of the ULA screen.
static void plot(uint8_t x, uint8_t y)
{
    *zx_pxy2saddr(x, y) |= zx_px2bitmask(x);
}

// Draws a QR code row by row as it arrives, dark modules in black on white,
// centred, as large as the screen allows.
static int qr(uint8_t size)
{
    uint8_t scale = 184 / size, x0, y0, row, col, d, px, py, err;
    if (scale > 4) scale = 4;
    if (scale == 0) return fail("the QR code is too large for the screen", 0);
    x0 = (256 - size * scale) / 2;
    y0 = (192 - size * scale) / 2;
    zx_border(INK_WHITE);
    zx_cls(PAPER_WHITE | INK_BLACK);
    for (row = 0; row < size; row++) {
        err = link_line(line, sizeof line, ANSWER_SECONDS);
        if (err) return link_fail(err);
        for (col = 0; col < size; col++) {
            d = hex_digit(line[col >> 2]);
            if (d == 255) return fail("the Pi sent a damaged QR code", line);
            if (!(d & (8 >> (col & 3)))) continue;
            for (py = 0; py < scale; py++)
                for (px = 0; px < scale; px++) plot(x0 + col * scale + px, y0 + row * scale + py);
        }
    }
    return 0;
}

static int join(void)
{
    uint32_t len, crc;
    if (command("join")) return 1;
    if (expect(LINE_QR, &len, &crc, ANSWER_SECONDS) != LINE_QR) return 1;
    if (qr((uint8_t)len)) return 1;
    // The phone scans; the pairing ends with CBBOK. SPACE cancels.
    if (expect(LINE_OK, &len, &crc, JOIN_SECONDS) != LINE_OK) return 1;
    link_prompt();
    zx_border(INK_BLACK);
    zx_cls(PAPER_WHITE | INK_BLACK);
    printf("Joined the group.\n");
    return 0;
}

static int run(int argc, char **argv)
{
    int i = 1;
    if (i < argc && strcmp(argv[i], "-d") == 0) {
        debug = 1;
        i++;
    }
    if (i >= argc) {
        usage();
        return 0;
    }
    link_open();
    // copy -s and text -s send a secret.
    if ((strcmp(argv[i], "copy") == 0 || strcmp(argv[i], "text") == 0) && i + 1 < argc && strcmp(argv[i + 1], "-s") == 0) {
        secret = 1;
        argv[i + 1] = argv[i];
        i++;
    }
    if (strcmp(argv[i], "paste") == 0 && argc - i <= 2) return paste(argc - i == 2 ? argv[i + 1] : 0);
    if (strcmp(argv[i], "copy") == 0 && argc - i == 2) return copy_file(argv[i + 1]);
    if (strcmp(argv[i], "text") == 0 && argc - i >= 2) return copy_words(argc - i - 1, argv + i + 1);
    if (strcmp(argv[i], "join") == 0 && argc - i == 1) return join();
    usage();
    return 1;
}

int main(int argc, char **argv)
{
    // Each command shows its own message; a nonzero result would make
    // NextZXOS add an unrelated error of its own.
    run(argc, argv);
    return 0;
}
