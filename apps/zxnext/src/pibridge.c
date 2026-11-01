// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// .pibridge: a test tool that opens NextPi's shell (SUP>) to a computer on
// the home network. The Next's ESP8266 dials the computer in its stock AT
// firmware's passthrough mode, and the Z80 copies bytes between the Pi's
// UART and the ESP's until SPACE is pressed. It carries the Pi's root shell
// in the clear, so it is for a test bench only (README.md, "Test bench").
// It is also the first step of the Pi's network through the ESP8266
// (docs/roadmap.md, item 14), and it counts the times a receive buffer
// filled up, which tells whether the Z80 keeps up.

#include <arch/zxn.h>
#include <input.h>
#include <stdio.h>
#include <string.h>
#include <z80.h>

#include "link.h"

#define VERSION "0.3.1"
// Rings for each direction: the UARTs' own buffers are small, so the Z80
// takes in what arrives at once and passes it on as the other side has
// room, one byte at a time, without waiting on either.
#define TO_ESP 2048 // the Pi's output, which comes in long runs
#define TO_PI 1024  // what the computer types

static uint8_t ring_esp[TO_ESP], ring_pi[TO_PI];
static uint16_t esp_in, esp_out, pi_in, pi_out;
static char line[80];
static uint8_t debug;
static uint32_t to_pi, to_esp;

// The ROM's frame counter, 50 a second while interrupts run.
#define FRAMES (*(volatile uint8_t *)23672)
// The ROM's scroll count: kept high, the screen scrolls on without asking
// "scroll?", which would hold the bridge until a key is pressed.
#define SCR_CT (*(volatile uint8_t *)23692)
#define NO_SCROLL_PROMPT() (SCR_CT = 255)

static void usage(void)
{
    printf("pibridge " VERSION "\n\n"
           "Opens the Pi's shell to a\n"
           "computer on the network, over\n"
           "the Next's Wi-Fi. TEST ONLY: the\n"
           "shell travels in the clear.\n\n"
           ".pibridge HOST PORT\n"
           ".pibridge -d HOST PORT  details\n"
           "SPACE stops.\n");
}

static int fail(const char *msg, const char *detail)
{
    NO_SCROLL_PROMPT();
    printf("pibridge: %s\n", msg);
    if (debug && detail && *detail) printf("  (%s)\n", detail);
    return 1;
}

// Reads the ESP's lines until one starts with want or an error; 0 when it
// is want. In debug mode every line is shown.
static uint8_t esp_expect(const char *want, uint16_t seconds)
{
    uint8_t n = strlen(want);
    for (;;) {
        if (link_line(line, sizeof line, seconds) != LINK_OK) {
            strcpy(line, "no answer");
            return 1;
        }
        if (!line[0]) continue;
        if (debug) {
            NO_SCROLL_PROMPT();
            printf("  esp: %s\n", line);
        }
        if (strncmp(line, want, n) == 0) return 0;
        if (strcmp(line, "ALREADY CONNECTED") == 0) return 0; // CIPSTART, still open
        if (strcmp(line, "ERROR") == 0 || strcmp(line, "FAIL") == 0 || strncmp(line, "busy", 4) == 0) return 1;
    }
}


// Waits ticks frames; a cap on the rounds ends it if interrupts are off.
static void wait_frames(uint8_t ticks)
{
    uint8_t last = FRAMES;
    uint32_t rounds = 4000000UL;
    while (ticks && --rounds) {
        if (FRAMES != last) {
            last = FRAMES;
            ticks--;
        }
    }
}

// Reads and drops what the ESP still sends (the late answer to an earlier
// command) until it is quiet for ticks frames.
static void esp_quiet(uint8_t ticks)
{
    uint8_t last = FRAMES, left = ticks;
    uint32_t rounds = 4000000UL;
    while (left && --rounds) {
        if (link_ready()) {
            uint8_t c = link_get();
            if (debug && c >= 32 && c < 127) {
                NO_SCROLL_PROMPT();
                putchar(c);
            }
            left = ticks;
        } else if (FRAMES != last) {
            last = FRAMES;
            left--;
        }
    }
}

static uint8_t esp_command(const char *cmd, const char *want, uint16_t seconds)
{
    esp_quiet(10);
    link_send_str(cmd);
    link_send_str("\r\n");
    return esp_expect(want, seconds);
}

// Waits for the '>' that starts passthrough.
static uint8_t esp_prompt(void)
{
    uint8_t c;
    while (link_recv(&c, 5) == LINK_OK) {
        if (c == '>') return 0;
    }
    return 1;
}

// Software flow control towards the Pi: its shell's terminal stops writing
// on XOFF and goes on at XON (stty ixon), so a burst longer than the ring
// waits on the Pi instead of overflowing the Next's small UART buffer.
#define XOFF 0x13
#define XON 0x11
#define PAUSE_AT (TO_ESP * 3 / 4)
#define RESUME_AT (TO_ESP / 4)

static uint8_t paused, control; // control: XOFF or XON still to send
static uint16_t fill_max, pauses, over_pi, over_esp;

// One round in each direction.
static void pump(void)
{
    uint16_t fill, over;
    link_use(LINK_PI);
    over = link_overflows();
    while (((esp_in + 1) & (TO_ESP - 1)) != esp_out && link_ready()) {
        ring_esp[esp_in] = link_get();
        esp_in = (esp_in + 1) & (TO_ESP - 1);
    }
    over_pi += link_overflows() - over;
    fill = (esp_in - esp_out) & (TO_ESP - 1);
    if (fill > fill_max) fill_max = fill;
    if (!paused && fill >= PAUSE_AT) {
        paused = 1;
        control = XOFF;
        pauses++;
    } else if (paused && fill <= RESUME_AT) {
        paused = 0;
        control = XON;
    }
    if (control && link_can_send()) {
        link_put(control);
        control = 0;
    }
    while (!control && pi_out != pi_in && link_can_send()) {
        link_put(ring_pi[pi_out]);
        pi_out = (pi_out + 1) & (TO_PI - 1);
        to_pi++;
    }
    link_use(LINK_ESP);
    over = link_overflows();
    while (((pi_in + 1) & (TO_PI - 1)) != pi_out && link_ready()) {
        ring_pi[pi_in] = link_get();
        pi_in = (pi_in + 1) & (TO_PI - 1);
    }
    over_esp += link_overflows() - over;
    while (esp_out != esp_in && link_can_send()) {
        link_put(ring_esp[esp_out]);
        esp_out = (esp_out + 1) & (TO_ESP - 1);
        to_esp++;
    }
}

static void esp_hang_up(void)
{
    link_use(LINK_ESP);
    wait_frames(60); // the ESP takes +++ only after a second of quiet
    link_send_str("+++");
    wait_frames(60);
    esp_command("AT+CIPMODE=0", "OK", 2);
    esp_command("AT+CIPCLOSE", "OK", 2);
}

// The port, or 0 if s is not a number from 1 to 65535.
static uint16_t parse_port(const char *s)
{
    uint32_t n = 0;
    if (!*s) return 0;
    for (; *s; s++) {
        if (*s < '0' || *s > '9') return 0;
        n = n * 10 + (*s - '0');
        if (n > 65535UL) return 0;
    }
    return (uint16_t)n;
}

#define NR_CPU_SPEED 0x07

static uint8_t nextreg_get(uint8_t reg)
{
    z80_outp(0x243B, reg);
    return z80_inp(0x253B);
}

static void nextreg_set(uint8_t reg, uint8_t value)
{
    z80_outp(0x243B, reg);
    z80_outp(0x253B, value);
}

static uint8_t speed; // the CPU speed it found, restored at the end

static int run(int argc, char **argv)
{
    uint8_t i = 1;
    uint16_t port;
    char cmd[80];
    if (i < argc && strcmp(argv[i], "-d") == 0) {
        debug = 1;
        i++;
    }
    if (argc - i != 2) {
        usage();
        return 1;
    }
    port = parse_port(argv[i + 1]);
    if (!port || strlen(argv[i]) > 40) return fail("give a host and a port", argv[i + 1]);

    speed = nextreg_get(NR_CPU_SPEED) & 3;
    nextreg_set(NR_CPU_SPEED, 3); // 28 MHz while it runs
    link_open();            // the Pi's UART, at NextPi's speed
    link_open_esp(115200UL); // the ESP's, at its stock speed
    link_use(LINK_ESP);
    // A run that ended without its hang-up can leave the ESP in passthrough,
    // where AT would go to the old connection: leave it first.
    wait_frames(60);
    link_send_str("+++");
    wait_frames(60);
    if (esp_command("AT", "OK", 2) && esp_command("AT", "OK", 2)) {
        return fail("the Wi-Fi module does not answer", line);
    }
    esp_command("ATE0", "OK", 2);
    if (debug) esp_command("AT+GMR", "OK", 2);
    esp_command("AT+CIPMODE=0", "OK", 2);
    esp_command("AT+CIPCLOSE", "OK", 5); // an old connection, if any
    esp_quiet(50); // old firmware (AT 1.2) can answer late
    sprintf(cmd, "AT+CIPSTART=\"TCP\",\"%s\",%u", argv[i], port);
    if (esp_command(cmd, "OK", 15)) {
        esp_command("AT+CIPCLOSE", "OK", 5); // it may have connected anyway
        return fail("could not reach the computer; is Wi-Fi joined and the port open?", line);
    }
    if (esp_command("AT+CIPMODE=1", "OK", 2) || (link_send_str("AT+CIPSEND\r\n"), esp_prompt())) {
        esp_hang_up();
        return fail("the Wi-Fi module did not start passthrough", line);
    }
    NO_SCROLL_PROMPT();
    printf("Connected to %s:%u.\nSPACE stops.\n", argv[i], port);

    link_use(LINK_PI);
    link_send('\n'); // so the computer sees SUP> at once
    while (!in_key_pressed(IN_KEY_SCANCODE_SPACE)) {
        pump();
    }
    if (paused) link_send(XON);
    esp_hang_up();
    link_use(LINK_PI);
    NO_SCROLL_PROMPT();
    printf("Stopped. %lu bytes to the Pi,\n%lu from it.\n", to_pi, to_esp);
    printf("Ring to the ESP: up to %u of %u,\n%u pauses (XOFF).\n", fill_max, TO_ESP, pauses);
    if (over_pi || over_esp) printf("A receive buffer filled up:\nPi %u, ESP %u times;\nbytes may be lost.\n", over_pi, over_esp);
    return 0;
}

int main(int argc, char **argv)
{
    speed = 0xFF;
    run(argc, argv);
    if (speed != 0xFF) nextreg_set(NR_CPU_SPEED, speed);
    return 0;
}
