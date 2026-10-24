// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The UART between the Next and its Raspberry Pi, and NextPi's shell on it.

#ifndef CBB_LINK_H
#define CBB_LINK_H

#include <stdint.h>

// Why a link call failed.
enum {
    LINK_OK,
    LINK_TIMEOUT, // nothing arrived in time
    LINK_BREAK    // the user pressed SPACE
};

// Points the UART at the Pi at the speed NextPi uses (from NR 0x7F, which
// .pisend -q sets, else 115200).
void link_open(void);

// Makes NextPi's shell (SUP>) ready for a command; 0 if the Pi answers.
uint8_t link_shell(void);

void link_send(uint8_t c);
void link_send_str(const char *s);

// One byte, waiting up to seconds; LINK_OK with the byte in *c.
uint8_t link_recv(uint8_t *c, uint16_t seconds);

// One line up to CR, without it (LF and NUL are dropped), cut to max-1
// characters; waits up to seconds for each byte.
uint8_t link_line(char *buf, uint8_t max, uint16_t seconds);

// Reads until the shell prompt comes back, so the next command starts clean.
void link_prompt(void);

#endif
