// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The C side of the macOS pasteboard binding. A NULL or empty name is the
// general pasteboard; another name is a private pasteboard, for tests.

#define CB_SECRET 1 // a password manager marked the item
#define CB_REMOTE 2 // the item came through Universal Clipboard

long cb_change_count(const char *name);
int cb_read(const char *name, char **text, long *len, int *flags, long *change);
long cb_write(const char *name, const char *text, long len, int secret);
long cb_clear(const char *name);
void cb_release(const char *name);
