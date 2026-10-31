// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// fileKeys (K11): a group whose root and admins keep their keys in files
// says so: cbb new warns on the root, cbb status marks each device's keys,
// and making a computer with a file key an admin is refused unless asked
// for with -allow-file-key, with what a thief could do. The offer to move
// to a proven root is the phone's (ui).
func fileKeys(ctx context.Context, r *Report, f *Fleet, timeout time.Duration) {
	const p = "fleet/K11-file-keys/"
	ds := make([]*Device, 2)
	if r.Do(p+"start", func() error {
		for i := range ds {
			var err error
			if ds[i], err = f.Add(ctx); err != nil {
				return err
			}
		}
		return nil
	}) != nil {
		return
	}
	root, m := ds[0], ds[1]
	r.Do(p+"new-warns", func() error {
		return succeeds(ctx, root, "cbb new", "", "Its root key is a file here: guard this computer")
	})
	r.Do(p+"join", func() error {
		_, err := pairOne(ctx, root, m)
		return err
	})
	r.Do(p+"status-marks", func() error {
		return eventually(ctx, 20*time.Second, func() error {
			for _, d := range ds {
				row, err := statusRow(ctx, root, d.Name)
				if err != nil {
					return err
				}
				if !strings.Contains(row, "in a file") {
					return fmt.Errorf("cbb status does not mark %s's keys as in a file: %q", d.Name, row)
				}
			}
			return nil
		})
	})
	fails(ctx, r, p+"admin-refused", root, errorCase{cmd: "cbb admin " + m.Name, want: []string{"keeps its keys in a file", "-allow-file-key"}})
	r.Do(p+"admin-allowed", func() error {
		out, err := Run(ctx, root, "cbb admin -allow-file-key "+m.Name, "")
		if err != nil {
			return err
		}
		for _, want := range []string{"is an admin now", "guard it: whoever copies that file acts as an admin"} {
			if !strings.Contains(out, want) {
				return fmt.Errorf("cbb admin -allow-file-key printed %q, without %q", out, want)
			}
		}
		return nil
	})
	r.Do(p+"admin-marked", func() error {
		return eventually(ctx, 20*time.Second, func() error {
			row, err := statusRow(ctx, root, m.Name)
			if err == nil && (!strings.Contains(row, "admin") || !strings.Contains(row, "in a file")) {
				err = fmt.Errorf("cbb status shows the new admin %s as %q", m.Name, row)
			}
			return err
		})
	})
}
