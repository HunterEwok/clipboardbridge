// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package update

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// signature is what Get-AuthenticodeSignature says of a file.
type signature struct {
	Status  string `json:"status"`
	Subject string `json:"subject"`
}

func authenticode(path string) (signature, error) {
	script := `$s = Get-AuthenticodeSignature -LiteralPath '` + strings.ReplaceAll(path, "'", "''") + `'
$subject = if ($s.SignerCertificate) { $s.SignerCertificate.Subject } else { '' }
[pscustomobject]@{ status = [string]$s.Status; subject = $subject } | ConvertTo-Json -Compress`
	out, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script).Output()
	if err != nil {
		return signature{}, fmt.Errorf("checking the signature of %s: %w", path, err)
	}
	var s signature
	if err := json.Unmarshal(out, &s); err != nil {
		return signature{}, fmt.Errorf("checking the signature of %s: %w", path, err)
	}
	return s, nil
}

// VerifySigner refuses new programs that are not Authenticode-signed by
// the same signer as the installed ones, when those are signed: any valid
// signature is not enough. Unsigned installed programs (releases made
// before the project's certificate) leave release.json as the only check.
func VerifySigner(installed, unpacked []string) error {
	for i, p := range installed {
		old, err := authenticode(p)
		if err != nil {
			return err
		}
		if old.Status != "Valid" {
			continue
		}
		s, err := authenticode(unpacked[i])
		if err != nil {
			return err
		}
		if s.Status != "Valid" || s.Subject != old.Subject {
			return fmt.Errorf("the new %s is not signed by %s (its signature: %s %s); not installing it", unpacked[i], old.Subject, s.Status, s.Subject)
		}
	}
	return nil
}
