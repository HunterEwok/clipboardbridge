// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package phone

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/HunterEwok/clipbridge/internal/group"
	"github.com/HunterEwok/clipbridge/internal/pair"
	"github.com/HunterEwok/clipbridge/internal/uptime"
)

// Window is an open pairing window for an iPhone: a six-digit code that the
// user types on the pairing page, after trusting the iPhone CA. Like a
// computer's window it is open for five minutes, closes after a success or
// the third wrong code, and its time counts sleep.
type Window struct {
	code []byte
	ca   *group.CA

	mu       sync.Mutex
	expires  time.Duration
	failures int
	err      error // why it closed
	phoneID  string
	done     chan struct{}
	uptime   func() time.Duration
}

// OpenWindow opens a pairing window for the code.
func OpenWindow(ca *group.CA, code string) (*Window, error) {
	code, err := pair.NormalizeCode(code)
	if err != nil {
		return nil, err
	}
	if ca == nil || ca.Key == nil {
		return nil, errors.New("phone: only a Linux member that holds the iPhone CA can pair an iPhone")
	}
	return &Window{code: []byte(code), ca: ca, expires: uptime.Now() + pair.Lifetime, done: make(chan struct{}), uptime: uptime.Now}, nil
}

// Done is closed when the window closes.
func (w *Window) Done() <-chan struct{} { return w.done }

// Result returns the paired phone's ID, or why the window closed.
func (w *Window) Result() (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.phoneID != "" {
		return w.phoneID, nil
	}
	return "", w.err
}

// Close closes the window.
func (w *Window) Close() { w.closeWith(pair.ErrClosed) }

func (w *Window) closeWith(err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.closeLocked(err)
}

func (w *Window) closeLocked(err error) {
	if w.err == nil && w.phoneID == "" {
		w.err = err
		close(w.done)
	}
}

// try checks a code and returns a new token for a right one.
func (w *Window) try(code string) (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err == nil && w.phoneID == "" && w.uptime() >= w.expires {
		w.closeLocked(pair.ErrExpired)
	}
	if w.phoneID != "" {
		return "", pair.ErrClosed
	}
	if w.err != nil {
		return "", w.err
	}
	c, err := pair.NormalizeCode(code)
	if err != nil || subtle.ConstantTimeCompare([]byte(c), w.code) != 1 {
		w.failures++
		if w.failures >= pair.MaxFailures {
			w.closeLocked(pair.ErrTooMany)
		}
		return "", pair.ErrWrongCode
	}
	token, id, err := NewToken(w.ca)
	if err != nil {
		return "", err
	}
	w.phoneID = id
	close(w.done)
	return token, nil
}

// Fingerprint returns what the user compares under the profile's details:
// the SHA-256 fingerprint of the iPhone CA, in the groups iOS shows.
func Fingerprint(ca *group.CA) string { return group.Fingerprint(ca.Cert) }

// Profile returns the configuration profile that installs the iPhone CA.
// Its identifier is fixed, so a new profile replaces the old one.
func Profile(ca *group.CA) []byte {
	sum := sha256.Sum256(ca.Cert.Raw)
	uuid := func(salt byte) string {
		h := sha256.Sum256(append(sum[:], salt))
		h[6] = h[6]&0x0f | 0x50 // a name-based UUID
		h[8] = h[8]&0x3f | 0x80
		return fmt.Sprintf("%X-%X-%X-%X-%X", h[0:4], h[4:6], h[6:8], h[8:10], h[10:16])
	}
	der := base64.StdEncoding.EncodeToString(ca.Cert.Raw)
	return []byte(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>PayloadCertificateFileName</key>
			<string>clipbridge-iphone-ca.cer</string>
			<key>PayloadContent</key>
			<data>` + der + `</data>
			<key>PayloadDescription</key>
			<string>Lets the clipbridge shortcut reach clipbridge.local. The certificate is limited to that name.</string>
			<key>PayloadDisplayName</key>
			<string>` + template.HTMLEscapeString(ca.Cert.Subject.CommonName) + `</string>
			<key>PayloadIdentifier</key>
			<string>io.github.hunterewok.clipbridge.ca</string>
			<key>PayloadType</key>
			<string>com.apple.security.root</string>
			<key>PayloadUUID</key>
			<string>` + uuid(1) + `</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
		</dict>
	</array>
	<key>PayloadDescription</key>
	<string>Trust for clipbridge on this home network.</string>
	<key>PayloadDisplayName</key>
	<string>clipbridge</string>
	<key>PayloadIdentifier</key>
	<string>io.github.hunterewok.clipbridge</string>
	<key>PayloadRemovalDisallowed</key>
	<false/>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadUUID</key>
	<string>` + uuid(2) + `</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
</dict>
</plist>
`)
}

// ProfileHandler serves the profile port while a window is open: the
// profile, and a short page that links to it.
func ProfileHandler(ca *group.CA) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /clipbridge.mobileconfig", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-apple-aspen-config")
		w.Header().Set("Content-Disposition", `attachment; filename="clipbridge.mobileconfig"`)
		w.Write(Profile(ca))
	})
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		page(w, profilePage, map[string]string{"Fingerprint": Fingerprint(ca)})
	})
	return mux
}

// PairHandler serves the pairing page on the iPhone port. win returns the
// open window, or nil.
func PairHandler(win func() *Window) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /pair", func(w http.ResponseWriter, r *http.Request) {
		page(w, codePage, map[string]string{})
	})
	mux.HandleFunc("POST /pair", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		code := r.PostFormValue("code")
		wd := win()
		if wd == nil {
			page(w, codePage, map[string]string{"Error": "No pairing window is open. Run clipbridge pair -phone on a Linux member."})
			return
		}
		token, err := wd.try(code)
		if err != nil {
			msg := "Wrong code. Check it and try again."
			if !errors.Is(err, pair.ErrWrongCode) {
				msg = strings.TrimPrefix(err.Error(), "pair: ") + ". Run clipbridge pair -phone again."
			}
			page(w, codePage, map[string]string{"Error": msg})
			return
		}
		page(w, tokenPage, map[string]string{"Token": token})
	})
	return mux
}

func page(w http.ResponseWriter, t *template.Template, data map[string]string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'")
	w.Header().Set("X-Frame-Options", "DENY")
	t.Execute(w, data)
}

const pageHead = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>clipbridge</title>
<style>body{font:17px -apple-system,system-ui,sans-serif;margin:24px;max-width:36em;line-height:1.45}
input,button{font:inherit;padding:10px 12px;border-radius:10px;border:1px solid #888}
code{word-break:break-all;font-size:15px}.err{color:#b00020}.fp{font:15px ui-monospace,monospace}</style>
</head><body>`

var profilePage = template.Must(template.New("profile").Parse(pageHead + `
<h1>clipbridge</h1>
<ol>
<li><a href="/clipbridge.mobileconfig">Download the profile</a> and install it in Settings.</li>
<li>Under Settings &rsaquo; General &rsaquo; VPN &amp; Device Management &rsaquo; clipbridge &rsaquo; More Details, compare the SHA-256 fingerprint with the one the computer printed:
<p class="fp">{{.Fingerprint}}</p></li>
<li>Only if they match, turn on full trust under Settings &rsaquo; General &rsaquo; About &rsaquo; Certificate Trust Settings.</li>
<li>Then open <b>https://clipbridge.local:8765/pair</b>. It must open without a warning; if it does not, stop.</li>
</ol>
</body></html>`))

var codePage = template.Must(template.New("code").Parse(pageHead + `
<h1>Pair this iPhone</h1>
{{with .Error}}<p class="err">{{.}}</p>{{end}}
<form method="post" action="/pair">
<p><label>The code from clipbridge pair -phone:<br>
<input name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9 ]*" maxlength="7" required autofocus></label></p>
<p><button type="submit">Pair</button></p>
</form>
</body></html>`))

var tokenPage = template.Must(template.New("token").Parse(pageHead + `
<h1>Paired</h1>
<p>Install the clipbridge shortcut and paste this token when it asks for it:</p>
<p><code>{{.Token}}</code></p>
<p>Keep it private: it lets the shortcut use the group's clipboard. Then assign the shortcut to the Action button or to Back Tap.</p>
</body></html>`))
