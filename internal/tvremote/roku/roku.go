// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Package roku types on a Roku player or TV through its External Control
// Protocol (docs/roadmap.md, item 25): plain HTTP on port 8060, a
// keypress for each character. ECP has no pairing and no encryption:
// anyone on the network sees the text, and the Roku takes keys from
// anyone. Since Roku OS 14.1 it needs "Control by mobile apps" set to
// "Enabled" or "Permissive" in Settings > System > Advanced system
// settings.
package roku

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Port is ECP's port.
const Port = 8060

// keyGap is the pause between keys: a Roku drops keys sent faster.
const keyGap = 20 * time.Millisecond

// ErrOff is a Roku that does not take keys from the network.
var ErrOff = errors.New(`the Roku does not take keys from the network: set "Control by mobile apps" to "Enabled" or "Permissive" in Settings > System > Advanced system settings`)

// Client talks to one Roku.
type Client struct {
	base string
	http *http.Client
}

// New is the client of the Roku at host, which may name another port, for
// tests. dial is how it connects, net.Dialer's DialContext if nil.
func New(host string, dial func(ctx context.Context, network, addr string) (net.Conn, error)) *Client {
	if _, _, err := net.SplitHostPort(host); err != nil {
		host = net.JoinHostPort(host, fmt.Sprint(Port))
	}
	if dial == nil {
		dial = (&net.Dialer{Timeout: 5 * time.Second}).DialContext
	}
	return &Client{
		base: "http://" + host,
		http: &http.Client{
			Timeout:   10 * time.Second,
			Transport: &http.Transport{DialContext: dial, Proxy: nil},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// Name is the Roku's name, as it gives it, and checks that it takes keys.
func (c *Client) Name(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/query/device-info", nil)
	if err != nil {
		return "", err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("cannot reach the Roku: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden {
		return "", ErrOff
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("the Roku answered %s", resp.Status)
	}
	var info struct {
		Name  string `xml:"user-device-name"`
		Model string `xml:"friendly-model-name"`
	}
	if err := xml.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&info); err != nil {
		return "", fmt.Errorf("the Roku's device info: %w", err)
	}
	if info.Name == "" {
		info.Name = info.Model
	}
	if info.Name == "" {
		info.Name = "Roku"
	}
	return info.Name, nil
}

// Type types text, with Enter for each line break.
func (c *Client) Type(ctx context.Context, text string) error {
	first := true
	for _, r := range strings.ReplaceAll(text, "\r\n", "\n") {
		if !first {
			t := time.NewTimer(keyGap)
			select {
			case <-ctx.Done():
				t.Stop()
				return ctx.Err()
			case <-t.C:
			}
		}
		first = false
		key := "Lit_" + url.PathEscape(string(r))
		if r == '\n' {
			key = "Enter"
		}
		if err := c.press(ctx, key); err != nil {
			return err
		}
	}
	return nil
}

func (c *Client) press(ctx context.Context, key string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/keypress/"+key, nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("cannot reach the Roku: %w", err)
	}
	resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK, http.StatusAccepted, http.StatusNoContent:
		return nil
	case http.StatusForbidden:
		return ErrOff
	}
	return fmt.Errorf("the Roku answered %s", resp.Status)
}
