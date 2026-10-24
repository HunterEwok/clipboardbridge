// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package control

import (
	"errors"
	"net"
	"os"
	"time"
)

// SocketPath returns the control socket to use: $CBB_SOCKET, or
// DefaultSocket.
func SocketPath() string {
	if p := os.Getenv("CBB_SOCKET"); p != "" {
		return p
	}
	return DefaultSocket
}

// A Client is a connection to the service.
type Client struct {
	c net.Conn
	r *Reader
}

// Dial connects to the service.
func Dial(path string) (*Client, error) {
	c, err := net.DialTimeout("unix", path, 5*time.Second)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return nil, errors.New("no permission to use the clipboardbridge service; " + permissionHint)
		}
		return nil, errors.New("the clipboardbridge service is not running (" + err.Error() + ")")
	}
	return &Client{c: c, r: NewReader(c)}, nil
}

// Close closes the connection.
func (c *Client) Close() error { return c.c.Close() }

// SetDeadline sets the deadline for sending and receiving.
func (c *Client) SetDeadline(t time.Time) error { return c.c.SetDeadline(t) }

// Send sends a message.
func (c *Client) Send(m *Message) error { return Write(c.c, m) }

// Receive reads the next message. An answer with an error becomes the
// error.
func (c *Client) Receive() (*Message, error) {
	m, err := c.r.Read()
	if err != nil {
		return nil, err
	}
	if m.Error != "" {
		return m, &RequestError{Msg: m.Error, Detail: m.Detail}
	}
	return m, nil
}

// A RequestError is a request the service refused or could not do: Msg for
// the user, and Detail, when there is one, for debugging.
type RequestError struct {
	Msg, Detail string
}

func (e *RequestError) Error() string { return e.Msg }

// Do sends a request and returns its single answer.
func (c *Client) Do(m *Message) (*Message, error) {
	if err := c.Send(m); err != nil {
		return nil, err
	}
	return c.Receive()
}
