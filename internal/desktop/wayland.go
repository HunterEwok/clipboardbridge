// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//go:build linux

package desktop

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/HunterEwok/clipbridge/internal/connector"
	"github.com/HunterEwok/clipbridge/internal/wl"
)

// The data-control protocols let a client without a window read and set
// the clipboard. The standard one, ext-data-control-v1, and the older
// wlr-data-control-unstable-v1 have the same requests and events.
var dataControls = []string{"ext_data_control_manager_v1", "zwlr_data_control_manager_v1"}

// Opcodes, the same in both protocols.
const (
	mgrCreateSource = 0
	mgrGetDevice    = 1

	devSetSelection        = 0
	devSetPrimarySelection = 2
	devEvDataOffer         = 0
	devEvSelection         = 1
	devEvFinished          = 2
	devEvPrimarySelection  = 3

	srcOffer     = 0
	srcDestroy   = 1
	srcEvSend    = 0
	srcEvCancel  = 1
	offerReceive = 0
	offerDestroy = 1
	offerEvOffer = 0
)

// textTypes are the MIME types and X11 targets of text, the best first.
var textTypes = []string{"text/plain;charset=utf-8", "UTF8_STRING", "text/plain", "STRING", "TEXT"}

// secretType is the type KDE's password managers add to a secret; any
// value counts.
const secretType = "x-kde-passwordManagerHint"

const (
	maxText     = 1 << 20
	readTimeout = 2 * time.Second
)

// Wayland is the clipboard of a Wayland session through data-control.
type Wayland struct {
	d      *wl.Display
	mgr    uint32
	device uint32
	ifaces string // the protocol's prefix, for the offer and source interfaces
	logf   func(string, ...any)

	mu       sync.Mutex
	offers   map[uint32][]string // the types of each live offer
	current  uint32              // the clipboard's offer, 0 if empty
	own      uint32              // the clipboard source this client set, 0 if none
	ownSet   bool                // the next selection event is for our own source
	item     connector.Item
	has      bool
	changes  chan connector.Item
	errc     chan error
	writeSeq int
}

// OpenWayland connects to the Wayland session and binds data-control.
func OpenWayland(logf func(string, ...any)) (*Wayland, error) {
	d, err := wl.Connect()
	if err != nil {
		return nil, err
	}
	reg, err := d.GetRegistry()
	if err != nil {
		d.Close()
		return nil, err
	}
	w := &Wayland{d: d, logf: logf, offers: map[uint32][]string{}, changes: make(chan connector.Item, 4), errc: make(chan error, 1)}
	var mgr wl.Global
	found := false
	for _, name := range dataControls {
		if mgr, found = reg.Find(name); found {
			break
		}
	}
	if !found {
		d.Close()
		return nil, errors.New("wayland: the compositor offers no data-control protocol")
	}
	seat, ok := reg.Find("wl_seat")
	if !ok {
		d.Close()
		return nil, errors.New("wayland: the compositor has no seat")
	}
	w.ifaces = mgr.Interface[:len(mgr.Interface)-len("manager_v1")]
	w.mgr = reg.Bind(mgr, 2, nil)
	seatID := reg.Bind(seat, 1, nil)
	w.device = d.NewID(w.deviceEvent)
	if err := d.Send(w.mgr, mgrGetDevice, (&wl.Request{}).Uint(w.device).Uint(seatID)); err != nil {
		d.Close()
		return nil, err
	}
	// The device announces the current selection right away.
	if err := d.Roundtrip(); err != nil {
		d.Close()
		return nil, err
	}
	go w.loop()
	return w, nil
}

// Close closes the connection.
func (w *Wayland) Close() error { return w.d.Close() }

func (w *Wayland) loop() {
	for {
		if err := w.d.Dispatch(); err != nil {
			select {
			case w.errc <- fmt.Errorf("%w: %v", connector.ErrBoardGone, err):
			default:
			}
			return
		}
	}
}

func (w *Wayland) deviceEvent(op uint16, a *wl.Args) error {
	switch op {
	case devEvDataOffer:
		id := a.Uint()
		if a.Err != nil {
			return a.Err
		}
		w.mu.Lock()
		w.offers[id] = nil
		w.mu.Unlock()
		w.d.SetHandler(id, func(op uint16, a *wl.Args) error {
			if op == offerEvOffer {
				t := a.String()
				w.mu.Lock()
				if types, ok := w.offers[id]; ok {
					w.offers[id] = append(types, t)
				}
				w.mu.Unlock()
			}
			return a.Err
		})
	case devEvSelection:
		id := a.Uint()
		if a.Err != nil {
			return a.Err
		}
		w.selection(id)
	case devEvPrimarySelection:
		// Mouse selections are not sent to the group; let the offer go.
		if id := a.Uint(); id != 0 {
			w.dropOffer(id)
		}
	case devEvFinished:
		return errors.New("wayland: the data-control device was taken away")
	}
	return a.Err
}

func (w *Wayland) dropOffer(id uint32) {
	w.mu.Lock()
	delete(w.offers, id)
	w.mu.Unlock()
	w.d.Send(id, offerDestroy, nil)
	w.d.Forget(id)
}

// selection handles a new clipboard selection: it reads the text in the
// background, since reading our own selection needs the event loop.
func (w *Wayland) selection(id uint32) {
	w.mu.Lock()
	old := w.current
	w.current = id
	types := slices.Clone(w.offers[id])
	own := w.ownSet && w.own != 0
	w.ownSet = false
	w.mu.Unlock()
	if old != 0 && old != id {
		w.dropOffer(old)
	}
	if id == 0 {
		w.mu.Lock()
		w.item, w.has = connector.Item{}, false
		w.mu.Unlock()
		return
	}
	if own {
		return // our own write coming back
	}
	go func() {
		it, ok, err := w.read(id, types)
		if err != nil {
			w.logf("clipbridge: reading the clipboard: %v", err)
			return
		}
		w.mu.Lock()
		if w.current != id {
			w.mu.Unlock()
			return // already replaced
		}
		w.item, w.has = it, ok
		w.mu.Unlock()
		if ok {
			select {
			case w.changes <- it:
			default:
				// The connector is behind; the latest item wins below.
				select {
				case <-w.changes:
				default:
				}
				w.changes <- it
			}
		}
	}()
}

// read receives the text of an offer through a pipe.
func (w *Wayland) read(id uint32, types []string) (connector.Item, bool, error) {
	mime := ""
	for _, t := range textTypes {
		if slices.Contains(types, t) {
			mime = t
			break
		}
	}
	if mime == "" {
		return connector.Item{}, false, nil
	}
	var p [2]int
	if err := unix.Pipe2(p[:], unix.O_CLOEXEC); err != nil {
		return connector.Item{}, false, err
	}
	r := os.NewFile(uintptr(p[0]), "clipboard")
	defer r.Close()
	err := w.d.Send(id, offerReceive, (&wl.Request{}).String(mime).FD(p[1]))
	unix.Close(p[1])
	if err != nil {
		return connector.Item{}, false, err
	}
	r.SetReadDeadline(time.Now().Add(readTimeout))
	data, err := io.ReadAll(io.LimitReader(r, maxText+1))
	if err != nil {
		return connector.Item{}, false, err
	}
	if len(data) > maxText {
		return connector.Item{}, false, fmt.Errorf("the clipboard holds more than %d bytes", maxText)
	}
	return connector.Item{Text: string(data), Secret: slices.Contains(types, secretType)}, len(data) > 0, nil
}

// Current returns what the clipboard holds.
func (w *Wayland) Current() (connector.Item, bool, error) {
	// The first selection may still be reading; give it a moment.
	deadline := time.Now().Add(readTimeout)
	for {
		w.mu.Lock()
		it, has, cur := w.item, w.has, w.current
		w.mu.Unlock()
		if has || cur == 0 || time.Now().After(deadline) {
			return it, has, nil
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Next waits for a change that is not our own.
func (w *Wayland) Next(ctx context.Context) (connector.Item, bool, error) {
	select {
	case it := <-w.changes:
		return it, true, nil
	case err := <-w.errc:
		return connector.Item{}, false, err
	case <-ctx.Done():
		return connector.Item{}, false, ctx.Err()
	}
}

// Write sets the clipboard and the primary selection, so Ctrl+V works in
// applications and Shift+Insert and the middle button in terminals.
func (w *Wayland) Write(text string, secret bool) error {
	types := slices.Clone(textTypes)
	if secret {
		types = append(types, secretType)
	}
	clip, err := w.source(text, types)
	if err != nil {
		return err
	}
	w.mu.Lock()
	if w.own != 0 {
		defer w.destroySource(w.own)
	}
	w.own, w.ownSet = clip, true
	w.mu.Unlock()
	if err := w.d.Send(w.device, devSetSelection, (&wl.Request{}).Uint(clip)); err != nil {
		return err
	}
	if primary, err := w.source(text, types); err == nil {
		w.d.Send(w.device, devSetPrimarySelection, (&wl.Request{}).Uint(primary))
	}
	w.mu.Lock()
	w.item, w.has = connector.Item{Text: text, Secret: secret}, true
	w.mu.Unlock()
	return nil
}

// source makes a data source that serves text for the types.
func (w *Wayland) source(text string, types []string) (uint32, error) {
	var id uint32
	id = w.d.NewID(func(op uint16, a *wl.Args) error {
		switch op {
		case srcEvSend:
			mime := a.String()
			fd := a.FD()
			if a.Err != nil {
				return a.Err
			}
			go func() {
				f := os.NewFile(uintptr(fd), "clipboard")
				defer f.Close()
				if mime == secretType {
					f.WriteString("secret")
					return
				}
				f.WriteString(text)
			}()
		case srcEvCancel:
			w.mu.Lock()
			if w.own == id {
				w.own = 0
			}
			w.mu.Unlock()
			w.destroySource(id)
		}
		return a.Err
	})
	if err := w.d.Send(w.mgr, mgrCreateSource, (&wl.Request{}).Uint(id)); err != nil {
		return 0, err
	}
	for _, t := range types {
		if err := w.d.Send(id, srcOffer, (&wl.Request{}).String(t)); err != nil {
			return 0, err
		}
	}
	return id, nil
}

func (w *Wayland) destroySource(id uint32) {
	w.d.Send(id, srcDestroy, nil)
	w.d.Forget(id)
}

// ClearIfUnchanged empties the clipboard if it still holds our last write.
func (w *Wayland) ClearIfUnchanged() error {
	w.mu.Lock()
	own := w.own
	w.mu.Unlock()
	if own == 0 {
		return nil
	}
	if err := w.d.Send(w.device, devSetSelection, (&wl.Request{}).Uint(0)); err != nil {
		return err
	}
	w.d.Send(w.device, devSetPrimarySelection, (&wl.Request{}).Uint(0))
	return nil
}
