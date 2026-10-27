// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package node

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/HunterEwok/clipboardbridge/internal/clip"
)

// memContent holds parts in memory.
type memContent struct {
	mu    sync.Mutex
	parts map[[sha256.Size]byte][]byte
}

func (m *memContent) put(b []byte) clip.Part {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.parts == nil {
		m.parts = make(map[[sha256.Size]byte][]byte)
	}
	sum := sha256.Sum256(b)
	m.parts[sum] = b
	return clip.Part{Size: int64(len(b)), SHA256: sum[:]}
}

func (m *memContent) Open(sum [sha256.Size]byte) (io.ReaderAt, int64, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.parts[sum]
	return bytes.NewReader(b), int64(len(b)), ok
}

func withContent(c Content) option {
	return func(_ *clip.Config, nc *Config) { nc.Content = c }
}

func random(t *testing.T, n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

// fetchAll fetches a part from offset on into one buffer.
func fetchAll(ctx context.Context, m *member, from *member, p clip.Part, offset int64) ([]byte, error) {
	var got bytes.Buffer
	err := m.Fetch(ctx, from.id.ID, [sha256.Size]byte(p.SHA256), p.Size, offset, func(off int64, data []byte) error {
		if off != offset+int64(got.Len()) {
			return errors.New("a piece out of order")
		}
		got.Write(data)
		return nil
	})
	return got.Bytes(), err
}

// TestContentTransfer: a media event reaches the other member as a
// manifest, which fetches each part by its hash, from the start or from an
// offset, while texts keep flowing; a part the peer lacks is missing, and a
// peer that serves no content is not asked.
func TestContentTransfer(t *testing.T) {
	var store memContent
	big, small := random(t, 5<<20+12345), []byte("<b>hi</b>")
	bp := store.put(big)
	bp.Type = clip.TypePNG
	sp := store.put(small)
	sp.Type = clip.TypeHTML
	mac := newMember(t, Full, withContent(&store), withTimers(50*time.Millisecond, 2*time.Second))
	pi := newMember(t, Full, withContent(&memContent{}), withTimers(50*time.Millisecond, 2*time.Second))
	link(t, mac, pi)
	waitPeers(t, mac, 1)
	waitPeers(t, pi, 1)
	if !pi.Peers()[0].Media {
		t.Fatal("the Mac's hello does not say it serves content")
	}
	m := &clip.Manifest{Size: bp.Size + sp.Size, Parts: []clip.Part{bp, sp}}
	if err := mac.SendMedia(m, "a picture", clip.Copy); err != nil {
		t.Fatal(err)
	}
	w := waitWrite(t, pi, "a picture")
	if w.Kind != clip.Media || w.Media == nil || len(w.Media.Parts) != 2 || w.Origin != mac.id.ID || w.ID == "" {
		t.Fatalf("the write %+v", w)
	}

	ctx := context.Background()
	done := make(chan error, 1)
	var got []byte
	go func() {
		var err error
		got, err = fetchAll(ctx, pi, mac, w.Media.Parts[0], 0)
		done <- err
	}()
	// A text goes ahead of the chunks.
	if _, err := mac.Copied("meanwhile", clip.Text, clip.Copy); err != nil {
		t.Fatal(err)
	}
	waitWrite(t, pi, "meanwhile")
	if err := wait(t, done, "the fetch"); err != nil || !bytes.Equal(got, big) {
		t.Fatalf("fetched %d bytes, %v", len(got), err)
	}
	if got, err := fetchAll(ctx, pi, mac, w.Media.Parts[0], 3<<20+7); err != nil || !bytes.Equal(got, big[3<<20+7:]) {
		t.Errorf("from an offset: %d bytes, %v", len(got), err)
	}
	if got, err := fetchAll(ctx, pi, mac, w.Media.Parts[1], 0); err != nil || string(got) != string(small) {
		t.Errorf("the small part: %q, %v", got, err)
	}

	other := sha256.Sum256([]byte("nobody has this"))
	if _, err := fetchAll(ctx, pi, mac, clip.Part{Size: 10, SHA256: other[:]}, 0); !errors.Is(err, ErrMissing) {
		t.Errorf("a part the Mac lacks: %v", err)
	}

	// A fetch that stops lets the next one start over.
	cctx, cancel := context.WithCancel(ctx)
	n := 0
	err := pi.Fetch(cctx, mac.id.ID, [sha256.Size]byte(bp.SHA256), bp.Size, 0, func(int64, []byte) error {
		if n++; n == 2 {
			cancel()
		}
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("a cancelled fetch: %v", err)
	}
	if got, err := fetchAll(ctx, pi, mac, w.Media.Parts[0], 0); err != nil || !bytes.Equal(got, big) {
		t.Errorf("after a cancel: %d bytes, %v", len(got), err)
	}

	// A member that serves no content is never asked.
	lite := newMember(t, Full)
	link(t, lite, mac)
	waitPeers(t, mac, 2)
	if _, err := fetchAll(ctx, mac, lite, bp, 0); err == nil || !strings.Contains(err.Error(), "serves no content") {
		t.Errorf("a fetch from a member without content: %v", err)
	}
}

func TestChunkFrames(t *testing.T) {
	data := random(t, ChunkSize)
	ch := chunk{sum: sha256.Sum256(data), offset: 1 << 33, data: data}
	f := encodeChunk(ch)
	if (len(f)-4)%chunkPad != 0 || len(f)-4 > maxChunkFrame {
		t.Errorf("a frame of %d bytes", len(f))
	}
	m, err := readMessage(deadlineReader{bytes.NewReader(f)}, time.Second)
	if err != nil || m.Type != typeChunk || m.chunk.offset != ch.offset || m.chunk.sum != ch.sum || !bytes.Equal(m.chunk.data, data) {
		t.Fatalf("decoded %+v, %v", m, err)
	}
	small := encodeChunk(chunk{data: []byte("x")})
	if len(small) != 4+chunkPad {
		t.Errorf("a small chunk's frame has %d bytes", len(small))
	}
	// A binary frame longer than a chunk closes the connection.
	big := []byte{0x80, 0x10, 0, 0}
	if _, err := readMessage(deadlineReader{bytes.NewReader(big)}, time.Second); err == nil {
		t.Error("a binary frame of 1 MiB was read")
	}
}

type deadlineReader struct{ io.Reader }

func (deadlineReader) SetReadDeadline(time.Time) error { return nil }

// gatedContent holds parts whose reads wait until gate is closed.
type gatedContent struct {
	memContent
	gate chan struct{}
}

type gatedReader struct {
	io.ReaderAt
	gate chan struct{}
}

func (r gatedReader) ReadAt(p []byte, off int64) (int, error) {
	<-r.gate
	return r.ReaderAt.ReadAt(p, off)
}

func (g *gatedContent) Open(sum [sha256.Size]byte) (io.ReaderAt, int64, bool) {
	r, n, ok := g.memContent.Open(sum)
	return gatedReader{r, g.gate}, n, ok
}

// TestFetchStall: a fetch to which the peer sends nothing gives up after
// fetchStall and cancels its ranges, and the next fetch gets the part
// whole; a chunk that comes after its fetch returned never blocks the
// connection's reader.
func TestFetchStall(t *testing.T) {
	old := fetchStall
	fetchStall = 300 * time.Millisecond
	t.Cleanup(func() { fetchStall = old })
	store := &gatedContent{gate: make(chan struct{})}
	data := random(t, 3<<20+5)
	p := store.put(data)
	mac := newMember(t, Full, withContent(store), withTimers(50*time.Millisecond, 2*time.Second))
	pi := newMember(t, Full, withContent(&memContent{}), withTimers(50*time.Millisecond, 2*time.Second))
	link(t, mac, pi)
	waitPeers(t, mac, 1)
	waitPeers(t, pi, 1)

	ctx := context.Background()
	if _, err := fetchAll(ctx, pi, mac, p, 0); err == nil || !strings.Contains(err.Error(), "sent nothing") {
		t.Fatalf("a fetch from a peer that sends nothing: %v", err)
	}
	close(store.gate)
	if got, err := fetchAll(ctx, pi, mac, p, 0); err != nil || !bytes.Equal(got, data) {
		t.Fatalf("the next fetch: %d bytes, %v", len(got), err)
	}

	// A fetch that returned while its chunks fill its queue.
	pi.mu.Lock()
	c := pi.conns[mac.id.ID]
	pi.mu.Unlock()
	f := &fetching{ch: make(chan chunk, 1), missing: make(chan struct{}), done: make(chan struct{})}
	sum := sha256.Sum256([]byte("late"))
	c.fetchMu.Lock()
	c.fetches[sum] = f
	c.fetchMu.Unlock()
	c.received(chunk{sum: sum, data: []byte("a")})
	close(f.done)
	returned := make(chan struct{})
	go func() {
		c.received(chunk{sum: sum, data: []byte("b")})
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("a chunk for a fetch that returned blocked the reader")
	}
	c.fetchMu.Lock()
	delete(c.fetches, sum)
	c.fetchMu.Unlock()
}
