// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package main

import (
	"os"
	"path/filepath"
	"sync"
	"time"
)

// maxLog is the size at which a log file is moved to its ".1" name and
// started again, so a log keeps at most twice this much.
const maxLog = 1 << 20

// A logFile is a log on Windows, where no system service keeps the output
// of the service and the agent. Every line starts with the time.
type logFile struct {
	mu   sync.Mutex
	path string
	f    *os.File
	size int64
	now  func() time.Time
}

func openLog(path string) (*logFile, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	l := &logFile{path: path, now: time.Now}
	if err := l.open(); err != nil {
		return nil, err
	}
	return l, nil
}

func (l *logFile) open() error {
	f, err := os.OpenFile(l.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	l.f, l.size = f, st.Size()
	return nil
}

// Write writes one or more lines, each after the time.
func (l *logFile) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.size >= maxLog {
		l.f.Close()
		os.Remove(l.path + ".1")
		os.Rename(l.path, l.path+".1")
		if err := l.open(); err != nil {
			return 0, err
		}
	}
	stamp := l.now().Format("2006-01-02 15:04:05 ")
	var b []byte
	start := true
	for _, c := range p {
		if start {
			b = append(b, stamp...)
			start = false
		}
		b = append(b, c)
		if c == '\n' {
			start = true
		}
	}
	n, err := l.f.Write(b)
	l.size += int64(n)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (l *logFile) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.f.Close()
}
