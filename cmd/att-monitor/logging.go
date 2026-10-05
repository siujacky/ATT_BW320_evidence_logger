package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
)

// The operational log is NOT evidence (the ledger is). It helps diagnose the monitor itself.
const (
	logMaxBytes = 10 << 20 // rotate at 10 MiB
	logKeep     = 5        // service.log.1 … service.log.5
)

// rotatingFile is a minimal size-based rotating writer.
type rotatingFile struct {
	mu   sync.Mutex
	path string
	f    *os.File
	size int64
}

func openRotating(path string) (*rotatingFile, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	return &rotatingFile{path: path, f: f, size: st.Size()}, nil
}

func (r *rotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return 0, errors.New("log closed")
	}
	if r.size+int64(len(p)) > logMaxBytes {
		r.rotate()
	}
	n, err := r.f.Write(p)
	r.size += int64(n)
	return n, err
}

func (r *rotatingFile) rotate() {
	r.f.Close()
	for i := logKeep - 1; i >= 1; i-- {
		_ = os.Rename(fmt.Sprintf("%s.%d", r.path, i), fmt.Sprintf("%s.%d", r.path, i+1))
	}
	if err := os.Rename(r.path, r.path+".1"); err != nil {
		// The current log could not be moved (e.g. a viewer holds it open without delete
		// sharing). Never truncate it: keep appending and try to rotate again later.
		f, oerr := os.OpenFile(r.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if oerr != nil {
			r.f = nil
			return
		}
		r.f = f
		r.size = logMaxBytes / 2 // retry after another half-size of output
		return
	}
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		r.f = nil
		return
	}
	r.f, r.size = f, 0
}

func (r *rotatingFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return nil
	}
	err := r.f.Close()
	r.f = nil
	return err
}

// fanout sends every record to all handlers that are enabled for its level.
type fanout []slog.Handler

func (f fanout) Enabled(ctx context.Context, l slog.Level) bool {
	for _, h := range f {
		if h.Enabled(ctx, l) {
			return true
		}
	}
	return false
}

func (f fanout) Handle(ctx context.Context, r slog.Record) error {
	var errs []error
	for _, h := range f {
		if h.Enabled(ctx, r.Level) {
			if err := h.Handle(ctx, r.Clone()); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

func (f fanout) WithAttrs(attrs []slog.Attr) slog.Handler {
	out := make(fanout, len(f))
	for i, h := range f {
		out[i] = h.WithAttrs(attrs)
	}
	return out
}

func (f fanout) WithGroup(name string) slog.Handler {
	out := make(fanout, len(f))
	for i, h := range f {
		out[i] = h.WithGroup(name)
	}
	return out
}

// newLogger builds the operational logger: logs/<mode>.log (rotating), plus stderr in console
// mode, plus an optional extra handler (the Windows Event Log in service mode).
func newLogger(logDir, mode string, console bool, extra slog.Handler) (*slog.Logger, func(), error) {
	name := "service.log"
	if mode != "service" {
		name = mode + ".log"
	}
	rf, err := openRotating(filepath.Join(logDir, name))
	if err != nil {
		// Logging must never prevent evidence collection: fall back to stderr only.
		h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})
		return slog.New(h), func() {}, nil
	}
	var w io.Writer = rf
	handlers := fanout{slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelInfo})}
	if console {
		handlers = append(handlers, slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}
	if extra != nil {
		handlers = append(handlers, extra)
	}
	return slog.New(handlers), func() { _ = rf.Close() }, nil
}
