// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"latere.ai/x/pkg/health"
	"latere.ai/x/pkg/otel"

	"latere.ai/x/pons/internal/config"
	"latere.ai/x/pons/internal/version"
)

// grace is how long open requests are given to finish after a signal.
const grace = 25 * time.Second

// Hooks are what a test hands the server that no variable sets.
type Hooks struct {
	// Ready, when it is not nil, is sent the address the server listens on
	// once it does.
	Ready chan<- string
}

// serve reads the configuration and serves until ctx ends.
func serve(ctx context.Context, getenv func(string) string, logs io.Writer, hooks Hooks) error {
	s, err := config.FromEnv(getenv)
	if err != nil {
		return err
	}
	log, shutdown, err := otel.Bootstrap(ctx, otel.Config{
		ServiceName: "ponsd", Version: version.Version,
		Stdout: slog.NewJSONHandler(logs, nil),
	})
	if err != nil {
		// The logger works either way; the error is the export path's.
		log.WarnContext(ctx, "telemetry export is not set up", "error", err.Error())
	}
	defer func() {
		if err := shutdown(context.WithoutCancel(ctx)); err != nil {
			log.WarnContext(ctx, "telemetry did not flush", "error", err.Error())
		}
	}()

	mux := http.NewServeMux()
	probes := health.Handler(health.Options{
		Version: version.Version, Commit: version.Commit, BuildTime: version.Date,
	})
	for _, p := range []string{"GET /livez", "GET /readyz", "GET /version"} {
		mux.Handle(p, probes)
	}

	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", s.Addr)
	if err != nil {
		return fmt.Errorf("PONS_ADDR: %w", err)
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	failed := make(chan error, 1)
	go func() { failed <- srv.Serve(ln) }()
	log.InfoContext(ctx, "listening", "route", s.BasePath, "version", version.Version)
	if hooks.Ready != nil {
		hooks.Ready <- ln.Addr().String()
	}

	select {
	case err := <-failed:
		return err
	case <-ctx.Done():
	}
	stop, cancel := context.WithTimeout(context.WithoutCancel(ctx), grace)
	defer cancel()
	err = srv.Shutdown(stop)
	if errors.Is(err, context.DeadlineExceeded) {
		// What is left is a stream that did not end within the grace.
		err = srv.Close()
	}
	if served := <-failed; served != nil && !errors.Is(served, http.ErrServerClosed) {
		return errors.Join(err, served)
	}
	return err
}

// check reads the configuration as serve would and prints one line per
// finding. It fails on everything serve refuses at start.
func check(_ context.Context, getenv func(string) string, out io.Writer, _ Hooks) error {
	if _, err := config.FromEnv(getenv); err != nil {
		return err
	}
	_, err := fmt.Fprintln(out, "configuration: ok")
	return err
}
