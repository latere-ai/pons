// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"time"

	"latere.ai/x/pkg/authz"
	"latere.ai/x/pkg/health"
	"latere.ai/x/pkg/otel"

	"latere.ai/x/pons/catalog"
	"latere.ai/x/pons/internal/access"
	"latere.ai/x/pons/internal/config"
	"latere.ai/x/pons/internal/httpapi"
	"latere.ai/x/pons/internal/store"
	"latere.ai/x/pons/internal/store/memory"
	"latere.ai/x/pons/internal/store/postgres"
	"latere.ai/x/pons/internal/version"
)

// The times of the server.
const (
	// grace is how long open requests are given to finish after a signal.
	grace = 25 * time.Second
	// openTimeout bounds reaching the database at start.
	openTimeout = 30 * time.Second
	// warmTimeout bounds reading the issuers' keys and asking the probe
	// at start.
	warmTimeout = 10 * time.Second
	// sweepEvery is how often a replica sweeps old records and keys.
	sweepEvery = 10 * time.Minute
	// rewrapBatch is how many rows one rewrap transaction holds.
	rewrapBatch = 100
)

// Hooks are what a test hands the server that no variable sets.
type Hooks struct {
	// Ready, when it is not nil, is sent the address the server listens on
	// once it does.
	Ready chan<- string
	// Roots are the authorities the operator client verifies against. Nil
	// is the process's roots; a test passes the stubs'.
	Roots *x509.CertPool
}

// server is everything one process serves with.
type server struct {
	settings config.Settings
	store    store.Store
	sealer   *store.KeySealer
	catalog  catalog.Catalog
	access   *access.Access
	log      *slog.Logger
}

// open reads what serve and check read alike: the store, the sealing keys,
// the catalog and who decides. It logs the store first, then who decides,
// whether anything can be sealed, and the dial switch and the proxy.
func open(ctx context.Context, s config.Settings, log *slog.Logger, hooks Hooks) (*server, error) {
	srv := &server{settings: s, log: log}
	st, err := openStore(ctx, s)
	if err != nil {
		return nil, err
	}
	srv.store = st
	if s.Durable() {
		log.InfoContext(ctx, "store: postgres")
	} else {
		log.WarnContext(ctx, "store: memory, and nothing it keeps survives the process")
	}
	fail := func(err error) (*server, error) { return nil, errors.Join(err, st.Close()) }

	keys := make([][32]byte, len(s.SealingKeys))
	for i, k := range s.SealingKeys {
		keys[i] = k
	}
	if srv.sealer, err = store.NewSealer(keys...); err != nil {
		return fail(fmt.Errorf("PONS_SEALING_KEYS: %w", err))
	}
	if s.CatalogFile != "" {
		if srv.catalog, err = catalog.Load(s.CatalogFile, catalog.Options{LookupEnv: config.LookupEnv}); err != nil {
			return fail(err)
		}
	}
	if srv.access, err = access.New(s, access.Options{Roots: hooks.Roots}); err != nil {
		return fail(err)
	}
	log.InfoContext(ctx, "decides: "+srv.access.Mode)
	if len(s.SealingKeys) == 0 {
		log.WarnContext(ctx, "sealing: no key, so nothing can be sealed or opened; a request that would answers sealing_unavailable")
	}
	if s.CatalogFile == "" {
		log.InfoContext(ctx, "catalog: empty, since PONS_CATALOG_FILE is not set")
	}
	if s.DialAllowPrivate {
		log.WarnContext(ctx, "dial: private addresses allowed, since PONS_DIAL_ALLOW_PRIVATE is set; never in production")
	}
	if s.OutboundProxy != nil {
		log.InfoContext(ctx, "dial: requests leave through the proxy PONS_OUTBOUND_PROXY names", "host", s.OutboundProxy.Host)
	}
	return srv, nil
}

// openStore is the memory store without a database, and Postgres with
// one: the schema applied over the direct URL, and the pool opened over
// the serving one. A database that does not answer stops the start.
func openStore(ctx context.Context, s config.Settings) (store.Store, error) {
	if !s.Durable() {
		return memory.New(memory.Options{}), nil
	}
	ctx, cancel := context.WithTimeout(ctx, openTimeout)
	defer cancel()
	if err := postgres.Migrate(ctx, s.DatabaseURL); err != nil {
		return nil, fmt.Errorf("PONS_DATABASE_URL: %w", err)
	}
	st, err := postgres.Open(ctx, s.ServingURL(), postgres.Options{})
	if err != nil {
		return nil, fmt.Errorf("PONS_DATABASE_POOL_URL or PONS_DATABASE_URL: %w", err)
	}
	return st, nil
}

// identity reads the issuers' keys and asks the authorizer the probe. An
// issuer or an authorizer that does not answer is named and the server
// starts, since every request then fails closed; an authorizer that allows
// the probe does not read the request, and the server does not start.
func (srv *server) identity(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, warmTimeout)
	defer cancel()
	if err := srv.access.Warm(ctx); err != nil {
		srv.log.WarnContext(ctx, "an issuer did not answer; its keys are read when its first token arrives", "error", err.Error())
	}
	err := srv.access.Check(ctx)
	switch {
	case errors.Is(err, authz.ErrProbeAllowed):
		return errors.New("PONS_AUTHORIZER_URL: the authorizer allowed the probe, so it does not read the request")
	case err != nil:
		srv.log.WarnContext(ctx, "the authorizer did not answer the probe; every request fails closed until it does", "error", err.Error())
	}
	return nil
}

// api is the HTTP surface of the server.
func (srv *server) api() *httpapi.Server {
	s := srv.settings
	sealing := func(context.Context) error {
		if len(s.SealingKeys) == 0 {
			return errors.New("no sealing key")
		}
		return nil
	}
	return &httpapi.Server{
		Store: srv.store, Sealer: srv.sealer, Catalog: srv.catalog,
		Auth: srv.access.Authenticator, Authz: srv.access.Authorizer,
		PublicURL: s.PublicURL, BasePath: s.BasePath,
		MaxConnectionsPerOwner: s.MaxConnectionsPerOwner, CreatesPerMinute: s.CreatesPerMinute,
		Ready: []health.Check{
			{Name: "sealing", Run: sealing},
			// A catalog that does not read stops the start, so a server
			// that serves has read it.
			{Name: "catalog", Run: func(context.Context) error { return nil }},
		},
		AllowPrivate: s.DialAllowPrivate,
		Log:          srv.log,
	}
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

	srv, err := open(ctx, s, log, hooks)
	if err != nil {
		return err
	}
	defer func() {
		if err := srv.store.Close(); err != nil {
			log.WarnContext(ctx, "the store did not close", "error", err.Error())
		}
	}()
	if err := srv.identity(ctx); err != nil {
		return err
	}

	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", s.Addr)
	if err != nil {
		return fmt.Errorf("PONS_ADDR: %w", err)
	}
	httpSrv := &http.Server{Handler: srv.api().Handler(), ReadHeaderTimeout: 10 * time.Second}
	failed := make(chan error, 1)
	go func() { failed <- httpSrv.Serve(ln) }()
	log.InfoContext(ctx, "listening", "host", ln.Addr().String())

	work, stopWork := context.WithCancel(context.WithoutCancel(ctx))
	defer stopWork()
	go srv.rewrap(work)
	go srv.sweep(work)
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
	err = httpSrv.Shutdown(stop)
	if errors.Is(err, context.DeadlineExceeded) {
		// What is left is a stream that did not end within the grace.
		err = httpSrv.Close()
	}
	if served := <-failed; served != nil && !errors.Is(served, http.ErrServerClosed) {
		return errors.Join(err, served)
	}
	return err
}

// rewrap moves every sealed value under the first key, in the background,
// once at start: a rotation is prepending a key and restarting.
func (srv *server) rewrap(ctx context.Context) {
	if len(srv.settings.SealingKeys) < 2 {
		return
	}
	n, err := store.Rewrap(ctx, srv.store, srv.sealer, rewrapBatch)
	if err != nil && ctx.Err() == nil {
		srv.log.WarnContext(ctx, "a rewrap stopped; the next start takes it up", "count", n, "error", err.Error())
		return
	}
	srv.log.InfoContext(ctx, "rewrapped under the first sealing key", "count", n)
}

// sweep removes old records and idempotency keys every sweepEvery, on every
// replica.
func (srv *server) sweep(ctx context.Context) {
	tick := time.NewTicker(sweepEvery)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			calls, keys, err := store.Sweep(ctx, srv.store, time.Now(), srv.settings.RecordsRetention)
			if err != nil && ctx.Err() == nil {
				srv.log.WarnContext(ctx, "a sweep failed; the next tick tries again", "table", "calls", "error", err.Error())
				continue
			}
			srv.log.InfoContext(ctx, "swept", "count", calls+keys)
		}
	}
}

// check reads the configuration, the catalog and the store as serve would,
// serves nothing, and prints one line per finding. It fails on everything
// serve refuses at start, and on a sealed value no listed key wraps.
func check(ctx context.Context, getenv func(string) string, out io.Writer, hooks Hooks) error {
	s, err := config.FromEnv(getenv)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv, err := open(ctx, s, log, hooks)
	if err != nil {
		return err
	}
	defer func() {
		if err := srv.store.Close(); err != nil {
			fmt.Fprintln(out, "store: did not close:", err)
		}
	}()
	if err := srv.identity(ctx); err != nil {
		return err
	}
	var lines []string
	say := func(format string, args ...any) { lines = append(lines, fmt.Sprintf(format, args...)) }
	say("configuration: ok")
	say("catalog: %d connectors", len(srv.catalog.Connectors))
	say("decides: %s", srv.access.Mode)
	if s.DialAllowPrivate {
		say("dial: private addresses allowed (PONS_DIAL_ALLOW_PRIVATE)")
	}
	if s.OutboundProxy != nil {
		say("dial: requests leave through a proxy (PONS_OUTBOUND_PROXY)")
	}
	var unwrapped error
	if s.Durable() {
		remaining, err := store.Remaining(ctx, srv.store, srv.sealer)
		if err != nil {
			return fmt.Errorf("store: counting the sealed values: %w", err)
		}
		tables := make([]string, 0, len(remaining))
		for t := range remaining {
			tables = append(tables, t)
		}
		sort.Strings(tables)
		for _, t := range tables {
			c := remaining[t]
			say("sealing: %s: %d not under the first key, %d under no listed key", t, c.NotFirst, c.NoKey)
			if c.NoKey > 0 {
				unwrapped = errors.New("sealing: a sealed value is under no listed key; list the key it was sealed under")
			}
		}
	}
	for _, line := range lines {
		if _, err := fmt.Fprintln(out, line); err != nil {
			return err
		}
	}
	return unwrapped
}
