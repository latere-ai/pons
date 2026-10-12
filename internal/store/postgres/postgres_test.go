// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package postgres_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"latere.ai/x/pons/internal/store"
	"latere.ai/x/pons/internal/store/postgres"
	"latere.ai/x/pons/internal/store/postgres/migrations"
	"latere.ai/x/pons/internal/store/postgres/pgtest"
	"latere.ai/x/pons/internal/store/storetest"
)

func TestMain(m *testing.M) { pgtest.Main(m) }

// Postgres passes the one suite on a direct connection.
func TestPostgresStore(t *testing.T) {
	storetest.Run(t, func(t *testing.T, now func() time.Time) store.Store {
		return pgtest.Open(t, false, postgres.Options{Now: now})
	})
}

// Postgres passes the one suite through a transaction-mode pooler, which
// keeps no session state between two statements.
func TestPostgresStoreThroughAPooler(t *testing.T) {
	storetest.Run(t, func(t *testing.T, now func() time.Time) store.Store {
		return pgtest.Open(t, true, postgres.Options{Now: now, MaxConns: 4})
	})
}

// A schema ahead of the binary and a dirty migration each stop the start,
// naming the version; Open refuses a schema at another version than its
// own, and the errors name no part of the URL.
func TestSchemaGuards(t *testing.T) {
	ctx := context.Background()
	highest, err := migrations.Highest()
	if err != nil {
		t.Fatal(err)
	}

	direct, _ := pgtest.Database(t)
	if err := postgres.Migrate(ctx, direct); err != nil {
		t.Fatalf("migrating twice: %v", err)
	}
	if err := pgtest.Exec(ctx, direct, `UPDATE schema_migrations SET version = $1`, int64(highest+1)); err != nil {
		t.Fatal(err)
	}
	err = postgres.Migrate(ctx, direct)
	if err == nil || !strings.Contains(err.Error(), "version 2") || !strings.Contains(err.Error(), "carries 1") {
		t.Fatalf("a schema ahead of the binary: %v", err)
	}
	if _, err := postgres.Open(ctx, direct, postgres.Options{}); err == nil || !strings.Contains(err.Error(), "version 2") {
		t.Fatalf("opening a schema ahead of the binary: %v", err)
	}

	dirty, _ := pgtest.Database(t)
	if err := pgtest.Exec(ctx, dirty, `UPDATE schema_migrations SET dirty = true`); err != nil {
		t.Fatal(err)
	}
	err = postgres.Migrate(ctx, dirty)
	if err == nil || !strings.Contains(err.Error(), "dirty at version 1") {
		t.Fatalf("a dirty migration: %v", err)
	}
	if _, err := postgres.Open(ctx, dirty, postgres.Options{}); err == nil || !strings.Contains(err.Error(), "dirty: true") {
		t.Fatalf("opening a dirty schema: %v", err)
	}

	fresh := pgtest.OnDatabase(t, direct, "postgres")
	if _, err := postgres.Open(ctx, fresh, postgres.Options{}); err == nil || !strings.Contains(err.Error(), "version 0") {
		t.Fatalf("opening a database with no schema: %v", err)
	}

	const secret = "s3cret-password"
	unreachable := "postgres://pons:" + secret + "@127.0.0.1:1/pons?sslmode=disable&connect_timeout=2"
	short, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for name, err := range map[string]error{
		"migrate": postgres.Migrate(short, unreachable),
		"open":    func() error { _, err := postgres.Open(short, unreachable, postgres.Options{}); return err }(),
	} {
		if !errors.Is(err, postgres.ErrUnreachable) || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "127.0.0.1") {
			t.Errorf("%s of an unreachable database: %v", name, err)
		}
	}
	for _, bad := range []string{"mysql://pons@db.example.com/pons", "://"} {
		if err := postgres.Migrate(ctx, bad); err == nil || strings.Contains(err.Error(), "db.example.com") {
			t.Errorf("migrating %q: %v", bad, err)
		}
		if _, err := postgres.Open(ctx, bad, postgres.Options{}); err == nil {
			t.Errorf("opening %q was accepted", bad)
		}
	}
}

// The readiness probe answers while the database does, and fails once it
// is closed.
func TestReady(t *testing.T) {
	ctx := context.Background()
	direct, _ := pgtest.Database(t)
	s, err := postgres.Open(ctx, direct+"&pool_max_conns=2", postgres.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Ready(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Ready(ctx); !errors.Is(err, postgres.ErrUnreachable) {
		t.Fatalf("a closed store is ready: %v", err)
	}
}

// The highest migration is read from the files' numbers.
func TestHighestOf(t *testing.T) {
	got, err := migrations.HighestOf(fstest.MapFS{
		"000001_a.up.sql": {}, "000003_b.up.sql": {}, "README": {},
	})
	if err != nil || got != 3 {
		t.Fatalf("HighestOf = %d, %v", got, err)
	}
	if _, err := migrations.HighestOf(fstest.MapFS{"x_a.up.sql": {}}); err == nil {
		t.Fatal("a migration that does not start with a number was read")
	}
	if _, err := migrations.HighestOf(fstest.MapFS{}); err == nil {
		t.Fatal("no migration at all was read")
	}
}
