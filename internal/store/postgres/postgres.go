// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package postgres is the durable store of specs/005-store-and-sealing.md,
// selected by PONS_DATABASE_URL.
//
// A transaction-mode pooler may sit in front of the database, so nothing
// here depends on session state: no LISTEN or NOTIFY, no session advisory
// lock, no named prepared statement. The pool describes the unnamed
// statement and caches the description in the client, unless the URL names
// another query mode, and every JSON value is bound as text. The one
// advisory lock is the transaction-level one of a capped create.
//
// Two connections are named apart. Migrate takes the direct URL, because
// the migrator holds a session lock across its statements. Open takes the
// serving URL, which may be a pooler's.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5" // the pgx5:// driver pgxmigrate selects by scheme
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"latere.ai/x/pkg/pgxmigrate"

	"latere.ai/x/pons/internal/store"
	"latere.ai/x/pons/internal/store/postgres/migrations"
)

// Pool bounds.
const (
	// DefaultMaxConns is the pool a zero Options.MaxConns takes; a URL
	// that names pool_max_conns keeps its own.
	DefaultMaxConns = 8
	// readyTimeout bounds the readiness probe's statement.
	readyTimeout = time.Second

	maxConnLifetime   = 30 * time.Minute
	maxConnIdleTime   = time.Minute
	healthCheckPeriod = time.Minute
)

// ErrUnreachable is a database that did not answer. It names no part of
// the URL, which holds a password.
var ErrUnreachable = errors.New("store: the database does not answer")

// Options opens the store.
type Options struct {
	// MaxConns bounds the pool when the URL names no pool_max_conns. Zero
	// takes DefaultMaxConns.
	MaxConns int32
	// Now stands in for the database's now(), for a test that moves the
	// store's clock. Nil in a running server: every statement then reads
	// the database's own clock, so no replica's clock is compared with
	// another's.
	Now func() time.Time
}

// Store is the store over one connection pool.
type Store struct {
	pool *pgxpool.Pool
	now  func() time.Time
}

var _ store.Store = (*Store)(nil)

const versionSQL = `SELECT version, dirty FROM schema_migrations`

// Migrate applies the pending migrations over the direct connection. It
// refuses a schema this binary does not know: one a failed migration left
// dirty, and one a newer binary wrote.
func Migrate(ctx context.Context, directURL string) error {
	dsn, err := migrationURL(directURL)
	if err != nil {
		return err
	}
	highest, err := migrations.Highest()
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	conn, err := pgx.Connect(ctx, directURL)
	if err != nil {
		return ErrUnreachable
	}
	version, dirty, err := schemaVersion(ctx, conn)
	closeErr := conn.Close(ctx)
	switch {
	case err != nil:
		return err
	case closeErr != nil:
		return fmt.Errorf("store: closing the migration check's connection: %w", closeErr)
	case dirty:
		return fmt.Errorf("store: the schema is dirty at version %d: a migration failed halfway, and an operator repairs it before this process starts", version)
	case version > highest:
		return fmt.Errorf("store: the schema is at version %d and this binary carries %d: run the version that wrote the schema", version, highest)
	}
	if err := pgxmigrate.Up(dsn, migrations.FS, "."); err != nil {
		return fmt.Errorf("store: applying the schema: %w", err)
	}
	return nil
}

// migrationURL is the direct URL under the scheme golang-migrate's pgx/v5
// driver registers. The errors name no part of the URL.
func migrationURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", errors.New("store: the direct database URL is not a URL")
	}
	if u.Scheme != "postgres" && u.Scheme != "postgresql" {
		return "", errors.New("store: the direct database URL does not have the scheme postgres")
	}
	u.Scheme = "pgx5"
	return u.String(), nil
}

// versioner reads the schema version: a connection or a pool.
type versioner interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// schemaVersion reads the version golang-migrate recorded. A database with
// no schema at all is at version 0.
func schemaVersion(ctx context.Context, q versioner) (version uint, dirty bool, err error) {
	var v int64
	err = q.QueryRow(ctx, versionSQL).Scan(&v, &dirty)
	var pgErr *pgconn.PgError
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return 0, false, nil
	case errors.As(err, &pgErr) && pgErr.Code == "42P01":
		return 0, false, nil // undefined table: a fresh database
	case err != nil:
		return 0, false, ErrUnreachable
	}
	return uint(v), dirty, nil
}

// Open connects over the serving URL and checks that the schema is the one
// this binary carries. It does not migrate: Migrate does, over the direct
// connection, before the first Open.
func Open(ctx context.Context, servingURL string, o Options) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(servingURL)
	if err != nil {
		// The parse error is not kept: it may quote the URL.
		return nil, errors.New("store: the serving database URL is not a Postgres URL")
	}
	// The driver's default prepares a named statement per query and keeps
	// it for the life of the connection, which a transaction-mode pooler
	// hands to another client between two statements. Describing the
	// unnamed statement keeps nothing on the server. A URL that names
	// another mode keeps it.
	if cfg.ConnConfig.DefaultQueryExecMode == pgx.QueryExecModeCacheStatement {
		cfg.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeCacheDescribe
	}
	if !strings.Contains(servingURL, "pool_max_conns") {
		cfg.MaxConns = DefaultMaxConns
		if o.MaxConns > 0 {
			cfg.MaxConns = o.MaxConns
		}
	}
	cfg.MinConns = 0
	cfg.MaxConnLifetime = maxConnLifetime
	cfg.MaxConnIdleTime = maxConnIdleTime
	cfg.HealthCheckPeriod = healthCheckPeriod
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, ErrUnreachable
	}
	highest, err := migrations.Highest()
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: %w", err)
	}
	version, dirty, err := schemaVersion(ctx, pool)
	switch {
	case err != nil:
		pool.Close()
		return nil, err
	case dirty || version != highest:
		pool.Close()
		return nil, fmt.Errorf("store: the schema is at version %d (dirty: %t) and this binary needs %d: migrate over the direct connection first", version, dirty, highest)
	}
	return &Store{pool: pool, now: o.Now}, nil
}

// Close closes the pool.
func (s *Store) Close() error {
	s.pool.Close()
	return nil
}

// Ready is SELECT 1 within a second.
func (s *Store) Ready(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, readyTimeout)
	defer cancel()
	var one int
	if err := s.pool.QueryRow(ctx, `SELECT 1`).Scan(&one); err != nil {
		return ErrUnreachable
	}
	return nil
}

// Tx runs fn in one transaction.
func (s *Store) Tx(ctx context.Context, fn func(store.Tx) error) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		return fn(&view{s: s, q: tx, tx: tx})
	})
}

// base is the tables outside a transaction.
func (s *Store) base() *view { return &view{s: s, q: s.pool} }

func (s *Store) Connectors() store.Connectors       { return s.base().Connectors() }
func (s *Store) Connections() store.Connections     { return s.base().Connections() }
func (s *Store) Credentials() store.Credentials     { return s.base().Credentials() }
func (s *Store) Flows() store.Flows                 { return s.base().Flows() }
func (s *Store) Registrations() store.Registrations { return s.base().Registrations() }
func (s *Store) Calls() store.Calls                 { return s.base().Calls() }
func (s *Store) Idempotency() store.Idempotency     { return s.base().Idempotency() }
func (s *Store) Rotation() store.Rotation           { return s.base().Rotation() }

// querier is a pool or a transaction.
type querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// view is the tables over a pool or inside one transaction.
type view struct {
	s  *Store
	q  querier
	tx pgx.Tx // nil outside a transaction
}

// atomic runs fn in the view's transaction, or in one of its own outside
// one, for the writes that are more than one statement.
func (v *view) atomic(ctx context.Context, fn func(q querier) error) error {
	if v.tx != nil {
		return fn(v.tx)
	}
	return pgx.BeginFunc(ctx, v.s.pool, func(tx pgx.Tx) error { return fn(tx) })
}

// at is a test's clock as a statement's parameter, and NULL in a running
// server, where the statement reads the database's now().
func (v *view) at() *time.Time {
	if v.s.now == nil {
		return nil
	}
	t := v.s.now()
	return &t
}

func (v *view) Connectors() store.Connectors       { return connectors{v} }
func (v *view) Connections() store.Connections     { return connections{v} }
func (v *view) Credentials() store.Credentials     { return credentials{v} }
func (v *view) Flows() store.Flows                 { return flows{v} }
func (v *view) Registrations() store.Registrations { return registrations{v} }
func (v *view) Calls() store.Calls                 { return calls{v} }
func (v *view) Idempotency() store.Idempotency     { return idempotency{v} }
func (v *view) Rotation() store.Rotation           { return rotation{v} }

// The SQLSTATE codes the store reads.
const (
	uniqueViolation     = "23505"
	foreignKeyViolation = "23503"
)

// violation is the constraint a statement broke, when it broke one of
// code's kind.
func violation(err error, code string) (string, bool) {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == code {
		return pgErr.ConstraintName, true
	}
	return "", false
}

// one maps a missing row to store.ErrNotFound.
func one(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return store.ErrNotFound
	}
	return err
}

// nullable is a byte slice as a parameter: NULL when empty.
func nullable(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
}

// nullTime is a time as a parameter: NULL when zero.
func nullTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}

// nullInt is a count as a parameter: NULL when zero.
func nullInt(n int64) any {
	if n == 0 {
		return nil
	}
	return n
}

// timeOf reads a nullable time, zero for NULL.
func timeOf(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return t.UTC()
}

// page cuts rows read one past the limit to a page and its next cursor.
func page[T any](rows []T, idOf func(T) string, size int) ([]T, string) {
	if len(rows) > size {
		return rows[:size], idOf(rows[size-1])
	}
	return rows, ""
}
