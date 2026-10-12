// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package pgtest starts the Postgres the store's suites run against, with a
// PgBouncer in transaction mode beside it, through Testcontainers. Only
// test binaries import it.
//
// The server and its pooler are started once per test binary, on first
// use, and Main removes what the binary started, so a failed run leaves no
// container and no network behind. Every case gets a database of its own.
// Where no container runtime answers, the start fails and the test fails
// with the reason: a suite that skipped is never a green gate.
package pgtest

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"

	"latere.ai/x/pons/internal/store/postgres"
)

const (
	postgresImage = "postgres:16-alpine" // the oldest server the design supports
	poolerImage   = "edoburu/pgbouncer:v1.24.1-p1"

	dbUser     = "pons"
	dbPassword = "pons"
	// dbAlias is the name the pooler reaches the server by on their network.
	dbAlias = "pons-postgres"
	// adminDB is the server's maintenance database. Every case gets a
	// database of its own beside it.
	adminDB = "pons_admin"

	// poolSize is the pool of the pooler every suite shares.
	poolSize = 8
)

// Server is the database server a suite runs against.
type Server struct {
	// Direct is the URL of the server's maintenance database, and Pooler
	// the same server reached through PgBouncer in transaction mode with
	// prepared statements turned off, the strictest pooler a deployment may
	// put in front.
	Direct string
	Pooler string
}

var (
	mu         sync.Mutex
	containers []testcontainers.Container
	shared     *testcontainers.DockerNetwork

	once      sync.Once
	server    Server
	serverErr error
)

// keep records a container for Stop. A container that failed to start is
// still kept when the library returned one: it may hold a name or a port.
func keep(c testcontainers.Container) {
	if c == nil {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	containers = append(containers, c)
}

// Start returns the server of this test binary, starting it and its pooler
// on first use.
func Start() (Server, error) {
	once.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		server, serverErr = start(ctx)
	})
	return server, serverErr
}

func start(ctx context.Context) (Server, error) {
	reaper("/var/run/docker.sock")
	nw, err := network.New(ctx)
	if err != nil {
		return Server{}, fmt.Errorf("pgtest: creating the network: %w", err)
	}
	mu.Lock()
	shared = nw
	mu.Unlock()
	pg, err := tcpostgres.Run(ctx, postgresImage,
		tcpostgres.WithDatabase(adminDB),
		tcpostgres.WithUsername(dbUser),
		tcpostgres.WithPassword(dbPassword),
		network.WithNetwork([]string{dbAlias}, nw),
		// The suites are not a durability test of Postgres: they trade the
		// server's own crash safety for speed. The connection bound holds
		// the pools of every case that runs at once.
		testcontainers.WithCmd("postgres", "-c", "fsync=off", "-c", "synchronous_commit=off",
			"-c", "full_page_writes=off", "-c", "max_connections=300"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).WithStartupTimeout(3*time.Minute)),
	)
	keep(pg)
	if err != nil {
		return Server{}, fmt.Errorf("pgtest: starting Postgres: %w", err)
	}
	direct, err := pg.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		return Server{}, fmt.Errorf("pgtest: the server's address: %w", err)
	}
	pooler, err := startPooler(ctx, nw)
	if err != nil {
		return Server{}, err
	}
	return Server{Direct: direct, Pooler: pooler}, nil
}

func startPooler(ctx context.Context, nw *testcontainers.DockerNetwork) (string, error) {
	// Any database name is passed through to the server.
	pooler, err := testcontainers.Run(ctx, poolerImage,
		network.WithNetwork(nil, nw),
		testcontainers.WithExposedPorts("5432/tcp"),
		testcontainers.WithEnv(map[string]string{
			"DB_HOST": dbAlias, "DB_USER": dbUser, "DB_PASSWORD": dbPassword,
			"AUTH_TYPE": "scram-sha-256", "POOL_MODE": "transaction",
			"MAX_PREPARED_STATEMENTS": "0", "DEFAULT_POOL_SIZE": strconv.Itoa(poolSize), "MAX_CLIENT_CONN": "1000",
		}),
		testcontainers.WithWaitStrategy(wait.ForListeningPort("5432/tcp").WithStartupTimeout(2*time.Minute)),
	)
	keep(pooler)
	if err != nil {
		return "", fmt.Errorf("pgtest: starting the pooler: %w", err)
	}
	host, err := pooler.Host(ctx)
	if err != nil {
		return "", fmt.Errorf("pgtest: the pooler's host: %w", err)
	}
	port, err := pooler.MappedPort(ctx, "5432/tcp")
	if err != nil {
		return "", fmt.Errorf("pgtest: the pooler's port: %w", err)
	}
	return (&url.URL{
		Scheme: "postgres", User: url.UserPassword(dbUser, dbPassword),
		Host: net.JoinHostPort(host, port.Port()), Path: "/" + adminDB, RawQuery: "sslmode=disable",
	}).String(), nil
}

// Stop removes every container and the network this binary started.
func Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	mu.Lock()
	defer mu.Unlock()
	var errs []error
	for _, c := range containers {
		if err := c.Terminate(ctx); err != nil {
			errs = append(errs, fmt.Errorf("pgtest: removing a test container: %w", err))
		}
	}
	containers = nil
	if shared != nil {
		if err := shared.Remove(ctx); err != nil {
			errs = append(errs, fmt.Errorf("pgtest: removing the test network: %w", err))
		}
		shared = nil
	}
	return errors.Join(errs...)
}

// Main runs a test binary's tests and then removes what they started. It is
// the body of a TestMain.
func Main(m *testing.M) {
	code := m.Run()
	if err := Stop(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		if code == 0 {
			code = 1
		}
	}
	os.Exit(code)
}

// Database is an empty database of its own, migrated, for one case. It
// answers the direct URL and the URL through the pooler, both pointed at
// that database, and drops it when the case ends.
func Database(t testing.TB) (direct, pooled string) {
	t.Helper()
	srv, err := Start()
	if err != nil {
		t.Fatalf("no Postgres for the store's suite, and a skipped suite is no pass: %v", err)
	}
	name := "pons_" + strings.ToLower(rand.Text()[:12])
	if err := run(context.Background(), srv.Direct, "create database "+name); err != nil {
		t.Fatalf("creating the database: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := run(ctx, srv.Direct, "drop database if exists "+name+" with (force)"); err != nil {
			t.Errorf("dropping the database: %v", err)
		}
	})
	direct, pooled = OnDatabase(t, srv.Direct, name), OnDatabase(t, srv.Pooler, name)
	if err := postgres.Migrate(context.Background(), direct); err != nil {
		t.Fatalf("migrating the database: %v", err)
	}
	return direct, pooled
}

// Open is a store over a fresh database of its own, reached directly or
// through the pooler, closed when the case ends.
func Open(t testing.TB, throughPooler bool, o postgres.Options) *postgres.Store {
	t.Helper()
	direct, pooled := Database(t)
	at := direct
	if throughPooler {
		at = pooled
	}
	s, err := postgres.Open(context.Background(), at, o)
	if err != nil {
		t.Fatalf("opening the store: %v", err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("closing the store: %v", err)
		}
	})
	return s
}

// Exec runs one statement on the database a URL points at.
func Exec(ctx context.Context, dsn, statement string, args ...any) error {
	return run(ctx, dsn, statement, args...)
}

func run(ctx context.Context, dsn, statement string, args ...any) error {
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return err
	}
	_, err = conn.Exec(ctx, statement, args...)
	return errors.Join(err, conn.Close(ctx))
}

// OnDatabase is a server URL pointed at another database.
func OnDatabase(t testing.TB, server, name string) string {
	t.Helper()
	u, err := url.Parse(server)
	if err != nil {
		t.Fatalf("the server URL: %v", err)
	}
	u.Path = "/" + name
	return u.String()
}

// reaper turns Testcontainers' reaper off where the socket that answers is
// a Podman machine's under Docker's name: the reaper there asks for a
// bridge network the machine does not have, and Stop removes what this
// binary started anyway.
func reaper(socket string) {
	resolved, err := filepath.EvalSymlinks(socket)
	if err != nil || !strings.Contains(resolved, "podman") {
		return
	}
	if err := os.Setenv("TESTCONTAINERS_RYUK_DISABLED", "true"); err != nil {
		fmt.Fprintf(os.Stderr, "pgtest: turning the reaper off: %v\n", err)
	}
}
