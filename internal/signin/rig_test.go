// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package signin

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"latere.ai/x/pkg/authz"

	"latere.ai/x/pons/catalog"
	"latere.ai/x/pons/internal/dial"
	"latere.ai/x/pons/internal/store"
	"latere.ai/x/pons/internal/store/memory"
	"latere.ai/x/pons/test/stubs"
)

const issuer = "https://issuer.example.com"

func subject(sub string) string { return authz.Subject(issuer, sub) }

// clientSecret is the secret of the catalog's client at the stub.
const clientSecret = "the-catalog-client-secret"

// clock is a clock a test moves.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// logs is a log sink a server and a test share.
type logs struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logs) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logs) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// rig is one sign-in over the memory store against the stub authorization
// server and the stub API.
type rig struct {
	t      *testing.T
	s      *Signin
	st     *memory.Store
	sealer store.Sealer
	auth   *stubs.AuthServer
	api    *stubs.API
	clock  *clock
	conns  map[string]Connector
	logs   *logs
}

// newRig starts the stubs and a sign-in, with the catalog entries the doc
// adds to a GitHub-shaped one, "code", whose endpoints are the stub's.
func newRig(t *testing.T, extra string, opts ...stubs.AuthOption) *rig {
	t.Helper()
	r := &rig{t: t, st: memory.New(memory.Options{}), auth: stubs.NewAuthServer(t, opts...), api: stubs.NewAPI(t),
		clock: &clock{t: time.Now()}, logs: &logs{}}
	r.auth.AddClient("pons-client", clientSecret)
	sealer, err := store.NewSealer([32]byte{3})
	if err != nil {
		t.Fatal(err)
	}
	r.sealer = sealer
	doc := `connectors:
  - name: code
    title: Code
    kind: http
    url: ` + r.api.URL() + `
    hosts: ["api.example.com"]
    auth:
      type: oauth
      discovery: none
      authorize_url: ` + r.auth.AuthorizeURL() + `
      token_url: ` + r.auth.TokenURL() + `
      revoke_url: ` + r.auth.RevokeURL() + `
      client: {id: pons-client, secret: {env: CLIENT_SECRET}}
      account: {url: "` + r.api.URL() + `/user", field: login}
    links: {manage: "https://code.example.com/apps/pons/installations/new"}
  - name: minted
    title: Minted
    kind: http
    url: ` + r.api.URL() + `
    auth: {type: client_credentials, token_url: "` + r.auth.TokenURL() + `", scopes: [read], audience: "https://api.example.com"}
` + extra
	lookup := func(name string) (string, bool) { return clientSecret, name == "CLIENT_SECRET" }
	cat, err := catalog.Parse([]byte(doc), catalog.Options{LookupEnv: lookup})
	if err != nil {
		t.Fatal(err)
	}
	r.conns = map[string]Connector{}
	for _, c := range cat.Connectors {
		r.conns[c.Name] = Connector{Connector: c, Ref: c.Name}
	}
	r.s = &Signin{
		Store: r.st, Sealer: r.sealer,
		Dial: dial.New(dial.Options{Resolver: stubs.Resolver(), Roots: stubs.Roots(), Permit: stubs.Permit(r.auth.Port(), r.api.Port())}),
		Resolve: func(_ context.Context, ref string) (Connector, error) {
			if c, ok := r.conns[ref]; ok {
				return c, nil
			}
			return Connector{}, ErrNoConnector
		},
		LookupEnv: lookup, PublicURL: "https://pons.example.com", BasePath: "/v1", ClientName: "Pons",
		ReturnURLs: []string{"https://app.example.com/back", "https://app.example.com/settings/"},
		Log:        slog.New(slog.NewJSONHandler(r.logs, nil)), Now: r.clock.now,
	}
	return r
}

// connection stores a connection, and a credential when secrets are given.
func (r *rig) connection(owner, connector string, state store.State, secrets *store.Secrets, meta store.Meta) store.Connection {
	r.t.Helper()
	conn := r.conns[connector]
	c := store.Connection{
		ID: "con_" + strings.ToLower(owner) + strings.Repeat("0", 22-len(owner)) + connector[:2], Owner: subject(owner),
		Name: connector, Connector: connector, Kind: conn.Kind, Auth: conn.Auth.Type, State: state, CreatedBy: subject(owner),
	}
	if err := r.st.Connections().Create(context.Background(), c, 0); err != nil {
		r.t.Fatal(err)
	}
	if secrets != nil {
		sealed, err := r.s.seal(c, conn, *secrets, meta)
		if err != nil {
			r.t.Fatal(err)
		}
		if _, err := r.st.Credentials().Put(context.Background(), c.ID, sealed); err != nil {
			r.t.Fatal(err)
		}
	}
	return c
}

// signedIn is a connection whose tokens the stub issued, its access token
// ending at expires.
func (r *rig) signedIn(owner string, state store.State, expires time.Time) Opened {
	r.t.Helper()
	access, refresh := r.auth.Grant("pons-client", "read")
	c := r.connection(owner, "code", state, &store.Secrets{AccessToken: access, RefreshToken: refresh}, store.Meta{
		TokenType: "Bearer", AccessExpiresAt: expires, TokenEndpoint: r.auth.TokenURL(), RevocationEndpoint: r.auth.RevokeURL(), ClientID: "pons-client",
	})
	return r.open(c)
}

// open opens a connection's stored credential.
func (r *rig) open(c store.Connection) Opened {
	r.t.Helper()
	o, err := Open(context.Background(), r.st, r.sealer, c, r.conns[c.Connector])
	if err != nil {
		r.t.Fatal(err)
	}
	return o
}

// tokenRequests counts the stub's requests to its token endpoint of one
// grant type.
func (r *rig) tokenRequests(grant string) int {
	n := 0
	for _, q := range r.auth.Requests() {
		if q.Path == "/token" && q.Form.Get("grant_type") == grant {
			n++
		}
	}
	return n
}

func (r *rig) state(c store.Connection) store.Connection {
	r.t.Helper()
	got, err := r.st.Connections().Get(context.Background(), c.ID)
	if err != nil {
		r.t.Fatal(err)
	}
	return got
}
