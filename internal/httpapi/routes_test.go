// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"latere.ai/x/pkg/health"

	"latere.ai/x/pons/internal/access"
	"latere.ai/x/pons/internal/store"
	"latere.ai/x/pons/internal/store/postgres"
	"latere.ai/x/pons/internal/store/postgres/pgtest"
)

func TestMain(m *testing.M) { pgtest.Main(m) }

// fixture makes, as alice, an added connector and a connection to it, and
// answers their ids.
func fixture(t testing.TB, h *harness) (ctr, con string) {
	t.Helper()
	a := h.do(http.MethodPost, "/v1/connectors", "alice", map[string]any{
		"name": "wiki", "title": "Wiki", "kind": "mcp", "url": "https://wiki.example.com/mcp", "auth": map[string]any{"type": "token"},
	})
	if a.status != http.StatusCreated {
		t.Fatalf("add: %d %s", a.status, a.body)
	}
	ctr = idOf(t, a)
	c := h.connect("alice", "search", "", "the-key-of-alice")
	if c.status != http.StatusCreated {
		t.Fatalf("connect: %d %s", c.status, c.body)
	}
	return ctr, idOf(t, c)
}

// request is one valid request of a route, as alice, about the fixture.
func request(rt Route, ctr, con string) (path string, body any) {
	path = "/v1" + strings.NewReplacer("{ref}", "search", "{id}", con).Replace(rt.Path)
	switch {
	case rt.Method == http.MethodDelete && strings.HasPrefix(rt.Path, "/connectors"):
		path = "/v1/connectors/" + ctr
	case rt.Method == http.MethodPost && rt.Path == "/connectors":
		body = map[string]any{"name": "other", "title": "Other", "kind": "mcp", "url": "https://other.example.com/mcp", "auth": map[string]any{"type": "none"}}
	case rt.Method == http.MethodPost && rt.Path == "/connections":
		body = map[string]any{"connector": "weather", "name": "weather-two"}
	case rt.Method == http.MethodPatch:
		body = map[string]any{"name": "renamed"}
	case rt.Method == http.MethodPut:
		body = map[string]any{"credential": map[string]any{"value": "a-new-key-of-alice"}}
	}
	return path, body
}

// Every route asks its action, once, before it acts.
func TestEveryRouteAsksItsAction(t *testing.T) {
	for _, rt := range Routes() {
		if rt.Path == "/openapi.yaml" {
			continue
		}
		t.Run(rt.Method+" "+rt.Path, func(t *testing.T) {
			h := newHarness(t)
			ctr, con := fixture(t, h)
			before := len(h.authz.questions())
			path, body := request(rt, ctr, con)
			a := h.do(rt.Method, path, "alice", body)
			if a.status >= 300 {
				t.Fatalf("%d %s", a.status, a.body)
			}
			asked := h.authz.questions()[before:]
			row, _ := access.RouteOf(rt.Method, rt.Path)
			if len(asked) != 1 || asked[0].Action != row.Action {
				t.Fatalf("asked %+v, want one %s", asked, row.Action)
			}
		})
	}
}

// state is what a store holds that a route could change.
func state(t testing.TB, st store.Store, con string) string {
	t.Helper()
	ctx := context.Background()
	owners := []string{subject("alice")}
	conns, _, err := st.Connections().List(ctx, store.Filter{Owners: owners}, store.Page{Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	ctrs, _, err := st.Connectors().List(ctx, owners, store.Page{Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	_, version, err := st.Credentials().Get(ctx, con)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, c := range conns {
		names = append(names, c.ID+":"+c.Name+":"+string(c.State))
	}
	return fmt.Sprint(names, len(ctrs), version)
}

// A deny and an outage are answered with nothing done, over both stores.
func TestADenyAndAnOutageAnswerBeforeAnythingIsDone(t *testing.T) {
	stores := map[string]func(t *testing.T) store.Store{
		"memory":   func(t *testing.T) store.Store { return newHarness(t).store },
		"postgres": func(t *testing.T) store.Store { return pgtest.Open(t, false, postgresOptions()) },
	}
	for name, open := range stores {
		t.Run(name, func(t *testing.T) {
			h := newHarnessOn(t, open(t))
			ctr, con := fixture(t, h)
			for _, rt := range Routes() {
				if rt.Path == "/openapi.yaml" || rt.Method == http.MethodGet {
					continue
				}
				path, body := request(rt, ctr, con)
				for _, outcome := range []string{"deny", "outage"} {
					before := state(t, h.store, con)
					h.authz.set(func(access.Caller, access.Question) (access.Decision, error) {
						if outcome == "outage" {
							return access.Decision{}, fmt.Errorf("%w: the endpoint hung", access.ErrUnavailable)
						}
						return access.Decision{Reason: "no"}, nil
					})
					a := h.do(rt.Method, path, "alice", body)
					h.authz.set(nil)
					want := map[string]int{"deny": http.StatusForbidden, "outage": http.StatusServiceUnavailable}[outcome]
					if outcome == "deny" && !strings.HasSuffix(rt.Path, "s") {
						want = http.StatusNotFound
					}
					if a.status != want {
						t.Errorf("%s %s under a %s: %d %s", rt.Method, rt.Path, outcome, a.status, a.body)
					}
					if after := state(t, h.store, con); after != before {
						t.Errorf("%s %s under a %s changed the store: %s to %s", rt.Method, rt.Path, outcome, before, after)
					}
				}
			}
		})
	}
}

// A connector read through the API carries no client, no reference and no
// endpoint.
func TestConnectorShowsNoSecretReference(t *testing.T) {
	h := newHarness(t)
	for _, path := range []string{"/v1/connectors", "/v1/connectors/code", "/v1/connectors/tracker", "/v1/connectors/warehouse"} {
		a := h.do(http.MethodGet, path, "alice", nil)
		if a.status != http.StatusOK {
			t.Fatalf("%s: %d", path, a.status)
		}
		for _, leak := range []string{`"client"`, "client_id", "secret", "CODE_CLIENT_SECRET", "TRACKER_CLIENT_SECRET", "Iv23example", "authorize_url", "token_url", "revoke_url", "issuer", "account", "login.example.com", "code.example.com/token", "audience"} {
			if strings.Contains(string(a.body), leak) {
				t.Errorf("%s shows %q: %s", path, leak, a.body)
			}
		}
	}
	a := h.do(http.MethodGet, "/v1/connectors/search", "alice", nil).json(t)
	if a["auth"].(map[string]any)["inject"].(map[string]any)["header"] != "X-Api-Key" {
		t.Fatalf("a token connector shows no inject: %v", a)
	}
}

// An added connector of kind http, on another port, with hosts, with a
// client or of type client_credentials is refused; one of type oauth needs
// the sign-in; and it is the owner's alone.
func TestAddedConnectorRules(t *testing.T) {
	h := newHarness(t)
	base := func(change func(map[string]any)) map[string]any {
		b := map[string]any{"name": "wiki", "title": "Wiki", "kind": "mcp", "url": "https://wiki.example.com/mcp", "auth": map[string]any{"type": "none"}}
		change(b)
		return b
	}
	cases := []struct {
		name        string
		change      func(map[string]any)
		code, field string
	}{
		{"kind http", func(b map[string]any) { b["kind"] = "http" }, CodeInvalidField, "kind"},
		{"another port", func(b map[string]any) { b["url"] = "https://wiki.example.com:8443/mcp" }, CodeInvalidField, "url"},
		{"an address", func(b map[string]any) { b["url"] = "https://10.0.0.1/mcp" }, CodeInvalidField, "url"},
		{"a private name", func(b map[string]any) { b["url"] = "https://wiki.internal/mcp" }, CodeInvalidField, "url"},
		{"http", func(b map[string]any) { b["url"] = "http://wiki.example.com/mcp" }, CodeInvalidField, "url"},
		{"hosts", func(b map[string]any) { b["hosts"] = []string{"wiki.example.com"} }, CodeUnknownField, "hosts"},
		{"a client", func(b map[string]any) {
			b["auth"] = map[string]any{"type": "oauth", "client": map[string]any{"id": "x"}}
		}, CodeUnknownField, "client"},
		{"client_credentials", func(b map[string]any) { b["auth"] = map[string]any{"type": "client_credentials"} }, CodeInvalidField, "auth.type"},
		{"no title", func(b map[string]any) { delete(b, "title") }, CodeMissingField, "title"},
		{"no auth", func(b map[string]any) { delete(b, "auth") }, CodeMissingField, "auth"},
		{"a bad name", func(b map[string]any) { b["name"] = "Wiki_1" }, CodeInvalidField, "name"},
	}
	for _, tc := range cases {
		a := h.do(http.MethodPost, "/v1/connectors", "alice", base(tc.change))
		if a.code() != tc.code || a.detail("field") != tc.field {
			t.Errorf("%s: %d %s", tc.name, a.status, a.body)
		}
	}
	a := h.do(http.MethodPost, "/v1/connectors", "alice", base(func(b map[string]any) { b["auth"] = map[string]any{"type": "oauth", "scopes": []string{"read"}} }))
	if a.status != http.StatusUnprocessableEntity || a.code() != CodeSignInUnsupported {
		t.Fatalf("oauth: %d %s", a.status, a.body)
	}
	ok := h.do(http.MethodPost, "/v1/connectors", "alice", base(func(map[string]any) {}))
	if ok.status != http.StatusCreated {
		t.Fatalf("a plain add: %d %s", ok.status, ok.body)
	}
	got := ok.json(t)
	if got["owner"] != subject("alice") || got["hosts"].([]any)[0] != "wiki.example.com" {
		t.Fatalf("the added connector %v", got)
	}
	id := got["id"].(string)
	if a := h.do(http.MethodGet, "/v1/connectors/"+id, "bob", nil); a.status != http.StatusNotFound || a.code() != CodeConnectorNotFound {
		t.Fatalf("bob reads alice's connector: %d", a.status)
	}
	if a := h.do(http.MethodGet, "/v1/connectors?kind=mcp", "bob", nil); strings.Contains(string(a.body), id) {
		t.Fatal("bob lists alice's connector")
	}
	if a := h.connect("bob", id, "", ""); a.status != http.StatusNotFound || a.code() != CodeConnectorNotFound {
		t.Fatalf("bob connects alice's connector: %d %s", a.status, a.body)
	}
	if a := h.do(http.MethodPost, "/v1/connectors", "alice", base(func(map[string]any) {})); a.code() != CodeNameTaken {
		t.Fatalf("a name twice: %d %s", a.status, a.body)
	}
}

// The probes answer without a token, outside the base path; /readyz names
// a check that failed and carries the dial line while the switch is set.
func TestProbes(t *testing.T) {
	h := newHarness(t)
	for _, p := range []string{"/livez", "/readyz", "/version"} {
		if a := h.do(http.MethodGet, p, "", nil); a.status != http.StatusOK {
			t.Errorf("%s: %d", p, a.status)
		}
	}
	if a := h.do(http.MethodGet, "/v1/livez", "", nil); a.status != http.StatusNotFound {
		t.Errorf("a probe under the base path: %d", a.status)
	}
	sealing := newHarness(t, func(s *Server) {
		s.Ready = append(s.Ready, readyCheck("sealing", errors.New("no sealing key")))
	})
	if a := sealing.do(http.MethodGet, "/readyz", "", nil); a.status != http.StatusServiceUnavailable || !strings.Contains(string(a.body), "sealing") {
		t.Errorf("no key: %d %s", a.status, a.body)
	}
	broken := newHarnessOn(t, failingStore{})
	a := broken.do(http.MethodGet, "/readyz", "", nil)
	if a.status != http.StatusServiceUnavailable || !strings.Contains(string(a.body), "store") || strings.Contains(string(a.body), "db.example.com") {
		t.Errorf("a store that does not answer: %d %s", a.status, a.body)
	}
	private := newHarness(t, func(s *Server) { s.AllowPrivate = true })
	if a := private.do(http.MethodGet, "/readyz", "", nil); a.status != http.StatusOK || string(a.body) != "ok\ndial: private addresses allowed\n" {
		t.Errorf("the switch: %d %q", a.status, a.body)
	}
	if a := private.do(http.MethodGet, "/livez", "", nil); strings.Contains(string(a.body), "dial") {
		t.Errorf("/livez carries the dial line")
	}
}

// A refused bearer is invalid_token with the verifier's word, and an error
// nobody classified is internal, logged and not answered.
func TestTokensAndUnclassifiedErrors(t *testing.T) {
	h := newHarness(t)
	a := h.do(http.MethodGet, "/v1/connections", "expired", nil)
	if a.status != http.StatusUnauthorized || a.code() != CodeInvalidToken || a.detail("reason") != "expired" || a.detail("retryable") != false {
		t.Fatalf("expired: %d %s", a.status, a.body)
	}
	if a := h.do(http.MethodGet, "/v1/connections", "unreachable", nil); a.detail("retryable") != true {
		t.Fatalf("an unreachable issuer: %s", a.body)
	}
	a = h.do(http.MethodGet, "/v1/connections", "broken", nil)
	if a.status != http.StatusInternalServerError || a.code() != CodeInternal || strings.Contains(string(a.body), "details") {
		t.Fatalf("broken: %d %s", a.status, a.body)
	}
	if !strings.Contains(h.logText(), "unexpected EOF") {
		t.Fatalf("the unclassified error was not logged: %s", h.logText())
	}
}

// An unclassified error whose text holds a URL with a query is logged with
// the query cut.
func TestAnErrorsURLLosesItsQuery(t *testing.T) {
	err := errors.New(`Get "https://api.example.com/v1/items?token=s3cr3t&x=1#frag": dial tcp: refused, and http://other.example.com/p?q=2`)
	got := logText(err)
	if strings.Contains(got, "s3cr3t") || strings.Contains(got, "q=2") || strings.Contains(got, "frag") {
		t.Fatalf("logged %q", got)
	}
	if !strings.Contains(got, "https://api.example.com/v1/items") || !strings.Contains(got, "http://other.example.com/p") {
		t.Fatalf("logged %q", got)
	}
	if logText(nil) != "" {
		t.Fatal("a nil error has text")
	}
	h := newHarness(t, func(s *Server) {
		s.Authz = deciderFunc(func(access.Caller, access.Question) (access.Decision, error) { return access.Decision{}, err })
	})
	if a := h.do(http.MethodGet, "/v1/connections", "alice", nil); a.status != http.StatusInternalServerError {
		t.Fatalf("%d", a.status)
	}
	if strings.Contains(h.logText(), "s3cr3t") || !strings.Contains(h.logText(), "api.example.com/v1/items") {
		t.Fatalf("the log: %s", h.logText())
	}
}

type deciderFunc func(access.Caller, access.Question) (access.Decision, error)

func (f deciderFunc) Authorize(_ context.Context, c access.Caller, q access.Question) (access.Decision, error) {
	return f(c, q)
}

func readyCheck(name string, err error) health.Check {
	return health.Check{Name: name, Run: func(context.Context) error { return err }}
}

// failingStore is a store whose database does not answer, with an error
// that names its address.
type failingStore struct{ store.Store }

func (failingStore) Ready(context.Context) error {
	return errors.New("dial tcp db.example.com:5432: connection refused")
}

func postgresOptions() postgres.Options { return postgres.Options{} }
