// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package access_test

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"latere.ai/x/pkg/authz"
	"latere.ai/x/pkg/authz/conformance"
	"latere.ai/x/pkg/authz/server"
	"latere.ai/x/pkg/authz/stub"

	"latere.ai/x/pons/authorizer"
	"latere.ai/x/pons/internal/access"
	"latere.ai/x/pons/internal/config"
	"latere.ai/x/pons/test/stubs"
)

const (
	alice = "https://issuer.example.com|alice"
	bob   = "https://issuer.example.com|bob"
)

func caller(subject string) access.Caller {
	iss, sub, _ := authz.SplitSubject(subject)
	return access.Caller{Subject: subject, Issuer: iss, Sub: sub, Claims: map[string]any{"sub": sub, "tenant": "acme"}}
}

func reading(id, owner string) access.Question {
	return access.Question{Action: authorizer.ActionConnectionRead, Resource: access.Connection{
		ID: id, Owner: owner, Connector: "notion", Name: "notion", Kind: "mcp", Auth: "oauth",
	}.Resource(authorizer.ActionConnectionRead)}
}

func connect(owner string) access.Question {
	return access.Question{Action: authorizer.ActionConnectionCreate, Resource: access.Connection{
		Owner: owner, Connector: "notion", Name: "notion", Kind: "mcp", Auth: "oauth",
	}.Resource(authorizer.ActionConnectionCreate)}
}

// asking is the authorizer ponsd runs over an endpoint.
func asking(t *testing.T, a *stubs.Authorizer, now func() time.Time) access.Authorizer {
	t.Helper()
	c, err := access.NewClient(access.ClientOptions{URL: a.URL(), Token: config.NewSecret(a.Token()), HTTP: operator(t), Now: now})
	if err != nil {
		t.Fatal(err)
	}
	return access.NewAuthorizer(c)
}

// The authorizer receives the subject, every claim verbatim, the action and
// the resource, and the request's id, peer and user agent.
func TestTheEnvelopeCarriesTheCallerAndTheQuestion(t *testing.T) {
	s := stubs.NewAuthorizer(t)
	az := asking(t, s, nil)
	r := httptest.NewRequest(http.MethodGet, "/v1/connections/con_1", nil)
	r.Header.Set("X-Request-Id", "req-1")
	r.Header.Set("User-Agent", "client/1")
	q := access.Ask(r, authorizer.ActionConnectionRead, reading("con_1", alice).Resource)
	if _, err := az.Authorize(t.Context(), caller(alice), q); err != nil {
		t.Fatal(err)
	}
	got := s.Requests()
	if len(got) != 1 {
		t.Fatalf("%d requests", len(got))
	}
	req := got[0]
	if req.Subject != alice || req.Issuer != "https://issuer.example.com" || req.Sub != "alice" ||
		req.Claims["tenant"] != "acme" || req.Action != authorizer.ActionConnectionRead {
		t.Fatalf("envelope %+v", req)
	}
	if req.Resource.ID != "con_1" || req.Resource.String(authorizer.FieldOwner) != alice || req.Resource.String(authorizer.FieldAuth) != "oauth" {
		t.Fatalf("resource %+v", req.Resource)
	}
	if req.Request.ID != "req-1" || req.Request.UserAgent != "client/1" || req.Request.IP == "" {
		t.Fatalf("request %+v", req.Request)
	}
	// A member Pons does not know is left out, never sent empty.
	c := access.Connection{ID: "con_1", Owner: alice}.Resource(authorizer.ActionConnectionRead)
	if _, ok := c.Fields[authorizer.FieldConnector]; ok {
		t.Fatal("an unknown member is sent")
	}
	// A list names no object and no member.
	if l := access.List(authorizer.ActionConnectionList); l.ID != "" || len(l.Fields) != 0 || l.Kind != authorizer.KindConnection {
		t.Fatalf("list %+v", l)
	}
	// A connect sends no id.
	if res := connect(alice).Resource; res.ID != "" {
		t.Fatalf("connect %+v", res)
	}
	// A caller with no claims sends an empty object.
	if _, err := az.Authorize(t.Context(), access.Caller{Subject: alice}, reading("con_9", alice)); err != nil {
		t.Fatal(err)
	}
	if last := s.Requests()[1]; last.Claims == nil {
		t.Fatal("no claims object")
	}
	noPort := httptest.NewRequest(http.MethodGet, "/", nil)
	noPort.RemoteAddr = "192.0.2.1"
	if access.RequestInfo(noPort).IP != "192.0.2.1" {
		t.Fatal("an address with no port")
	}
}

// Every member of every question Pons builds reaches the authorizer, over
// the envelope's JSON, as it was built: a connection's kind and a
// connector's arrive under their own names, and no field is dropped.
func TestEveryMemberReachesTheAuthorizer(t *testing.T) {
	s := stubs.NewAuthorizer(t)
	az := asking(t, s, nil)
	conn := access.Connection{
		ID: "con_1", Owner: alice, Connector: "github", Name: "github", Kind: "http", Auth: "oauth", ConnectorOwner: bob,
		Method: http.MethodPost, Tool: "git-receive-pack", Effect: "write", Refs: []string{"refs/heads/agents/a"},
	}
	ctr := access.Connector{ID: "ctr_1", Owner: alice, Name: "wiki", Kind: "mcp", Host: "wiki.example.com"}
	for i, action := range authorizer.Actions() {
		var sent authz.Resource
		if authorizer.Kind(action) == authorizer.KindConnector {
			sent = ctr.Resource(action)
		} else {
			sent = conn.Resource(action)
		}
		if len(sent.Fields) != len(authorizer.Fields(action)) {
			t.Fatalf("%s builds %v, its fields are %v", action, sent.Fields, authorizer.Fields(action))
		}
		if _, err := az.Authorize(t.Context(), caller(alice), access.Question{Action: action, Resource: sent}); err != nil {
			t.Fatal(err)
		}
		got := s.Requests()[i].Resource
		want, arrived := asJSON(t, sent.Fields), asJSON(t, got.Fields)
		if got.Kind != sent.Kind || got.ID != sent.ID || arrived != want {
			t.Errorf("%s sent %s %q %s, and %s %q %s arrived", action, sent.Kind, sent.ID, want, got.Kind, got.ID, arrived)
		}
	}
	if got := s.Requests()[len(authorizer.Actions())-1].Resource; got.String(authorizer.FieldConnectionKind) != "http" {
		t.Fatalf("a use's connection kind arrived as %+v", got)
	}
}

// asJSON is a resource's fields as JSON, an empty object for none.
func asJSON(t *testing.T, fields map[string]any) string {
	t.Helper()
	if len(fields) == 0 {
		return "{}"
	}
	raw, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// The endpoint Pons asks answers the contract for every row of the
// vocabulary: the stub authorizer, as the test tiers start it.
// A list of connections or of connectors names the owner it asks for and
// no other member, and one that names none sends no field.
func TestAListNamesItsOwner(t *testing.T) {
	const alice = "https://issuer.example.com|alice"
	l := access.ListOf(authorizer.ActionConnectionList, alice)
	if l.ID != "" || l.Kind != authorizer.KindConnection || len(l.Fields) != 1 || l.String(authorizer.FieldOwner) != alice {
		t.Fatalf("a list naming an owner: %+v", l)
	}
	if l := access.ListOf(authorizer.ActionConnectionList, ""); len(l.Fields) != 0 {
		t.Fatalf("a list naming none sends %v", l.Fields)
	}
	if l := access.ListOf(authorizer.ActionConnectorList, alice); len(l.Fields) != 1 || l.Kind != authorizer.KindConnector || l.String(authorizer.FieldOwner) != alice {
		t.Fatalf("a list of connectors sends %+v", l)
	}
	if l := access.ListOf(authorizer.ActionConnectorList, ""); len(l.Fields) != 0 {
		t.Fatalf("a list of connectors naming none sends %v", l.Fields)
	}
}

func TestAuthorizerConformance(t *testing.T) {
	s := stubs.NewAuthorizer(t)
	conformance.Run(t, s.URL(), s.Token(),
		conformance.WithVocabulary(authorizer.Vocabulary()),
		conformance.WithPageActions(),
		conformance.WithSubjects(alice, bob),
		conformance.WithHTTPClient(operator(t)))
}

// The client holds an allow for its ttl, a deny briefly and an outage
// never.
func TestWhatTheClientRemembers(t *testing.T) {
	s := stubs.NewAuthorizer(t, stub.WithAllow())
	s.Allow(stub.Rule{Subject: alice, Action: authorizer.ActionConnectionRead, Resource: "con_1", TTL: 120})
	s.Deny(stub.Rule{Subject: bob, Action: authorizer.ActionConnectionRead, Resource: "con_1"}, "not_owner")
	clock := time.Now()
	az := asking(t, s, func() time.Time { return clock })
	ask := func(subject string) access.Decision {
		t.Helper()
		d, err := az.Authorize(t.Context(), caller(subject), reading("con_1", alice))
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	asked := func() int { return len(s.Requests()) }
	for range 3 {
		if !ask(alice).Allow {
			t.Fatal("denied")
		}
	}
	if asked() != 1 {
		t.Fatalf("an allow was asked %d times", asked())
	}
	clock = clock.Add(121 * time.Second)
	ask(alice)
	if asked() != 2 {
		t.Fatalf("an allow past its ttl was not asked again")
	}
	for range 3 {
		if d := ask(bob); d.Allow || d.Reason != "not_owner" {
			t.Fatalf("bob got %+v", d)
		}
	}
	if asked() != 3 {
		t.Fatalf("a deny was asked %d times", asked()-2)
	}
	clock = clock.Add(authz.DenyTTL + time.Second)
	ask(bob)
	if asked() != 4 {
		t.Fatal("a deny was held past its time")
	}
	s.Fail(http.StatusServiceUnavailable)
	for range 2 {
		if _, err := az.Authorize(t.Context(), caller(alice), reading("con_2", alice)); !errors.Is(err, access.ErrUnavailable) {
			t.Fatalf("an outage: %v", err)
		}
	}
	if asked() != 6 {
		t.Fatalf("an outage was held")
	}
}

// A create and a list name no id, so their answers are never held.
func TestACreateIsAlwaysAsked(t *testing.T) {
	s := stubs.NewAuthorizer(t)
	az := asking(t, s, nil)
	for range 3 {
		if _, err := az.Authorize(t.Context(), caller(alice), connect("")); err != nil {
			t.Fatal(err)
		}
		list := access.Question{Action: authorizer.ActionConnectionList, Resource: access.List(authorizer.ActionConnectionList)}
		if _, err := az.Authorize(t.Context(), caller(alice), list); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(s.Requests()); got != 6 {
		t.Fatalf("3 connects and 3 lists reached the endpoint %d times", got)
	}
}

// Another status, a body with no allow, a late answer, limits with an
// unknown key, a negative figure or an empty glob, and a filter with labels
// are each no decision.
func TestTheClientFailsClosed(t *testing.T) {
	limits := func(l map[string]any) func(*stubs.Authorizer) {
		return func(s *stubs.Authorizer) {
			s.Allow(stub.Rule{Action: authorizer.ActionConnectionCreate, Limits: l})
		}
	}
	outages := map[string]func(*stubs.Authorizer){
		"a 500":                func(s *stubs.Authorizer) { s.Fail(http.StatusInternalServerError) },
		"a 403":                func(s *stubs.Authorizer) { s.Fail(http.StatusForbidden) },
		"a body not JSON":      func(s *stubs.Authorizer) { s.FailBody(stub.BodyMalformed) },
		"a body with no allow": func(s *stubs.Authorizer) { s.FailBody(stub.BodyNoAllow) },
		"no answer":            func(s *stubs.Authorizer) { s.Hang() },
		"an unknown limit":     limits(map[string]any{"plan": "pro"}),
		"a negative figure":    limits(map[string]any{"max_connections": -1}),
		"an empty glob":        limits(map[string]any{"connectors": []any{""}}),
		"a filter with labels": func(s *stubs.Authorizer) {
			s.Allow(stub.Rule{Action: "*", Filter: &authz.Filter{Labels: map[string]string{"a": "b"}}})
		},
		"limits that are no map": limits(map[string]any{"tools": "get_*"}),
	}
	for name, outage := range outages {
		t.Run(name, func(t *testing.T) {
			s := stubs.NewAuthorizer(t)
			az := asking(t, s, nil)
			outage(s)
			ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
			defer cancel()
			q := connect("")
			if strings.Contains(name, "filter") {
				q = access.Question{Action: authorizer.ActionConnectionList, Resource: access.List(authorizer.ActionConnectionList)}
			}
			d, err := az.Authorize(ctx, caller(alice), q)
			if !errors.Is(err, access.ErrUnavailable) || d.Allow {
				t.Fatalf("got %+v, %v", d, err)
			}
			if strings.Contains(err.Error(), s.Token()) {
				t.Errorf("the error carries the bearer: %v", err)
			}
		})
	}
}

// resets fails the first round trips with a reset connection.
type resets struct {
	fail  int32
	calls atomic.Int32
	next  http.RoundTripper
}

func (r *resets) RoundTrip(req *http.Request) (*http.Response, error) {
	if r.calls.Add(1) <= r.fail {
		return nil, &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}
	}
	return r.next.RoundTrip(req)
}

// A call whose connection failed before any answer is tried once more.
func TestOneRetryOnAConnectionFailure(t *testing.T) {
	var served atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		served.Add(1)
		if err := json.NewEncoder(w).Encode(map[string]any{"allow": true}); err != nil {
			t.Error(err)
		}
	}))
	defer srv.Close()
	ask := func(rt *resets) error {
		c, err := access.NewClient(access.ClientOptions{URL: srv.URL, Token: config.NewSecret("t"), HTTP: &http.Client{Transport: rt}})
		if err != nil {
			t.Fatal(err)
		}
		_, err = access.NewAuthorizer(c).Authorize(t.Context(), caller(alice), reading("con_1", alice))
		return err
	}
	once := &resets{fail: 1, next: http.DefaultTransport}
	if err := ask(once); err != nil || once.calls.Load() != 2 || served.Load() != 1 {
		t.Fatalf("once: %v, %d calls, %d served", err, once.calls.Load(), served.Load())
	}
	always := &resets{fail: 1 << 30, next: http.DefaultTransport}
	if err := ask(always); !errors.Is(err, access.ErrUnavailable) || always.calls.Load() != 2 {
		t.Fatalf("always: %v, %d calls", err, always.calls.Load())
	}
}

// The limits of an allow are read for a connect, an add and a use, and the
// members each holds; any other allow's limits are not read.
func TestWhatAnAllowHolds(t *testing.T) {
	s := stubs.NewAuthorizer(t)
	every := map[string]any{
		"owner": "https://issuer.example.com|team", "max_connections": 3, "connectors": []any{"notion"},
		"read_only": true, "tools": []any{"get_*"}, "refs": []any{"refs/heads/agent/*"}, "calls_per_minute": 5,
		"requests": []any{"GET /**"}, "vouched": true,
	}
	s.Allow(stub.Rule{Action: "*", Limits: every})
	az := asking(t, s, nil)
	ask := func(q access.Question) authorizer.Limits {
		d, err := az.Authorize(t.Context(), caller(alice), q)
		if err != nil || !d.Allow {
			t.Fatalf("%s: %+v %v", q.Action, d, err)
		}
		return d.Limits
	}
	if l := ask(connect("")); l.Owner == "" || l.MaxConnections != 3 || len(l.Connectors) != 1 || l.ReadOnly || l.Tools != nil || l.Requests != nil || l.CallsPerMinute != 0 || l.Vouched {
		t.Errorf("a connect holds %+v", l)
	}
	add := access.Question{Action: authorizer.ActionConnectorCreate, Resource: access.Connector{Kind: "mcp", Host: "wiki.example.com"}.Resource(authorizer.ActionConnectorCreate)}
	if l := ask(add); l.Owner == "" || !l.Vouched || l.MaxConnections != 0 {
		t.Errorf("an add holds %+v", l)
	}
	use := access.Question{Action: authorizer.ActionConnectionUse, Resource: access.Connection{ID: "con_1", Owner: alice}.Resource(authorizer.ActionConnectionUse)}
	if l := ask(use); !l.ReadOnly || len(l.Tools) != 1 || len(l.Refs) != 1 || len(l.Requests) != 1 || l.CallsPerMinute != 5 || l.Owner != "" || l.Vouched {
		t.Errorf("a use holds %+v", l)
	}
	confirm := connect(alice)
	confirm.Resource.ID = "con_1"
	if l := ask(confirm); l.Owner != "" || l.MaxConnections != 0 {
		t.Errorf("a question about a stored connection moves it: %+v", l)
	}
	if l := ask(reading("con_1", alice)); l.Owner != "" || l.ReadOnly {
		t.Errorf("a read's limits were read: %+v", l)
	}
	// Unreadable limits on an action whose limits are not read are not
	// read either.
	s.SetRules(stub.Rule{Action: "*", Allow: true, Limits: map[string]any{"plan": "pro"}})
	if _, err := az.Authorize(t.Context(), caller(alice), reading("con_2", alice)); err != nil {
		t.Errorf("a read with limits nobody reads: %v", err)
	}
}

// A deny is a decision with the authorizer's reason, and a question outside
// the vocabulary is never sent.
func TestADenyIsADecision(t *testing.T) {
	s := stubs.NewAuthorizer(t, stub.WithAllow())
	s.Deny(stub.Rule{Action: authorizer.ActionConnectionRead}, "")
	az := asking(t, s, nil)
	d, err := az.Authorize(t.Context(), caller(alice), reading("con_1", alice))
	if err != nil || d.Allow || d.Reason == "" {
		t.Fatalf("%+v %v", d, err)
	}
	wrong := access.Question{Action: authorizer.ActionConnectionRead, Resource: access.Connector{Name: "x"}.Resource(authorizer.ActionConnectorRead)}
	if _, err := az.Authorize(t.Context(), caller(alice), wrong); err == nil {
		t.Fatal("a question about the wrong kind was asked")
	}
	if len(s.Requests()) != 1 {
		t.Fatal("a mistaken question reached the endpoint")
	}
}

// The owners a list shows: the filter's, the caller's own with no filter,
// narrowed and never widened by the request's owner.
func TestTheOwnersOfAList(t *testing.T) {
	c := caller(alice)
	if got := (access.Decision{Allow: true}).Owners(c, ""); !slices.Equal(got, []string{alice}) {
		t.Errorf("no filter: %v", got)
	}
	d := access.Decision{Allow: true, Filter: &authz.Filter{Owners: []string{alice, bob}}}
	if got := d.Owners(c, ""); !slices.Equal(got, []string{alice, bob}) {
		t.Errorf("a filter: %v", got)
	}
	if got := d.Owners(c, bob); !slices.Equal(got, []string{bob}) {
		t.Errorf("narrowed: %v", got)
	}
	if got := (access.Decision{Allow: true}).Owners(c, bob); len(got) != 0 {
		t.Errorf("widened: %v", got)
	}
}

// The table of routes has one row per route of the contract, each asking
// the action of spec 003.
func TestTheRowsAreTheSpecs(t *testing.T) {
	f, err := os.Open(filepath.Join("..", "..", "specs", "003-api.md"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			t.Error(err)
		}
	}()
	row := regexp.MustCompile("^\\| (.*?)`([A-Z]* ?/[^`]*)` \\| .* \\| (`[a-z.]+`|none) \\|$")
	type op struct{ method, path, action string }
	var spec []op
	scan := bufio.NewScanner(f)
	for scan.Scan() {
		m := row.FindStringSubmatch(scan.Text())
		if m == nil {
			continue
		}
		action := strings.Trim(m[3], "`")
		if action == "none" {
			action = ""
		}
		target := m[2]
		var methods []string
		path := target
		if method, rest, ok := strings.Cut(target, " "); ok {
			methods, path = []string{method}, rest
		}
		lead := m[1]
		switch {
		case strings.Contains(lead, "any method"):
			methods = []string{access.AnyMethod}
		case strings.Contains(lead, "GET"):
			methods = append(methods, http.MethodGet)
		}
		for _, method := range methods {
			spec = append(spec, op{method, path, action})
		}
	}
	if err := scan.Err(); err != nil {
		t.Fatal(err)
	}
	if len(spec) < 20 {
		t.Fatalf("read %d routes of spec 003", len(spec))
	}
	paths := map[string]bool{}
	for _, o := range spec {
		paths[o.path] = true
		rt, ok := access.RouteOf(o.method, o.path)
		if !ok || rt.Action != o.action {
			t.Errorf("%s %s: the table has %+v, the spec asks %q", o.method, o.path, rt, o.action)
		}
	}
	for _, rt := range access.Routes() {
		if !paths[rt.Path] {
			t.Errorf("the table has %s %s, which spec 003 does not", rt.Method, rt.Path)
		}
		if rt.Action != "" && !authorizer.Known(rt.Action) {
			t.Errorf("%s %s asks %q, no action", rt.Method, rt.Path, rt.Action)
		}
	}
	if _, ok := access.RouteOf(http.MethodPut, "/nothing"); ok {
		t.Error("a route the contract lacks is found")
	}
}

// The owner policy's rows, one question each.
func TestTheOwnerPolicy(t *testing.T) {
	stored := func(action, owner string) authz.Resource {
		return access.Connection{ID: "con_1", Owner: owner, Connector: "notion", Name: "n", Kind: "mcp", Auth: "token"}.Resource(action)
	}
	added := func(action, owner string) authz.Resource {
		return access.Connector{ID: "ctr_1", Owner: owner, Kind: "mcp"}.Resource(action)
	}
	cases := []struct {
		name, subject, action string
		res                   authz.Resource
		allow                 bool
		reason                string
		filter                bool
	}{
		{"the probe", alice, authorizer.ActionConnectionRead, authz.NewResource(authorizer.KindConnection, authz.ProbeID, nil), false, authz.ReasonProbe, false},
		{"nobody", "", authorizer.ActionConnectionList, access.List(authorizer.ActionConnectionList), false, authz.ReasonAnonymous, false},
		{"an unknown action", alice, "connection.steal", stored(authorizer.ActionConnectionRead, alice), false, access.ReasonUnknownAction, false},
		{"the wrong kind", alice, authorizer.ActionConnectionRead, added(authorizer.ActionConnectorRead, alice), false, access.ReasonUnknownAction, false},
		{"a catalog connector", alice, authorizer.ActionConnectorRead, access.Connector{Name: "notion", Kind: "mcp"}.Resource(authorizer.ActionConnectorRead), true, "", false},
		{"its added connector", alice, authorizer.ActionConnectorRead, added(authorizer.ActionConnectorRead, alice), true, "", false},
		{"another's added connector", alice, authorizer.ActionConnectorRead, added(authorizer.ActionConnectorRead, bob), false, authz.ReasonNotOwner, false},
		{"deletes its connector", alice, authorizer.ActionConnectorDelete, added(authorizer.ActionConnectorDelete, alice), true, "", false},
		{"edits its connector", alice, authorizer.ActionConnectorUpdate, added(authorizer.ActionConnectorUpdate, alice), true, "", false},
		{"edits another's connector", alice, authorizer.ActionConnectorUpdate, added(authorizer.ActionConnectorUpdate, bob), false, authz.ReasonNotOwner, false},
		{"may change its own connectors", alice, authorizer.ActionConnectorUpdate, access.Connector{Owner: alice}.Resource(authorizer.ActionConnectorUpdate), true, "", false},
		{"may change another's connectors", alice, authorizer.ActionConnectorUpdate, access.Connector{Owner: bob}.Resource(authorizer.ActionConnectorUpdate), false, authz.ReasonNotOwner, false},
		{"may change nobody's connectors", alice, authorizer.ActionConnectorUpdate, access.Connector{}.Resource(authorizer.ActionConnectorUpdate), false, authz.ReasonNotOwner, false},
		{"lists connectors", alice, authorizer.ActionConnectorList, access.List(authorizer.ActionConnectorList), true, "", true},
		{"lists connections", alice, authorizer.ActionConnectionList, access.List(authorizer.ActionConnectionList), true, "", true},
		{"reads its own", alice, authorizer.ActionConnectionRead, stored(authorizer.ActionConnectionRead, alice), true, "", false},
		{"uses its own", alice, authorizer.ActionConnectionUse, stored(authorizer.ActionConnectionUse, alice), true, "", false},
		{"renames another's", alice, authorizer.ActionConnectionUpdate, stored(authorizer.ActionConnectionUpdate, bob), false, authz.ReasonNotOwner, false},
		{"deletes another's", alice, authorizer.ActionConnectionDelete, stored(authorizer.ActionConnectionDelete, bob), false, authz.ReasonNotOwner, false},
		{"uses another's", alice, authorizer.ActionConnectionUse, stored(authorizer.ActionConnectionUse, bob), false, authz.ReasonNotOwner, false},
		{"confirms another's", alice, authorizer.ActionConnectionCreate, stored(authorizer.ActionConnectionCreate, bob), false, authz.ReasonNotOwner, false},
		{"a stored object with no owner", alice, authorizer.ActionConnectionRead, stored(authorizer.ActionConnectionRead, ""), false, authz.ReasonNotOwner, false},
		{"connects in its context", alice, authorizer.ActionConnectionCreate, connect("").Resource, true, "", false},
		{"connects in its name", alice, authorizer.ActionConnectionCreate, connect(alice).Resource, true, "", false},
		{"connects in another's name", alice, authorizer.ActionConnectionCreate, connect(bob).Resource, false, authz.ReasonNotOwner, false},
		{"adds in its context", alice, authorizer.ActionConnectorCreate, access.Connector{Kind: "mcp", Host: "x.example.com"}.Resource(authorizer.ActionConnectorCreate), true, "", false},
		{"adds in another's name", alice, authorizer.ActionConnectorCreate, access.Connector{Owner: bob, Kind: "mcp"}.Resource(authorizer.ActionConnectorCreate), false, authz.ReasonNotOwner, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := authz.Request{Subject: tc.subject, Action: tc.action, Resource: tc.res, Claims: map[string]any{}}
			d, err := access.OwnerPolicy{}.Authorize(t.Context(), req)
			if err != nil {
				t.Fatal(err)
			}
			if d.Allow != tc.allow || (!tc.allow && d.Reason != tc.reason) || (d.Filter != nil) != tc.filter {
				t.Fatalf("got %+v", d)
			}
			if tc.filter && !slices.Equal(d.Filter.Owners, []string{tc.subject}) {
				t.Fatalf("the filter is %+v", d.Filter)
			}
		})
	}
}

// The owner policy answers the contract's conformance suite through the
// shared scaffold.
func TestOwnerPolicyConformance(t *testing.T) {
	const token = "conformance-bearer"
	srv := httptest.NewServer(server.New(server.Options{Bearer: token, Vocabulary: authorizer.Vocabulary(), Decider: access.OwnerPolicy{}}))
	defer srv.Close()
	conformance.Run(t, srv.URL, token, conformance.WithVocabulary(authorizer.Vocabulary()), conformance.WithPageActions(), conformance.WithSubjects(alice, bob))
}

// The same suite against the policy's own answer, served with nothing but
// the contract's wire, so what is checked is the narrowing by the grants the
// policy does itself; a token whose grants cannot be read is denied.
func TestOwnerPolicyNarrowsByTheGrants(t *testing.T) {
	const token = "conformance-bearer"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var req authz.Request
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil || !authorizer.Known(req.Action) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		d, err := access.OwnerPolicy{}.Decide(r.Context(), req)
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		body := map[string]any{"allow": d.Allow}
		if d.Reason != "" {
			body["reason"] = d.Reason
		}
		if d.Filter != nil {
			body["filter"] = d.Filter
		}
		if err := json.NewEncoder(w).Encode(body); err != nil {
			t.Error(err)
		}
	}))
	defer srv.Close()
	conformance.Run(t, srv.URL, token, conformance.WithVocabulary(authorizer.Vocabulary()), conformance.WithPageActions(), conformance.WithSubjects(alice, bob))

	unreadable := authz.Request{Subject: alice, Action: authorizer.ActionConnectionList, Resource: access.List(authorizer.ActionConnectionList),
		Claims: map[string]any{"token_use": authz.TokenUsePAT, "authorization_details": "not grants"}}
	if d, err := (access.OwnerPolicy{}).Authorize(t.Context(), unreadable); err != nil || d.Allow || d.Reason != authz.ReasonGrant {
		t.Fatalf("unreadable grants: %+v %v", d, err)
	}
}

// The owner policy and the stub authorizer deny the probe id, and the check
// reports an endpoint that allows it.
func TestTheProbe(t *testing.T) {
	if err := access.Check(t.Context(), access.OwnerPolicy{}); err != nil {
		t.Fatalf("the owner policy: %v", err)
	}
	s := stubs.NewAuthorizer(t)
	c, err := access.NewClient(access.ClientOptions{URL: s.URL(), Token: config.NewSecret(s.Token()), HTTP: operator(t)})
	if err != nil {
		t.Fatal(err)
	}
	if err := access.Check(t.Context(), c); err != nil {
		t.Fatalf("the stub: %v", err)
	}
	open := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, err := io.WriteString(w, `{"allow": true}`); err != nil {
			t.Error(err)
		}
	}))
	defer open.Close()
	c, err = access.NewClient(access.ClientOptions{URL: open.URL, Token: config.NewSecret("t"), HTTP: http.DefaultClient})
	if err != nil {
		t.Fatal(err)
	}
	if err := access.Check(t.Context(), c); !errors.Is(err, authz.ErrProbeAllowed) {
		t.Fatalf("an endpoint that allows the probe: %v", err)
	}
}

// New builds the mode the settings name.
func TestNew(t *testing.T) {
	iss := stubs.NewIssuer(t)
	roots := stubs.Roots()
	s := config.Settings{OIDCIssuers: []string{iss.URL()}, OIDCAudiences: []string{audience}}
	a, err := access.New(s, access.Options{Roots: roots})
	if err != nil || a.Mode != access.ModeOwnerPolicy {
		t.Fatalf("%+v %v", a, err)
	}
	if err := a.Warm(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := a.Check(t.Context()); err != nil {
		t.Fatal(err)
	}
	c, err := a.Authenticator.Authenticate(bearing(t, iss.Token("alice", nil)))
	if err != nil || c.Sub != "alice" {
		t.Fatalf("%+v %v", c, err)
	}
	az := stubs.NewAuthorizer(t)
	s.AuthorizerURL, s.AuthorizerToken = az.URL(), config.NewSecret(az.Token())
	a, err = access.New(s, access.Options{Roots: roots})
	if err != nil || a.Mode != access.ModeAuthorizer {
		t.Fatalf("%+v %v", a, err)
	}
	if err := a.Check(t.Context()); err != nil {
		t.Fatal(err)
	}
	if d, err := a.Authorizer.Authorize(t.Context(), c, reading("con_1", c.Subject)); err != nil || !d.Allow {
		t.Fatalf("%+v %v", d, err)
	}
	if _, err := access.NewClient(access.ClientOptions{HTTP: http.DefaultClient}); err == nil {
		t.Fatal("a client with no URL was built")
	}
}

// An authorizer that predates connector.update, served from the shared
// scaffold with the vocabulary it knows, answers the new action with no
// decision, so an edit fails closed; and a decider that knows nothing of
// connector_owner answers a connect as it did, the new field unread.
func TestAnAuthorizerOfAnEarlierVocabularyFailsClosed(t *testing.T) {
	var earlier []authz.Action
	for _, a := range authorizer.Vocabulary().Actions {
		if a.Name != authorizer.ActionConnectorUpdate {
			earlier = append(earlier, a)
		}
	}
	vocab, err := authz.NewVocabulary(authorizer.Core, earlier...)
	if err != nil {
		t.Fatal(err)
	}
	const token = "earlier-bearer"
	srv := httptest.NewServer(server.New(server.Options{Bearer: token, Vocabulary: vocab, Decider: access.OwnerPolicy{}}))
	defer srv.Close()
	c, err := access.NewClient(access.ClientOptions{URL: srv.URL, Token: config.NewSecret(token), HTTP: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	az := access.NewAuthorizer(c)
	edit := access.Question{Action: authorizer.ActionConnectorUpdate, Resource: access.Connector{ID: "ctr_1", Owner: alice}.Resource(authorizer.ActionConnectorUpdate)}
	if d, err := az.Authorize(t.Context(), caller(alice), edit); !errors.Is(err, access.ErrUnavailable) || d.Allow {
		t.Fatalf("an edit asked of an earlier authorizer: %+v %v", d, err)
	}
	q := connect("")
	q.Resource = access.Connection{Connector: "ctr_1", Name: "wiki", Kind: "mcp", Auth: "token", ConnectorOwner: bob}.Resource(authorizer.ActionConnectionCreate)
	if d, err := az.Authorize(t.Context(), caller(alice), q); err != nil || !d.Allow {
		t.Fatalf("a connect with connector_owner: %+v %v", d, err)
	}
	read := access.Question{Action: authorizer.ActionConnectorRead, Resource: access.Connector{ID: "ctr_1", Owner: bob, Kind: "mcp"}.Resource(authorizer.ActionConnectorRead)}
	if d, err := az.Authorize(t.Context(), caller(alice), read); err != nil || d.Allow {
		t.Fatalf("a read of another owner's connector, which gates the connect: %+v %v", d, err)
	}
}
