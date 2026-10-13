// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"

	"latere.ai/x/pkg/authz"
	"latere.ai/x/pkg/authz/stub"

	"latere.ai/x/pons/authorizer"
	"latere.ai/x/pons/test/stubs"
)

// withAuthorizer starts a stub authorizer and points the server at it.
func withAuthorizer(t *testing.T, over map[string]string, opts ...stub.Option) (*stubs.Authorizer, map[string]string) {
	t.Helper()
	az := stubs.NewAuthorizer(t, opts...)
	path := t.TempDir() + "/token"
	if err := writeFile(path, az.Token()); err != nil {
		t.Fatal(err)
	}
	if over == nil {
		over = map[string]string{}
	}
	over["PONS_AUTHORIZER_URL"] = az.URL()
	over["PONS_AUTHORIZER_TOKEN_FILE"] = path
	return az, over
}

// A connection made with a key answers connected, and the key is kept
// sealed; a key of kind http is probed and a client minted for first.
func TestCreateByKey(t *testing.T) {
	iss := stubs.NewIssuer(t)
	s := startStack(t, iss, nil)
	a := s.connect("alice", "search", "", map[string]any{"value": "a-key-of-alice-0001"})
	if a.status != http.StatusCreated {
		t.Fatalf("%d %s", a.status, a.body)
	}
	c := a.json(t)
	if c["state"] != "connected" || c["auth"] != "token" || c["owner"] != iss.Subject("alice") ||
		c["created_by"] != iss.Subject("alice") || c["name"] != "search" {
		t.Fatalf("the connection %v", c)
	}
	if !strings.HasSuffix(c["address"].(string), "/v1/connections/"+c["id"].(string)+"/mcp") {
		t.Fatalf("the address %v", c["address"])
	}
	if strings.Contains(string(a.body), "a-key-of-alice-0001") || strings.Contains(s.dump(), "a-key-of-alice-0001") {
		t.Fatal("the key left its seal")
	}
	cred, version, err := s.store.Credentials().Get(context.Background(), c["id"].(string))
	if err != nil || version != 1 || cred.Kind != "token" || !strings.Contains(string(cred.Meta), "X-Api-Key") {
		t.Fatalf("the stored credential %+v %d %v", cred, version, err)
	}
	none := s.connect("alice", "weather", "", nil)
	if none.status != http.StatusCreated || none.json(t)["state"] != "connected" {
		t.Fatalf("a connector that takes nothing: %d %s", none.status, none.body)
	}
	if _, _, err := s.store.Credentials().Get(context.Background(), none.id(t)); err == nil {
		t.Fatal("a connection with no credential has one")
	}
	cc := s.connect("alice", "warehouse", "", map[string]any{"client_id": "wh-client", "client_secret": "a-secret-of-alice"})
	if cc.status != http.StatusCreated {
		t.Fatalf("client_credentials: %d %s", cc.status, cc.body)
	}
	// A key of kind http is probed once before it is kept, and a client is
	// minted for once; either refused stores nothing.
	up := upstreamOf(t)
	if a := s.connect("alice", "forge", "", map[string]any{"value": "a-forge-key-of-alice"}); a.status != http.StatusCreated {
		t.Fatalf("a probed key: %d %s", a.status, a.body)
	}
	if creds := up.api.Credentials(); len(creds) != 1 || creds[0] != "Bearer a-forge-key-of-alice" {
		t.Fatalf("the probe: %v", creds)
	}
	up.api.Refuse("Bearer a-refused-key-of-alice")
	if a := s.connect("alice", "forge", "forge-two", map[string]any{"value": "a-refused-key-of-alice"}); a.status != http.StatusUnprocessableEntity || a.code() != "credential_refused" {
		t.Fatalf("a refused key: %d %s", a.status, a.body)
	}
	up.auth.Set(func(sw *stubs.AuthSwitches) { sw.RefuseClient = true })
	if a := s.connect("alice", "warehouse", "warehouse-two", map[string]any{"client_id": "wh-client", "client_secret": "a-refused-secret"}); a.status != http.StatusUnprocessableEntity || a.code() != "credential_refused" {
		t.Fatalf("a refused client: %d %s", a.status, a.body)
	}
	up.auth.Set(func(sw *stubs.AuthSwitches) { sw.RefuseClient = false })
	if items := s.do(http.MethodGet, "/v1/connections", "alice", nil).json(t)["items"].([]any); len(items) != 4 {
		t.Fatalf("a refused credential stored a connection: %d", len(items))
	}
}

// A credential value shorter than 8 bytes is refused and nothing is
// stored.
func TestShortCredentialRefused(t *testing.T) {
	s := startStack(t, stubs.NewIssuer(t), nil)
	for _, cred := range []map[string]any{{"value": "1234567"}, {"value": ""}, {"client_id": "x", "client_secret": "short"}} {
		connector := "search"
		if _, ok := cred["client_id"]; ok {
			connector = "warehouse"
		}
		a := s.connect("alice", connector, "", cred)
		if a.status != http.StatusBadRequest {
			t.Errorf("%v: %d %s", cred, a.status, a.body)
		}
	}
	if a := s.do(http.MethodGet, "/v1/connections", "alice", nil); strings.Contains(string(a.body), `"id"`) {
		t.Fatalf("a refused credential stored a connection: %s", a.body)
	}
	good := s.connect("alice", "search", "", map[string]any{"value": "12345678"})
	if good.status != http.StatusCreated {
		t.Fatalf("8 bytes: %d", good.status)
	}
	if a := s.do(http.MethodPut, "/v1/connections/"+good.id(t)+"/credential", "alice", map[string]any{"credential": map[string]any{"value": "short"}}); a.status != http.StatusBadRequest {
		t.Fatalf("a short replacement: %d", a.status)
	}
}

// The same Idempotency-Key from one subject answers the first response and
// creates one object, of two requests at once too.
func TestIdempotentCreate(t *testing.T) {
	s := startStack(t, stubs.NewIssuer(t), nil)
	first := s.connect("alice", "search", "", map[string]any{"value": "a-key-of-alice-0002"}, "Idempotency-Key", "k1")
	again := s.connect("alice", "search", "", map[string]any{"value": "a-key-of-alice-0002"}, "Idempotency-Key", "k1")
	if first.status != http.StatusCreated || again.status != http.StatusCreated || first.id(t) != again.id(t) {
		t.Fatalf("a repeat: %d %s, %d %s", first.status, first.body, again.status, again.body)
	}
	var wg sync.WaitGroup
	ids := make([]string, 8)
	for i := range ids {
		wg.Go(func() {
			a := s.connect("alice", "weather", "", nil, "Idempotency-Key", "k2")
			if a.status == http.StatusCreated {
				ids[i] = a.id(t)
			}
		})
	}
	wg.Wait()
	for _, id := range ids {
		if id != ids[0] || id == "" {
			t.Fatalf("eight requests with one key answered %v", ids)
		}
	}
	bob := s.connect("bob", "weather", "", nil, "Idempotency-Key", "k2")
	if bob.status != http.StatusCreated || bob.id(t) == ids[0] {
		t.Fatalf("another subject's key is its own: %d %s", bob.status, bob.body)
	}
	list := s.do(http.MethodGet, "/v1/connections", "alice", nil).json(t)["items"].([]any)
	if len(list) != 2 {
		t.Fatalf("alice holds %d connections", len(list))
	}
	add := map[string]any{"name": "wiki", "title": "Wiki", "kind": "mcp", "url": "https://wiki.example.com/mcp", "auth": map[string]any{"type": "none"}}
	one := s.do(http.MethodPost, "/v1/connectors", "alice", add, "Idempotency-Key", "k3")
	two := s.do(http.MethodPost, "/v1/connectors", "alice", add, "Idempotency-Key", "k3")
	if one.status != http.StatusCreated || two.status != http.StatusCreated || one.id(t) != two.id(t) {
		t.Fatalf("an add twice: %s %s", one.body, two.body)
	}
	if a := s.connect("alice", "weather", "w3", nil, "Idempotency-Key", "k3"); a.status != http.StatusBadRequest {
		t.Fatalf("a key of another route: %d %s", a.status, a.body)
	}
}

// A read, a change and a delete of a connection the caller may not see
// answer 404 connection_not_found, byte for byte the answer of an id that
// names nothing; a create or a list the caller may not make answers 403.
func TestADenyDoesNotConfirmAnId(t *testing.T) {
	iss := stubs.NewIssuer(t)
	s := startStack(t, iss, nil)
	con := s.connect("alice", "search", "", map[string]any{"value": "a-key-of-alice-0003"}).id(t)
	missing := "con_01jb2m6x8q3v7k9n4w5t0zr1ya"
	requests := []struct {
		method, suffix string
		body           any
	}{
		{http.MethodGet, "", nil},
		{http.MethodPatch, "", map[string]any{"name": "taken"}},
		{http.MethodPut, "/credential", map[string]any{"credential": map[string]any{"value": "another-key-0003"}}},
		{http.MethodDelete, "", nil},
		{http.MethodGet, "/calls", nil},
	}
	for _, r := range requests {
		denied := s.do(r.method, "/v1/connections/"+con+r.suffix, "bob", r.body)
		absent := s.do(r.method, "/v1/connections/"+missing+r.suffix, "bob", r.body)
		if denied.status != http.StatusNotFound || !bytes.Equal(denied.body, absent.body) {
			t.Errorf("%s %s: denied %d %s, absent %d %s", r.method, r.suffix, denied.status, denied.body, absent.status, absent.body)
		}
	}
	if a := s.do(http.MethodGet, "/v1/connections/"+con, "alice", nil); a.status != http.StatusOK {
		t.Fatalf("a deny changed alice's connection: %d", a.status)
	}
	az, over := withAuthorizer(t, nil, stub.WithAllow())
	az.Deny(stub.Rule{Action: authorizer.ActionConnectionCreate}, "plan_ended")
	az.Deny(stub.Rule{Action: authorizer.ActionConnectionList}, "no_list")
	denying := startStack(t, iss, over)
	if a := denying.connect("alice", "weather", "", nil); a.status != http.StatusForbidden || a.code() != "forbidden" || a.detail("reason") != "plan_ended" {
		t.Fatalf("a denied create: %d %s", a.status, a.body)
	}
	if a := denying.do(http.MethodGet, "/v1/connections", "alice", nil); a.status != http.StatusForbidden {
		t.Fatalf("a denied list: %d %s", a.status, a.body)
	}
	if strings.Contains(denying.everything(), "plan_ended") && !strings.Contains(denying.everything(), `"reason":"plan_ended"`) {
		t.Fatal("the authorizer's reason reached the sentence a person reads")
	}
}

// A create is recorded under the owner its allow names, else the owner the
// request named, else the caller's subject.
func TestWhoseACreateIs(t *testing.T) {
	iss := stubs.NewIssuer(t)
	team := iss.Subject("team")
	az, over := withAuthorizer(t, nil)
	az.Allow(stub.Rule{Subject: iss.Subject("carol"), Action: authorizer.ActionConnectionCreate, Limits: map[string]any{"owner": team}})
	az.Allow(stub.Rule{Subject: iss.Subject("carol"), Action: authorizer.ActionConnectorCreate, Limits: map[string]any{"owner": team}})
	s := startStack(t, iss, over)
	if got := s.connect("carol", "weather", "", nil).json(t)["owner"]; got != team {
		t.Errorf("the allow's owner: %v", got)
	}
	body := map[string]any{"connector": "weather", "name": "w2", "owner": iss.Subject("org")}
	if got := s.do(http.MethodPost, "/v1/connections", "dave", body).json(t)["owner"]; got != iss.Subject("org") {
		t.Errorf("the request's owner: %v", got)
	}
	if got := s.connect("dave", "weather", "w3", nil).json(t)["owner"]; got != iss.Subject("dave") {
		t.Errorf("the caller: %v", got)
	}
	add := map[string]any{"name": "wiki", "title": "Wiki", "kind": "mcp", "url": "https://wiki.example.com/mcp", "auth": map[string]any{"type": "none"}}
	if got := s.do(http.MethodPost, "/v1/connectors", "carol", add).json(t)["owner"]; got != team {
		t.Errorf("an added connector's owner: %v", got)
	}
	// The question carried the owner the request named.
	var named bool
	for _, q := range az.Requests() {
		if q.Action == authorizer.ActionConnectionCreate && q.Resource.String("owner") == iss.Subject("org") {
			named = true
		}
	}
	if !named {
		t.Error("the authorizer was not told the owner the request named")
	}
}

// A replaced key does not move a connection to another owner, whatever
// owner its allow names.
func TestAStoredConnectionKeepsItsOwner(t *testing.T) {
	iss := stubs.NewIssuer(t)
	az, over := withAuthorizer(t, nil)
	az.Allow(stub.Rule{Action: authorizer.ActionConnectionCreate, Limits: map[string]any{"owner": iss.Subject("thief")}})
	s := startStack(t, iss, over)
	az.SetRules()
	a := s.connect("alice", "search", "", map[string]any{"value": "a-key-of-alice-0004"})
	id := a.id(t)
	az.Allow(stub.Rule{Action: authorizer.ActionConnectionCreate, Limits: map[string]any{"owner": iss.Subject("thief")}})
	if r := s.do(http.MethodPut, "/v1/connections/"+id+"/credential", "alice", map[string]any{"credential": map[string]any{"value": "a-key-of-alice-0005"}}); r.status != http.StatusNoContent {
		t.Fatalf("%d %s", r.status, r.body)
	}
	if got := s.do(http.MethodGet, "/v1/connections/"+id, "alice", nil).json(t)["owner"]; got != iss.Subject("alice") {
		t.Fatalf("the owner moved to %v", got)
	}
	var asked bool
	for _, q := range az.Requests() {
		if q.Action == authorizer.ActionConnectionCreate && q.Resource.ID == id && q.Resource.String("owner") == iss.Subject("alice") {
			asked = true
		}
	}
	if !asked {
		t.Fatal("the replaced key asked no question about the stored connection")
	}
}

// waiting are the members of an allow whose case is not written yet. The
// list only shrinks.
var waiting = []string{}

// Each member of Limits has a case in which an allow carrying it changes
// the outcome of a request, or is on the list of members waiting for the
// carrier.
func TestEachMemberOfAnAllowChangesTheOutcome(t *testing.T) {
	iss := stubs.NewIssuer(t)
	cases := map[string]func(t *testing.T){
		"Owner": func(t *testing.T) {
			az, over := withAuthorizer(t, nil)
			az.Allow(stub.Rule{Action: authorizer.ActionConnectionCreate, Limits: map[string]any{"owner": iss.Subject("team")}})
			s := startStack(t, iss, over)
			if got := s.connect("alice", "weather", "", nil).json(t)["owner"]; got != iss.Subject("team") {
				t.Fatalf("owner %v", got)
			}
		},
		"MaxConnections": func(t *testing.T) {
			az, over := withAuthorizer(t, nil)
			az.Allow(stub.Rule{Action: authorizer.ActionConnectionCreate, Limits: map[string]any{"max_connections": 1}})
			s := startStack(t, iss, over)
			if a := s.connect("alice", "weather", "", nil); a.status != http.StatusCreated {
				t.Fatalf("the first: %d", a.status)
			}
			a := s.connect("alice", "weather", "w2", nil)
			if a.status != http.StatusForbidden || a.detail("field") != "owner" || a.detail("reason") != "max_connections=1" {
				t.Fatalf("past the cap: %d %s", a.status, a.body)
			}
		},
		"Connectors": func(t *testing.T) {
			az, over := withAuthorizer(t, nil)
			az.Allow(stub.Rule{Action: authorizer.ActionConnectionCreate, Limits: map[string]any{"connectors": []string{"weather"}}})
			s := startStack(t, iss, over)
			if a := s.connect("alice", "weather", "", nil); a.status != http.StatusCreated {
				t.Fatalf("within: %d", a.status)
			}
			a := s.connect("alice", "search", "", map[string]any{"value": "a-key-of-alice-0006"})
			if a.status != http.StatusForbidden || a.detail("field") != "connector" {
				t.Fatalf("outside: %d %s", a.status, a.body)
			}
			if items := s.do(http.MethodGet, "/v1/connections", "alice", nil).json(t)["items"].([]any); len(items) != 1 {
				t.Fatalf("a refused connect stored a connection: %v", items)
			}
		},
	}
	// use connects alice to the forge with a key, under an allow of a use
	// that carries the limits, and answers the stack and the forwarding
	// address.
	use := func(t *testing.T, limits map[string]any) (*stack, string) {
		az, over := withAuthorizer(t, nil, stub.WithAllow("*"))
		az.Allow(stub.Rule{Action: authorizer.ActionConnectionUse, Limits: limits})
		s := startStack(t, iss, over)
		return s, "/v1/connections/" + s.connect("alice", "forge", "", map[string]any{"value": "a-forge-key-of-alice"}).id(t) + "/http"
	}
	cases["ReadOnly"] = func(t *testing.T) {
		s, web := use(t, map[string]any{"read_only": true})
		if a := s.do(http.MethodGet, web+"/user", "alice", nil); a.status != http.StatusOK {
			t.Fatalf("a read: %d %s", a.status, a.body)
		}
		if a := s.do(http.MethodPost, web+"/repos/acme/app/issues", "alice", map[string]any{"title": "x"}); a.status != http.StatusForbidden || a.detail("field") != "tool" {
			t.Fatalf("a write: %d %s", a.status, a.body)
		}
	}
	cases["Tools"] = func(t *testing.T) {
		s, web := use(t, map[string]any{"tools": []string{"/repos/acme/*"}})
		if a := s.do(http.MethodGet, web+"/repos/acme/app/issues", "alice", nil); a.status != http.StatusOK {
			t.Fatalf("inside: %d %s", a.status, a.body)
		}
		if a := s.do(http.MethodGet, web+"/user", "alice", nil); a.status != http.StatusForbidden || a.detail("reason") != "tools" {
			t.Fatalf("outside: %d %s", a.status, a.body)
		}
	}
	cases["Refs"] = func(t *testing.T) {
		if _, err := stubs.GitPath(); err != nil {
			t.Skip(err.Error())
		}
		s, web := use(t, map[string]any{"refs": []string{"refs/heads/agents/*"}})
		push := strings.TrimSuffix(web, "/http") + "/git/acme/app.git/git-receive-pack"
		body := pktLine(strings.Repeat("0", 40)+" "+strings.Repeat("1", 40)+" refs/heads/main\x00report-status\n") + "0000"
		if a := s.do(http.MethodPost, push, "alice", body, "Content-Type", "application/x-git-receive-pack-request"); a.status != http.StatusForbidden || a.detail("field") != "refs" {
			t.Fatalf("a push to main: %d %s", a.status, a.body)
		}
	}
	cases["CallsPerMinute"] = func(t *testing.T) {
		s, web := use(t, map[string]any{"calls_per_minute": 1})
		if a := s.do(http.MethodGet, web+"/user", "alice", nil); a.status != http.StatusOK {
			t.Fatalf("the first: %d %s", a.status, a.body)
		}
		if a := s.do(http.MethodGet, web+"/user", "alice", nil); a.status != http.StatusTooManyRequests {
			t.Fatalf("the second: %d %s", a.status, a.body)
		}
	}
	members := reflect.TypeFor[authorizer.Limits]()
	for field := range members.Fields() {
		name := field.Name
		_, hasCase := cases[name]
		if hasCase == slices.Contains(waiting, name) {
			t.Errorf("%s has a case: %v, and is waiting: %v", name, hasCase, slices.Contains(waiting, name))
		}
	}
	for name, run := range cases {
		t.Run(name, run)
	}
}

// With no authorizer an owner's connection past the cap is 403 naming the
// limit, and a subject's create past the rate is 429; under an authorizer
// an allow's cap above the installation's is held to it.
func TestLimitsHoldWithNoAuthorizer(t *testing.T) {
	iss := stubs.NewIssuer(t)
	s := startStack(t, iss, map[string]string{"PONS_MAX_CONNECTIONS_PER_OWNER": "2"})
	for i := range 2 {
		if a := s.connect("alice", "weather", fmt.Sprintf("w%d", i), nil); a.status != http.StatusCreated {
			t.Fatalf("%d: %d", i, a.status)
		}
	}
	if a := s.connect("alice", "weather", "w3", nil); a.status != http.StatusForbidden || a.detail("reason") != "max_connections=2" {
		t.Fatalf("past the cap: %d %s", a.status, a.body)
	}
	rate := startStack(t, iss, map[string]string{"PONS_CREATES_PER_MINUTE": "3"})
	for i := range 3 {
		rate.connect("bob", "weather", fmt.Sprintf("w%d", i), nil)
	}
	if a := rate.connect("bob", "weather", "w4", nil); a.status != http.StatusTooManyRequests || a.code() != "rate_limited" || a.header.Get("Retry-After") == "" {
		t.Fatalf("past the rate: %d %s", a.status, a.body)
	}
	if a := rate.connect("carol", "weather", "", nil); a.status != http.StatusCreated {
		t.Fatalf("another subject's rate is its own: %d", a.status)
	}
	az, over := withAuthorizer(t, map[string]string{"PONS_MAX_CONNECTIONS_PER_OWNER": "1"})
	az.Allow(stub.Rule{Action: authorizer.ActionConnectionCreate, Limits: map[string]any{"max_connections": 50}})
	held := startStack(t, iss, over)
	held.connect("alice", "weather", "", nil)
	if a := held.connect("alice", "weather", "w2", nil); a.status != http.StatusForbidden || a.detail("reason") != "max_connections=1" {
		t.Fatalf("an allow above the installation's cap: %d %s", a.status, a.body)
	}
}

// A list is narrowed by its allow's filter and by the request's owner, and
// the catalog is listed whatever the filter.
func TestAListIsNarrowedByItsAllowsFilter(t *testing.T) {
	iss := stubs.NewIssuer(t)
	alice, bob, carol := iss.Subject("alice"), iss.Subject("bob"), iss.Subject("carol")
	az, over := withAuthorizer(t, nil)
	az.Allow(stub.Rule{Subject: carol, Action: authorizer.ActionConnectionList, Filter: &authz.Filter{Owners: []string{alice, bob}}})
	az.Allow(stub.Rule{Subject: carol, Action: authorizer.ActionConnectorList, Filter: &authz.Filter{Owners: []string{}}})
	s := startStack(t, iss, over)
	s.connect("alice", "weather", "", nil)
	s.connect("bob", "weather", "", nil)
	s.connect("carol", "weather", "", nil)
	owners := func(path string) []string {
		var out []string
		for _, item := range s.do(http.MethodGet, path, "carol", nil).json(t)["items"].([]any) {
			out = append(out, item.(map[string]any)["owner"].(string))
		}
		slices.Sort(out)
		return out
	}
	if got := owners("/v1/connections"); !slices.Equal(got, []string{alice, bob}) {
		t.Fatalf("the filter: %v", got)
	}
	if got := owners("/v1/connections?owner=" + bob); !slices.Equal(got, []string{bob}) {
		t.Fatalf("narrowed by owner: %v", got)
	}
	if got := owners("/v1/connections?owner=" + carol); len(got) != 0 {
		t.Fatalf("widened by owner: %v", got)
	}
	catalogItems := s.do(http.MethodGet, "/v1/connectors", "carol", nil).json(t)["items"].([]any)
	if len(catalogItems) != 6 {
		t.Fatalf("the catalog under an empty filter: %d items", len(catalogItems))
	}
}

// Under the owner policy a subject cannot read, list, rename, replace or
// delete another subject's connection, see another's added connector, or
// create in another's name.
func TestTheOwnerPolicyThroughTheAPI(t *testing.T) {
	iss := stubs.NewIssuer(t)
	s := startStack(t, iss, nil)
	if a := s.do(http.MethodPost, "/v1/connections", "alice", map[string]any{"connector": "weather", "owner": iss.Subject("bob")}); a.status != http.StatusForbidden {
		t.Fatalf("a create in another's name: %d %s", a.status, a.body)
	}
	if a := s.do(http.MethodPost, "/v1/connections", "alice", map[string]any{"connector": "weather", "owner": iss.Subject("alice")}); a.status != http.StatusCreated {
		t.Fatalf("a create in its own name: %d %s", a.status, a.body)
	}
	reachesNothing(t, s)
}

// With verified tokens of two owners against a running server, one reaches
// nothing of the other's, and nothing changes.
func TestAnotherOwnersTokenReachesNothing(t *testing.T) {
	reachesNothing(t, startStack(t, stubs.NewIssuer(t), nil))
}

func reachesNothing(t *testing.T, s *stack) {
	t.Helper()
	con := s.connect("alice", "search", "mine", map[string]any{"value": "a-key-of-alice-0007"}).id(t)
	ctr := s.do(http.MethodPost, "/v1/connectors", "alice", map[string]any{
		"name": "wiki", "title": "Wiki", "kind": "mcp", "url": "https://wiki.example.com/mcp", "auth": map[string]any{"type": "none"},
	}).id(t)
	before := snapshot(s)
	for _, r := range []struct {
		method, path string
		body         any
	}{
		{http.MethodGet, "/v1/connections/" + con, nil},
		{http.MethodPatch, "/v1/connections/" + con, map[string]any{"name": "theirs"}},
		{http.MethodPut, "/v1/connections/" + con + "/credential", map[string]any{"credential": map[string]any{"value": "bobs-key-0007"}}},
		{http.MethodGet, "/v1/connections/" + con + "/calls", nil},
		{http.MethodDelete, "/v1/connections/" + con, nil},
		{http.MethodGet, "/v1/connectors/" + ctr, nil},
		{http.MethodDelete, "/v1/connectors/" + ctr, nil},
	} {
		if a := s.do(r.method, r.path, "bob", r.body); a.status != http.StatusNotFound {
			t.Errorf("bob %s %s: %d %s", r.method, r.path, a.status, a.body)
		}
	}
	if a := s.connect("bob", ctr, "", nil); a.status != http.StatusNotFound {
		t.Errorf("bob connects alice's connector: %d", a.status)
	}
	for _, path := range []string{"/v1/connections", "/v1/connectors"} {
		if a := s.do(http.MethodGet, path, "bob", nil); strings.Contains(string(a.body), con) || strings.Contains(string(a.body), ctr) {
			t.Errorf("bob lists alice's: %s", a.body)
		}
	}
	if snapshot(s) != before {
		t.Error("bob's requests changed what alice holds")
	}
}

// snapshot is what a stack's store holds, its lines sorted, so two
// snapshots of one content are equal whatever order a map was walked in.
func snapshot(s *stack) string {
	lines := strings.Split(s.dump(), "\n")
	slices.Sort(lines)
	return strings.Join(lines, "\n")
}

// An added connector is its owner's alone: 404 to anyone else, by id and in
// a list, and it may spell a catalog name without shadowing it.
func TestAnAddedConnectorIsItsOwnersAlone(t *testing.T) {
	s := startStack(t, stubs.NewIssuer(t), nil)
	a := s.do(http.MethodPost, "/v1/connectors", "alice", map[string]any{
		"name": "weather", "title": "My weather", "kind": "mcp", "url": "https://my-weather.example.com/mcp", "auth": map[string]any{"type": "none"},
	})
	id := a.id(t)
	if a := s.do(http.MethodGet, "/v1/connectors/weather", "alice", nil).json(t); a["url"] != "https://weather.example.org/mcp" {
		t.Fatalf("the added connector shadows the catalog's: %v", a)
	}
	if a := s.do(http.MethodGet, "/v1/connectors/"+id, "bob", nil); a.status != http.StatusNotFound {
		t.Fatalf("bob: %d", a.status)
	}
	if a := s.do(http.MethodGet, "/v1/connectors/"+id, "alice", nil); a.status != http.StatusOK {
		t.Fatalf("alice: %d", a.status)
	}
	con := s.connect("alice", id, "mine", nil)
	if con.status != http.StatusCreated || con.json(t)["connector"] != id {
		t.Fatalf("a connection to it: %d %s", con.status, con.body)
	}
	if a := s.do(http.MethodDelete, "/v1/connectors/"+id, "alice", nil); a.status != http.StatusConflict || a.code() != "connector_in_use" {
		t.Fatalf("removing one in use: %d %s", a.status, a.body)
	}
	s.do(http.MethodDelete, "/v1/connections/"+con.id(t), "alice", nil)
	if a := s.do(http.MethodDelete, "/v1/connectors/"+id, "alice", nil); a.status != http.StatusNoContent {
		t.Fatalf("removing it: %d %s", a.status, a.body)
	}
	if a := s.do(http.MethodDelete, "/v1/connectors/weather", "alice", nil); a.status != http.StatusNotFound {
		t.Fatalf("removing a catalog connector: %d", a.status)
	}
}

// A connection whose connector left the catalog is kept and reads with
// empty marks, and its marks return with the entry. A call to it answers
// connector_removed with the carrier.
func TestRemovedConnectorKeepsItsConnections(t *testing.T) {
	iss := stubs.NewIssuer(t)
	db := database(t)
	db["PONS_CATALOG_FILE"] = catalogFile(t, "")
	first := startStack(t, iss, db)
	id := first.connect("alice", "weather", "", nil).id(t)
	keyed := first.connect("alice", "search", "", map[string]any{"value": "a-key-of-alice-0009"}).id(t)
	first.stop()

	gone := mapsWith(db, "PONS_CATALOG_FILE", writeCatalog(t, "connectors: []\n"))
	second := startStack(t, iss, gone)
	c := second.do(http.MethodGet, "/v1/connections/"+id, "alice", nil).json(t)
	if c["state"] != "connected" || len(c["tools"].(map[string]any)["read_only"].([]any)) != 0 {
		t.Fatalf("with the entry gone: %v", c)
	}
	if a := second.connect("alice", "search", "two", map[string]any{"value": "a-key-of-alice-0010"}); a.status != http.StatusNotFound {
		t.Fatalf("a connect to a removed connector: %d %s", a.status, a.body)
	}
	a := second.do(http.MethodPut, "/v1/connections/"+keyed+"/credential", "alice", map[string]any{"credential": map[string]any{"value": "a-key-of-alice-0011"}})
	if a.status != http.StatusConflict || a.code() != "connection_not_connected" || a.detail("reason") != "connector_removed" {
		t.Fatalf("a key for a removed connector: %d %s", a.status, a.body)
	}
	second.stop()

	third := startStack(t, iss, db)
	c = third.do(http.MethodGet, "/v1/connections/"+id, "alice", nil).json(t)
	if got := c["tools"].(map[string]any)["read_only"].([]any); len(got) != 1 || got[0] != "*" {
		t.Fatalf("with the entry back: %v", c)
	}
}

// With no sealing key a server on the memory store starts, says so, is not
// ready, answers sealing_unavailable to a request that would seal, and
// serves reads, lists, deletes and a connection that takes no credential.
func TestWithoutASealingKey(t *testing.T) {
	s := startStack(t, stubs.NewIssuer(t), map[string]string{"PONS_SEALING_KEYS": ""})
	if !strings.Contains(s.logs.String(), "sealing: no key") {
		t.Fatalf("the start does not say so:\n%s", s.logs)
	}
	if a := s.do(http.MethodGet, "/readyz", "", nil); a.status != http.StatusServiceUnavailable || !strings.Contains(string(a.body), "sealing") {
		t.Fatalf("ready with no key: %d %s", a.status, a.body)
	}
	if a := s.connect("alice", "search", "", map[string]any{"value": "a-key-of-alice-0008"}); a.status != http.StatusServiceUnavailable || a.code() != "sealing_unavailable" {
		t.Fatalf("a key with no sealing key: %d %s", a.status, a.body)
	}
	none := s.connect("alice", "weather", "", nil)
	if none.status != http.StatusCreated {
		t.Fatalf("a connector that takes nothing: %d", none.status)
	}
	if a := s.do(http.MethodGet, "/v1/connections", "alice", nil); a.status != http.StatusOK || strings.Count(string(a.body), `"id"`) != 1 {
		t.Fatalf("the list: %d %s", a.status, a.body)
	}
	if a := s.do(http.MethodDelete, "/v1/connections/"+none.id(t), "alice", nil); a.status != http.StatusNoContent {
		t.Fatalf("a delete: %d", a.status)
	}
	if _, err := startErr(t, map[string]string{"PONS_DATABASE_URL": "postgres://pons@127.0.0.1:1/pons", "PONS_SEALING_KEYS": "", "PONS_PUBLIC_URL": "https://pons.example.com"}); err == nil || !strings.Contains(err.Error(), "PONS_SEALING_KEYS") {
		t.Fatalf("a database with no key: %v", err)
	}
}

// pktLine is one pkt-line of git's protocol.
func pktLine(s string) string { return fmt.Sprintf("%04x%s", len(s)+4, s) }
