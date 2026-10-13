// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"latere.ai/x/pons/internal/apierr"

	"latere.ai/x/pons/internal/access"
	"latere.ai/x/pons/internal/id"
	"latere.ai/x/pons/internal/store"
	"latere.ai/x/pons/internal/store/memory"
)

// faulty is a store that fails the methods a test names.
type faulty struct {
	store.Store
	mu   sync.Mutex
	fail map[string]bool
}

var errInjected = errors.New("an injected failure")

func (f *faulty) set(names ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fail = map[string]bool{}
	for _, n := range names {
		f.fail[n] = true
	}
}

func (f *faulty) failing(name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail[name] {
		return errInjected
	}
	return nil
}

func (f *faulty) wrap(tx store.Tx) store.Tx { return faultyTx{Tx: tx, f: f} }

func (f *faulty) Tx(ctx context.Context, fn func(store.Tx) error) error {
	return f.Store.Tx(ctx, func(tx store.Tx) error { return fn(f.wrap(tx)) })
}

func (f *faulty) Connectors() store.Connectors   { return f.wrap(f.Store).Connectors() }
func (f *faulty) Connections() store.Connections { return f.wrap(f.Store).Connections() }
func (f *faulty) Credentials() store.Credentials { return f.wrap(f.Store).Credentials() }
func (f *faulty) Calls() store.Calls             { return f.wrap(f.Store).Calls() }
func (f *faulty) Idempotency() store.Idempotency { return f.wrap(f.Store).Idempotency() }

type faultyTx struct {
	store.Tx
	f *faulty
}

func (t faultyTx) Connectors() store.Connectors   { return connectorsF{t.Tx.Connectors(), t.f} }
func (t faultyTx) Connections() store.Connections { return connectionsF{t.Tx.Connections(), t.f} }
func (t faultyTx) Credentials() store.Credentials { return credentialsF{t.Tx.Credentials(), t.f} }
func (t faultyTx) Calls() store.Calls             { return callsF{t.Tx.Calls(), t.f} }
func (t faultyTx) Idempotency() store.Idempotency { return idempotencyF{t.Tx.Idempotency(), t.f} }

type connectorsF struct {
	store.Connectors
	f *faulty
}

func (c connectorsF) Create(ctx context.Context, row store.Connector) error {
	if err := c.f.failing("connectors.create"); err != nil {
		return err
	}
	return c.Connectors.Create(ctx, row)
}

func (c connectorsF) Get(ctx context.Context, id string) (store.Connector, error) {
	if err := c.f.failing("connectors.get"); err != nil {
		return store.Connector{}, err
	}
	return c.Connectors.Get(ctx, id)
}

func (c connectorsF) List(ctx context.Context, owners []string, p store.Page) ([]store.Connector, string, error) {
	if err := c.f.failing("connectors.list"); err != nil {
		return nil, "", err
	}
	return c.Connectors.List(ctx, owners, p)
}

func (c connectorsF) Delete(ctx context.Context, id string) error {
	if err := c.f.failing("connectors.delete"); err != nil {
		return err
	}
	return c.Connectors.Delete(ctx, id)
}

type connectionsF struct {
	store.Connections
	f *faulty
}

func (c connectionsF) Create(ctx context.Context, row store.Connection, max int) error {
	if err := c.f.failing("connections.create"); err != nil {
		return err
	}
	return c.Connections.Create(ctx, row, max)
}

func (c connectionsF) Get(ctx context.Context, id string) (store.Connection, error) {
	if err := c.f.failing("connections.get"); err != nil {
		return store.Connection{}, err
	}
	return c.Connections.Get(ctx, id)
}

func (c connectionsF) List(ctx context.Context, f store.Filter, p store.Page) ([]store.Connection, string, error) {
	if err := c.f.failing("connections.list"); err != nil {
		return nil, "", err
	}
	return c.Connections.List(ctx, f, p)
}

func (c connectionsF) Rename(ctx context.Context, id, name string) error {
	if err := c.f.failing("connections.rename"); err != nil {
		return err
	}
	return c.Connections.Rename(ctx, id, name)
}

func (c connectionsF) Delete(ctx context.Context, id string) error {
	if err := c.f.failing("connections.delete"); err != nil {
		return err
	}
	return c.Connections.Delete(ctx, id)
}

type credentialsF struct {
	store.Credentials
	f *faulty
}

func (c credentialsF) Put(ctx context.Context, id string, sc store.SealedCredential) (int64, error) {
	if err := c.f.failing("credentials.put"); err != nil {
		return 0, err
	}
	return c.Credentials.Put(ctx, id, sc)
}

type callsF struct {
	store.Calls
	f *faulty
}

func (c callsF) List(ctx context.Context, id string, p store.Page) ([]store.Call, string, error) {
	if err := c.f.failing("calls.list"); err != nil {
		return nil, "", err
	}
	return c.Calls.List(ctx, id, p)
}

type idempotencyF struct {
	store.Idempotency
	f *faulty
}

func (c idempotencyF) Get(ctx context.Context, subject, key string) (store.IdempotencyKey, error) {
	if err := c.f.failing("idempotency.get"); err != nil {
		return store.IdempotencyKey{}, err
	}
	return c.Idempotency.Get(ctx, subject, key)
}

// A store that fails answers internal, with nothing of the failure in the
// answer and its text in the log.
func TestAFailingStoreIsInternal(t *testing.T) {
	f := &faulty{Store: memory.New(memory.Options{})}
	h := newHarnessOn(t, f)
	ctr, con := fixture(t, h)
	addBody := map[string]any{"name": "x2", "title": "X", "kind": "mcp", "url": "https://x.example.com/mcp", "auth": map[string]any{"type": "none"}}
	cases := []struct {
		fail         string
		method, path string
		body         any
		headers      []string
	}{
		{"connectors.list", http.MethodGet, "/v1/connectors", nil, nil},
		{"connectors.list", http.MethodGet, "/v1/connectors?limit=6", nil, nil},
		{"connectors.get", http.MethodGet, "/v1/connectors/" + ctr, nil, nil},
		{"connectors.get", http.MethodDelete, "/v1/connectors/" + ctr, nil, nil},
		{"connectors.delete", http.MethodDelete, "/v1/connectors/" + ctr, nil, nil},
		{"connectors.create", http.MethodPost, "/v1/connectors", addBody, nil},
		{"connectors.get", http.MethodPost, "/v1/connections", map[string]any{"connector": ctr}, nil},
		{"connections.create", http.MethodPost, "/v1/connections", map[string]any{"connector": "weather", "name": "w9"}, nil},
		{"credentials.put", http.MethodPost, "/v1/connections", map[string]any{"connector": "search", "name": "s9", "credential": map[string]any{"value": "a-key-0000001"}}, nil},
		{"idempotency.get", http.MethodPost, "/v1/connections", map[string]any{"connector": "weather", "name": "w1"}, []string{"Idempotency-Key", "same"}},
		{"connections.get", http.MethodGet, "/v1/connections/" + con, nil, nil},
		{"connections.list", http.MethodGet, "/v1/connections", nil, nil},
		{"connections.rename", http.MethodPatch, "/v1/connections/" + con, map[string]any{"name": "other"}, nil},
		{"connections.delete", http.MethodDelete, "/v1/connections/" + con, nil, nil},
		{"credentials.put", http.MethodPut, "/v1/connections/" + con + "/credential", map[string]any{"credential": map[string]any{"value": "a-key-0000002"}}, nil},
		{"calls.list", http.MethodGet, "/v1/connections/" + con + "/calls", nil, nil},
	}
	// The idempotent case needs the key taken first.
	h.do(http.MethodPost, "/v1/connections", "alice", map[string]any{"connector": "weather", "name": "w1"}, "Idempotency-Key", "same")
	for _, tc := range cases {
		f.set(tc.fail)
		a := h.do(tc.method, tc.path, "alice", tc.body, tc.headers...)
		f.set()
		if a.status != http.StatusInternalServerError || a.code() != apierr.CodeInternal || strings.Contains(string(a.body), "injected") {
			t.Errorf("%s %s with %s failing: %d %s", tc.method, tc.path, tc.fail, a.status, a.body)
		}
	}
	if !strings.Contains(h.logText(), "an injected failure") {
		t.Fatal("the failures were not logged")
	}
}

// Bodies the API cannot read.
func TestBodiesThatDoNotRead(t *testing.T) {
	h := newHarness(t)
	cases := []struct {
		body        string
		code, field string
	}{
		{`{"connector": "weather"} {}`, apierr.CodeInvalidRequest, ""},
		{`not json`, apierr.CodeInvalidRequest, ""},
		{`{"connector": 5}`, apierr.CodeInvalidField, "connector"},
		{`{"connector": "weather", "color": "red"}`, apierr.CodeUnknownField, "color"},
		{`{}`, apierr.CodeMissingField, "connector"},
		{`{"connector": "nothing"}`, apierr.CodeConnectorNotFound, "connector"},
		{`{"connector": "ctr_01jb2m7c0p5d8f2h6j9k3m4n7q"}`, apierr.CodeConnectorNotFound, "connector"},
		{`{"connector": "weather", "name": "Not_A_Label"}`, apierr.CodeInvalidField, "name"},
		{`{"connector": "weather", "return_to": "https://app.example.com"}`, apierr.CodeInvalidField, "return_to"},
		{`{"connector": "weather", "scopes": ["a"]}`, apierr.CodeInvalidField, "scopes"},
		{`{"connector": "weather", "credential": {"value": "a-key-0000003"}}`, apierr.CodeInvalidField, "credential.value"},
		{`{"connector": "warehouse", "credential": {"value": "a-key-0000003"}}`, apierr.CodeInvalidField, "credential.value"},
		{`{"connector": "warehouse", "credential": {"client_secret": "a-secret-00001"}}`, apierr.CodeMissingField, "credential.client_id"},
		{`{"connector": "search", "credential": {"client_id": "x", "value": "a-key-0000003"}}`, apierr.CodeInvalidField, "credential.client_id"},
		{`{"connector": "search"}`, apierr.CodeMissingField, "credential.value"},
	}
	for _, tc := range cases {
		a := h.do(http.MethodPost, "/v1/connections", "alice", tc.body)
		if a.code() != tc.code || (tc.field != "" && a.detail("field") != tc.field) {
			t.Errorf("%s: %d %s", tc.body, a.status, a.body)
		}
	}
	big := `{"connector": "` + strings.Repeat("a", maxBodyBytes) + `"}`
	if a := h.do(http.MethodPost, "/v1/connections", "alice", big); a.status != http.StatusRequestEntityTooLarge {
		t.Errorf("a large body: %d", a.status)
	}
	if a := h.do(http.MethodPatch, "/v1/connections/con_1", "alice", `{}`); a.code() != apierr.CodeMissingField {
		t.Errorf("a rename with no name: %s", a.body)
	}
	if a := h.do(http.MethodPatch, "/v1/connections/con_1", "alice", `{"name": "A B"}`); a.code() != apierr.CodeInvalidField {
		t.Errorf("a rename with a bad name: %s", a.body)
	}
	if a := h.do(http.MethodPatch, "/v1/connections/con_1", "alice", `x`); a.code() != apierr.CodeInvalidRequest {
		t.Errorf("a rename that is no JSON: %s", a.body)
	}
	if a := h.do(http.MethodPut, "/v1/connections/con_1/credential", "alice", `{}`); a.code() != apierr.CodeMissingField {
		t.Errorf("a replacement with no credential: %s", a.body)
	}
	if a := h.do(http.MethodPut, "/v1/connections/con_1/credential", "alice", `[`); a.code() != apierr.CodeInvalidRequest {
		t.Errorf("a replacement that is no JSON: %s", a.body)
	}
	if a := h.do(http.MethodPost, "/v1/connectors", "alice", `[`); a.code() != apierr.CodeInvalidRequest {
		t.Errorf("an add that is no JSON: %s", a.body)
	}
	for _, q := range []string{"limit=0", "limit=x", "state=gone"} {
		if a := h.do(http.MethodGet, "/v1/connections?"+q, "alice", nil); a.code() != apierr.CodeInvalidField {
			t.Errorf("?%s: %s", q, a.body)
		}
	}
	for _, path := range []string{"/v1/connectors?limit=-1", "/v1/connections/con_1/calls?limit=x"} {
		if a := h.do(http.MethodGet, path, "alice", nil); a.code() != apierr.CodeInvalidField {
			t.Errorf("%s: %s", path, a.body)
		}
	}
	if got := (&apierr.Error{Code: apierr.CodeInvalidField, Reason: "r", Field: "f"}).Error(); got != "apierr: invalid_field: r (f)" {
		t.Errorf("Error() = %q", got)
	}
	if got := (&apierr.Error{Code: apierr.CodeInternal}).Error(); got != "apierr: internal" {
		t.Errorf("Error() = %q", got)
	}
}

// The catalog and the added connectors page together: the catalog first, in
// the order of its file, then the added ones newest first.
func TestConnectorsPageThroughBoth(t *testing.T) {
	h := newHarness(t, func(s *Server) { s.IDs = &id.Generator{} })
	for _, name := range []string{"one", "two", "three"} {
		a := h.do(http.MethodPost, "/v1/connectors", "alice", map[string]any{"name": name, "title": name, "kind": "mcp", "url": "https://" + name + ".example.com/mcp", "auth": map[string]any{"type": "none"}})
		if a.status != http.StatusCreated {
			t.Fatal(a.status, string(a.body))
		}
	}
	walk := func(query string, size int) []string {
		var names []string
		cursor := ""
		for range 20 {
			path := "/v1/connectors?" + query + "&limit=" + string(rune('0'+size))
			if cursor != "" {
				path += "&cursor=" + cursor
			}
			body := h.do(http.MethodGet, path, "alice", nil).json(t)
			for _, item := range body["items"].([]any) {
				names = append(names, item.(map[string]any)["name"].(string))
			}
			next, _ := body["next_cursor"].(string)
			if next == "" {
				return names
			}
			cursor = next
		}
		t.Fatal("the pages did not end")
		return nil
	}
	want := "tracker search warehouse weather api code three two one"
	for size := 1; size <= 9; size++ {
		if got := strings.Join(walk("", size), " "); got != want {
			t.Errorf("pages of %d: %s", size, got)
		}
	}
	if got := strings.Join(walk("kind=http", 2), " "); got != "api" {
		t.Errorf("kind http: %s", got)
	}
	if got := strings.Join(walk("kind=mcp", 6), " "); got != "tracker search warehouse weather code three two one" {
		t.Errorf("kind mcp: %s", got)
	}
	if got := strings.Join(walk("", 6), " "); got != want {
		t.Errorf("a page that ends the catalog: %s", got)
	}
	bob := h.do(http.MethodGet, "/v1/connectors?limit=6", "bob", nil).json(t)
	if _, more := bob["next_cursor"]; more {
		t.Errorf("bob, who added nothing, has a next page after the catalog: %v", bob)
	}
}

// Connections and their records page newest first, and narrow by connector
// and state.
func TestConnectionsAndCallsPage(t *testing.T) {
	h := newHarness(t)
	var ids []string
	for i := range 3 {
		a := h.connect("alice", "weather", "w"+string(rune('a'+i)), "")
		ids = append(ids, idOf(t, a))
	}
	h.connect("alice", "search", "", "a-key-0000004")
	first := h.do(http.MethodGet, "/v1/connections?connector=weather&limit=2", "alice", nil).json(t)
	items := first["items"].([]any)
	if len(items) != 2 || items[0].(map[string]any)["id"] != ids[2] || first["next_cursor"] != ids[1] {
		t.Fatalf("the first page: %v", first)
	}
	second := h.do(http.MethodGet, "/v1/connections?connector=weather&limit=2&cursor="+ids[1], "alice", nil).json(t)
	if items := second["items"].([]any); len(items) != 1 || items[0].(map[string]any)["id"] != ids[0] {
		t.Fatalf("the second page: %v", second)
	}
	if got := h.do(http.MethodGet, "/v1/connections?state=needs_reconnect", "alice", nil).json(t)["items"].([]any); len(got) != 0 {
		t.Fatalf("needs_reconnect: %v", got)
	}
	ctx := context.Background()
	at := time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)
	for i := range 3 {
		call := store.Call{
			ID: id.New(id.Call), Connection: ids[0], Owner: subject("alice"), Connector: "weather", Subject: subject("alice"),
			Session: "ses_1", At: at.Add(time.Duration(i) * time.Second), DurationMS: 12, Method: "tools/call", Tool: "get_forecast",
			Effect: "read", Outcome: "ok", Status: 200, BytesIn: 10, BytesOut: 20,
		}
		if err := h.store.Calls().Insert(ctx, call); err != nil {
			t.Fatal(err)
		}
	}
	page := h.do(http.MethodGet, "/v1/connections/"+ids[0]+"/calls?limit=2", "alice", nil)
	hold(t, http.MethodGet, "/connections/"+ids[0]+"/calls", page)
	body := page.json(t)
	if items := body["items"].([]any); len(items) != 2 || items[0].(map[string]any)["tool"] != "get_forecast" || body["next_cursor"] == nil {
		t.Fatalf("calls: %v", body)
	}
}

// A replaced key moves a connection out of needs_reconnect and clears its
// reason; a connection of another way to give access takes no credential.
func TestReplacingACredential(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	keyed := idOf(t, h.connect("alice", "search", "", "a-key-0000005"))
	if err := h.store.Connections().Move(ctx, keyed, store.StateConnected, store.StateNeedsReconnect, store.ReasonCredentialRefused); err != nil {
		t.Fatal(err)
	}
	if got := h.do(http.MethodGet, "/v1/connections/"+keyed, "alice", nil).json(t); got["state"] != "needs_reconnect" || got["reason"] != "credential_refused" {
		t.Fatalf("before: %v", got)
	}
	if a := h.do(http.MethodPut, "/v1/connections/"+keyed+"/credential", "alice", map[string]any{"credential": map[string]any{"value": "a-key-0000006"}}); a.status != http.StatusNoContent {
		t.Fatalf("%d %s", a.status, a.body)
	}
	got := h.do(http.MethodGet, "/v1/connections/"+keyed, "alice", nil).json(t)
	if got["state"] != "connected" || got["reason"] != nil {
		t.Fatalf("after: %v", got)
	}
	if _, version, err := h.store.Credentials().Get(ctx, keyed); err != nil || version != 2 {
		t.Fatalf("the credential: %d %v", version, err)
	}
	cc := idOf(t, h.do(http.MethodPost, "/v1/connections", "alice", map[string]any{"connector": "warehouse", "credential": map[string]any{"client_id": "wh", "client_secret": "a-secret-00002"}}))
	h.up.auth.AddClient("wh2", "")
	if a := h.do(http.MethodPut, "/v1/connections/"+cc+"/credential", "alice", map[string]any{"credential": map[string]any{"client_id": "wh2", "client_secret": "a-secret-00003"}}); a.status != http.StatusNoContent {
		t.Fatalf("a new client: %d %s", a.status, a.body)
	}
	none := idOf(t, h.connect("alice", "weather", "", ""))
	if a := h.do(http.MethodPut, "/v1/connections/"+none+"/credential", "alice", map[string]any{"credential": map[string]any{"value": "a-key-0000007"}}); a.code() != apierr.CodeWrongKind {
		t.Fatalf("a credential for none: %d %s", a.status, a.body)
	}
	if a := h.do(http.MethodPatch, "/v1/connections/"+none, "alice", map[string]any{"name": "search"}); a.code() != apierr.CodeNameTaken {
		t.Fatalf("a rename to a taken name: %d %s", a.status, a.body)
	}
	api := h.connect("alice", "api", "", "a-key-0000008").json(t)
	if !strings.HasSuffix(api["address"].(string), "/connections/"+api["id"].(string)+"/http") {
		t.Fatalf("the address of kind http: %v", api["address"])
	}
	if code := h.connect("alice", "code", "", ""); code.code() != apierr.CodeMissingField {
		t.Fatalf("an oauth connect with no return_to: %d %s", code.status, code.body)
	}
	code := h.do(http.MethodPost, "/v1/connections", "alice", map[string]any{"connector": "code", "return_to": "https://app.example.com/done"})
	started := code.json(t)
	if code.status != http.StatusCreated || !strings.HasPrefix(started["authorization_url"].(string), "https://code.example.com/authorize?") ||
		started["connection"].(map[string]any)["state"] != "pending" {
		t.Fatalf("an oauth connect: %d %s", code.status, code.body)
	}
}

// The probes keep their answers when the logger is the default one.
func TestDefaults(t *testing.T) {
	s := &Server{}
	if s.log() == nil || s.newID(id.Connection) == "" {
		t.Fatal("the defaults")
	}
	var _ access.Authorizer = deciderFunc(nil)
}
