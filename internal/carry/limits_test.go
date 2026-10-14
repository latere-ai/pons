// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package carry

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"latere.ai/x/pkg/authz"
	"latere.ai/x/pkg/authz/stub"

	"latere.ai/x/pons/authorizer"
	"latere.ai/x/pons/catalog"
	"latere.ai/x/pons/internal/access"
	"latere.ai/x/pons/internal/dial"
	"latere.ai/x/pons/internal/store"
	"latere.ai/x/pons/test/stubs"
)

// A use carries its method, the tool and the effect the request names, and
// a push its refs; nothing else is sent empty.
func TestAUseAsksWithItsTool(t *testing.T) {
	r := newRig(t, false)
	c := r.keyed()
	r.send(http.MethodGet, address(c, "http")+"/repos/acme/app?x=1", "alice", nil)
	q := r.az.questions()[0]
	want := map[string]any{"owner": subject("alice"), "connector": "api", "name": "api", "connection_kind": "http", "method": "GET", "tool": "/repos/acme/app", "effect": "read"}
	if q.Action != authorizer.ActionConnectionUse || q.Resource.ID != c.ID || len(q.Resource.Fields) != len(want) {
		t.Fatalf("asked %+v", q)
	}
	for k, v := range want {
		if q.Resource.Fields[k] != v {
			t.Errorf("%s is %v, want %v", k, q.Resource.Fields[k], v)
		}
	}
	res := access.Connection{ID: "con_1", Kind: "http", Method: "POST", Tool: ReceivePack, Effect: "write", Refs: []string{"refs/heads/agents/a"}}
	if refs, _ := res.Resource(authorizer.ActionConnectionUse).Fields["refs"].([]string); len(refs) != 1 {
		t.Fatalf("a push's refs %+v", res.Resource(authorizer.ActionConnectionUse))
	}
	if _, ok := res.Resource(authorizer.ActionConnectionRead).Fields["refs"]; ok {
		t.Fatal("a read carries refs")
	}

	// At the MCP address a tools/call names its tool and effect, any other
	// message its method alone, and a reply, which has no method, neither.
	n := r.noted()
	for _, tc := range []struct {
		send func() answer
		want map[string]any
	}{
		{func() answer { return r.call(n, "alice", "create_note", map[string]any{"title": "x"}) }, map[string]any{"method": "tools/call", "tool": "create_note", "effect": "write"}},
		{func() answer { return r.list(n, "alice") }, map[string]any{"method": "tools/list"}},
		{func() answer { return r.send(http.MethodGet, address(n, "mcp"), "alice", nil) }, map[string]any{"method": "GET"}},
		{func() answer {
			return r.send(http.MethodPost, address(n, "mcp"), "alice", strings.NewReader(`{"jsonrpc":"2.0","id":4,"result":{}}`))
		}, map[string]any{}},
	} {
		before := len(r.az.questions())
		tc.send()
		q := r.az.questions()[before]
		for _, k := range []string{"method", "tool", "effect"} {
			if q.Resource.Fields[k] != tc.want[k] {
				t.Errorf("%s is %v, want %v", k, q.Resource.Fields[k], tc.want[k])
			}
		}
		if q.Resource.Fields["connection_kind"] != "mcp" {
			t.Errorf("the kind %v", q.Resource.Fields)
		}
	}
}

// A call a limit refuses opens no credential, reaches no connector and is
// recorded denied; the rate per minute and the places in flight are 429.
func TestALimitRefusesBeforeTheCredential(t *testing.T) {
	r := newRig(t, false)
	c := r.keyed()
	r.az.set(authorizer.Limits{Tools: []string{"/user"}})
	opened := r.sealer.opens()
	a := r.send(http.MethodGet, address(c, "http")+"/repos/acme/app", "alice", nil)
	if a.status != http.StatusForbidden || a.detail("field") != "tool" || a.detail("reason") != "tools" {
		t.Fatalf("a tool outside the globs: %d %s", a.status, a.body)
	}
	if r.sealer.opens() != opened || len(r.api.Requests()) != 0 {
		t.Fatal("a refused call opened the credential or reached the connector")
	}
	if a := r.send(http.MethodGet, address(c, "http")+"/user", "alice", nil); a.status != http.StatusOK {
		t.Fatalf("a tool inside the globs: %d %s", a.status, a.body)
	}
	if got := r.calls(c); len(got) != 2 || got[0].Outcome != OutcomeDenied {
		t.Fatalf("records %+v", got)
	}
	r.az.set(authorizer.Limits{CallsPerMinute: 1})
	if a := r.send(http.MethodGet, address(c, "http")+"/user", "alice", nil); a.status != http.StatusOK {
		t.Fatalf("the first of the minute: %d", a.status)
	}
	a = r.send(http.MethodGet, address(c, "http")+"/user", "alice", nil)
	if a.status != http.StatusTooManyRequests || a.detail("reason") != "calls_per_minute=1" || a.header.Get("Retry-After") == "" {
		t.Fatalf("past the rate: %d %s", a.status, a.body)
	}

	p := &places{process: 3, subject: 2, connection: 2, subjects: map[string]int{}, connections: map[string]int{}}
	one, err := p.caller("s1")
	if err != nil {
		t.Fatal(err)
	}
	two, err := p.caller("s1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.caller("s1"); err == nil || !strings.Contains(err.Error(), "max_inflight_per_subject=2") {
		t.Fatalf("a subject past its places: %v", err)
	}
	three, err := p.caller("s2")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.caller("s3"); err == nil || !strings.Contains(err.Error(), "max_inflight=3") {
		t.Fatalf("a process past its places: %v", err)
	}
	one()
	two()
	three()
	if p.total != 0 || len(p.subjects) != 0 {
		t.Fatalf("places left: %+v", p)
	}
	held := []func(){}
	for range 2 {
		release, err := p.connectionPlace("con_1")
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, release)
	}
	if _, err := p.connectionPlace("con_1"); err == nil {
		t.Fatal("a connection past its places")
	}
	if release, err := p.connectionPlace("con_2"); err != nil {
		t.Fatal("another connection's places are its own")
	} else {
		release()
	}
	for _, release := range held {
		release()
	}
	if len(p.connections) != 0 {
		t.Fatalf("places left: %+v", p.connections)
	}
}

// The session claim reaches the authorizer verbatim and the record as its
// id; a claim of another shape or over 128 bytes leaves the record without
// one.
func TestTheSessionClaimIsCopiedNotRead(t *testing.T) {
	r := newRig(t, false)
	c := r.keyed()
	r.send(http.MethodGet, address(c, "http")+"/user", "agent", nil)
	if got := r.calls(c); len(got) != 1 || got[0].Session != "ses_01" {
		t.Fatalf("records %+v", got)
	}
	for claim, want := range map[any]string{
		"ses_02":                 "ses_02",
		strings.Repeat("s", 129): "",
		42.0:                     "",
		true:                     "",
	} {
		if got := session(map[string]any{"session": claim}); got != want {
			t.Errorf("%v: %q", claim, got)
		}
	}
	if got := session(map[string]any{"session": map[string]any{"id": 7.0}}); got != "" {
		t.Errorf("an id that is no string: %q", got)
	}
	if got := truncate(strings.Repeat("t", 200)); len(got) != 128 {
		t.Errorf("a tool kept at %d bytes", len(got))
	}
}

// An allow of a use is remembered per tool: a second call of the same tool
// asks nothing within the ttl, a call of another tool asks, and a deny at
// the authorizer holds once the ttl has passed.
func TestAnAllowIsRememberedPerTool(t *testing.T) {
	r := newRig(t, false)
	c := r.keyed()
	az := stubs.NewAuthorizer(t, stub.WithAllow("*"))
	az.Allow(stub.Rule{Action: authorizer.ActionConnectionUse, TTL: 1})
	client, err := authz.NewClient(authz.Options{
		URL: az.URL(), Token: az.Token(), Vocabulary: authorizer.Vocabulary(),
		HTTP: dial.Operator(dial.OperatorOptions{Roots: stubs.Roots()}),
	})
	if err != nil {
		t.Fatal(err)
	}
	r.serving.Wait()
	r.c.Authz = access.NewAuthorizer(client)
	uses := func() int {
		n := 0
		for _, q := range az.Requests() {
			if q.Action == authorizer.ActionConnectionUse {
				n++
			}
		}
		return n
	}
	for range 2 {
		if a := r.send(http.MethodGet, address(c, "http")+"/user", "alice", nil); a.status != http.StatusOK {
			t.Fatalf("%d %s", a.status, a.body)
		}
	}
	if uses() != 1 {
		t.Fatalf("the same tool asked %d times", uses())
	}
	r.send(http.MethodGet, address(c, "http")+"/repos/acme/app", "alice", nil)
	if uses() != 2 {
		t.Fatalf("another tool asked %d times in all", uses())
	}
	az.Deny(stub.Rule{Action: authorizer.ActionConnectionUse}, "revoked")
	time.Sleep(1100 * time.Millisecond)
	if a := r.send(http.MethodGet, address(c, "http")+"/user", "alice", nil); a.status != http.StatusNotFound {
		t.Fatalf("a deny past the ttl: %d %s", a.status, a.body)
	}
}

// The probe of a key for kind http: an answer accepts it, a 401 or a 403
// refuses it, and no answer is a connector that cannot be reached.
func TestProbeOfAKey(t *testing.T) {
	r := newRig(t, false)
	api := r.conns["api"]
	key := store.Secrets{Value: "a-probed-key-00001"}
	meta := store.Meta{Header: "Authorization", Format: "Bearer {value}"}
	if err := r.c.Probe(t.Context(), api, key, meta); err != nil {
		t.Fatalf("an accepted key: %v", err)
	}
	if got := r.api.Requests(); len(got) != 1 || got[0].Path != "/" || got[0].Credential != "Bearer a-probed-key-00001" {
		t.Fatalf("the probe %+v", got)
	}
	r.api.Refuse("Bearer a-probed-key-00001")
	if err := r.c.Probe(t.Context(), api, key, meta); err == nil || !strings.Contains(err.Error(), "credential_refused") {
		t.Fatalf("a refused key: %v", err)
	}
	gone := api
	gone.URL = "https://nothing.example.org"
	if err := r.c.Probe(t.Context(), gone, key, meta); err == nil || !strings.Contains(err.Error(), "connector_unreachable") {
		t.Fatalf("an unreachable connector: %v", err)
	}
	gone.URL = "https://%zz"
	if err := r.c.Probe(t.Context(), gone, key, meta); err == nil || !strings.Contains(err.Error(), "connector_unreachable") {
		t.Fatalf("a url that does not parse: %v", err)
	}
}

// A connection is used in the states that may be used, and every other
// answers 409 with its state; a connector that left the catalog answers
// connector_removed; a credential no key opens answers 503 and leaves no
// record.
func TestTheStateOfAConnection(t *testing.T) {
	r := newRig(t, false)
	ctx := context.Background()
	c := r.keyed()
	call := func(sub string, c store.Connection) answer {
		return r.send(http.MethodGet, address(c, "http")+"/user", sub, nil)
	}
	if err := r.st.Connections().Move(ctx, c.ID, store.StateConnected, store.StatePending, ""); err != nil {
		t.Fatal(err)
	}
	if a := call("alice", c); a.status != http.StatusOK {
		t.Fatalf("pending for a reconnect, with its credential: %d %s", a.status, a.body)
	}
	if err := r.st.Connections().Move(ctx, c.ID, store.StatePending, store.StatePending, store.ReasonRevoked); err != nil {
		t.Fatal(err)
	}
	if a := call("alice", c); a.status != http.StatusConflict || a.detail("state") != "pending" || a.detail("reason") != store.ReasonRevoked {
		t.Fatalf("pending with a reason: %d %s", a.status, a.body)
	}
	fresh := store.Connection{ID: "con_fresh", Owner: subject("bob"), Name: "api", Connector: "api", Kind: "http", Auth: "token", State: store.StatePending, CreatedBy: subject("bob")}
	if err := r.st.Connections().Create(ctx, fresh, 0); err != nil {
		t.Fatal(err)
	}
	if a := call("bob", fresh); a.status != http.StatusConflict || a.detail("reason") != "not_confirmed" {
		t.Fatalf("pending with no credential: %d %s", a.status, a.body)
	}
	removed := r.connect("carol", "api", store.Secrets{Value: "the-key-of-carol-0001"}, store.Meta{})
	api := r.conns["api"]
	r.serving.Wait()
	delete(r.conns, "api")
	if a := call("carol", removed); a.status != http.StatusConflict || a.detail("reason") != "connector_removed" {
		t.Fatalf("a connector that left: %d %s", a.status, a.body)
	}
	r.serving.Wait()
	r.conns["api"] = api
	if a := call("carol", removed); a.status != http.StatusOK {
		t.Fatalf("a connector that came back: %d %s", a.status, a.body)
	}
	// A credential sealed under another key does not open.
	other, err := store.NewSealer([32]byte{9})
	if err != nil {
		t.Fatal(err)
	}
	lost := r.connect("dave", "api", store.Secrets{Value: "the-key-of-dave-0001"}, store.Meta{})
	plain, _ := store.Secrets{Value: "the-key-of-dave-0001"}.Encode()
	sealed, err := other.Seal(plain, store.CredentialBinding(lost.ID, lost.Owner, lost.Auth, store.Meta{}, ""))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.st.Credentials().Put(ctx, lost.ID, store.SealedCredential{Kind: "token", Meta: []byte(`{}`), Sealed: sealed}); err != nil {
		t.Fatal(err)
	}
	if a := call("dave", lost); a.status != http.StatusServiceUnavailable || a.code() != "sealing_unavailable" {
		t.Fatalf("a value no key opens: %d %s", a.status, a.body)
	}
	if got := r.calls(lost); len(got) != 0 {
		t.Fatalf("a failure of Pons's own left a record: %+v", got)
	}
	if row, _ := r.st.Connections().Get(ctx, lost.ID); row.State != store.StateConnected {
		t.Fatalf("a value no key opens moved the state: %s", row.State)
	}
	if !strings.Contains(r.logs.String(), "a credential did not open") {
		t.Fatal("a value no key opens was not logged")
	}
	_ = catalog.KindHTTP
}

// A credential within a minute of its expiry is refreshed before it is
// used; the header timeout is 504; an idle answer is cut and recorded
// timeout; a caller that goes away is recorded canceled.
func TestTimeoutsAndCancel(t *testing.T) {
	r := newRig(t, false)
	c, old := r.signedIn(time.Now().Add(30 * time.Second))
	if a := r.send(http.MethodGet, address(c, "http")+"/user", "alice", nil); a.status != http.StatusOK {
		t.Fatalf("%d %s", a.status, a.body)
	}
	if got := r.api.Credentials(); len(got) != 1 || got[0] == "Bearer "+old {
		t.Fatalf("a token due for a refresh was used: %v", got)
	}
	k := r.keyed()
	r.serving.Wait()
	r.c.HeaderTimeout = 100 * time.Millisecond
	r.api.Slow(time.Second)
	if a := r.send(http.MethodGet, address(k, "http")+"/user", "alice", nil); a.status != http.StatusGatewayTimeout || a.code() != "connector_timeout" {
		t.Fatalf("the header timeout: %d %s", a.status, a.body)
	}
	r.api.Slow(0)
	got := r.calls(k)
	if len(got) != 1 || got[0].Outcome != OutcomeTimeout {
		t.Fatalf("records %+v", got)
	}
	r.c.HeaderTimeout = 5 * time.Second
	ctx, cancel := context.WithCancel(context.Background())
	r.api.Slow(2 * time.Second)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.srv.URL+address(k, "http")+"/user", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer alice")
	time.AfterFunc(100*time.Millisecond, cancel)
	if resp, err := r.srv.Client().Do(req); err == nil {
		closeBody(resp)
		t.Fatal("a caller that went away was answered")
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(r.calls(k)) < 2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if got := r.calls(k); len(got) != 2 || got[1].Outcome != OutcomeCanceled {
		t.Fatalf("records %+v", got)
	}

	// The MCP address: the header timeout is 504, a silent stream is cut,
	// and a caller that goes away cancels the connector's request.
	r.api.Slow(0)
	n := r.noted()
	r.serving.Wait()
	r.c.HeaderTimeout = 100 * time.Millisecond
	r.mcp.Set(func(sw *stubs.ConnectorSwitches) { sw.Slow = time.Second })
	if a := r.list(n, "alice"); a.status != http.StatusGatewayTimeout || a.code() != "connector_timeout" {
		t.Fatalf("the header timeout at the MCP address: %d %s", a.status, a.body)
	}
	r.serving.Wait()
	r.c.HeaderTimeout, r.c.IdleTimeout = 5*time.Second, 100*time.Millisecond
	r.mcp.Set(func(sw *stubs.ConnectorSwitches) { sw.Slow, sw.Gap = 0, time.Second })
	if a := r.call(n, "alice", "count", nil); a.status != http.StatusOK || strings.Count(string(a.body), "notifications/progress") != 1 {
		t.Fatalf("a silent stream: %d %s", a.status, a.body)
	}
	r.serving.Wait()
	r.c.IdleTimeout = 5 * time.Second
	r.mcp.Set(func(sw *stubs.ConnectorSwitches) { sw.Gap, sw.Endless = 0, true })
	ctx, cancel = context.WithCancel(context.Background())
	body, headers := rpc("tools/call", map[string]any{"name": "count"})
	req, err = http.NewRequestWithContext(ctx, http.MethodPost, r.srv.URL+address(n, "mcp"), strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer alice")
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err := r.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	closeBody(resp)
	deadline = time.Now().Add(5 * time.Second)
	for r.mcp.Left() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if r.mcp.Left() != 1 {
		t.Fatal("the connector's request outlived its caller")
	}
	got = r.calls(n)
	if len(got) != 3 || got[0].Outcome != OutcomeTimeout || got[1].Outcome != OutcomeTimeout || got[2].Outcome != OutcomeCanceled {
		t.Fatalf("records %+v", got)
	}
}

// A scope challenge of an oauth connection is 409 with scope_insufficient
// and the scopes, and the connection's state does not change; for a key it
// passes as the connector gave it.
func TestInsufficientScope(t *testing.T) {
	r := newRig(t, false)
	c, _ := r.signedIn(time.Now().Add(time.Hour))
	r.api.Insufficient([]string{"repo", "workflow"})
	a := r.send(http.MethodGet, address(c, "http")+"/user", "alice", nil)
	scopes, _ := a.detail("scopes").([]any)
	if a.status != http.StatusConflict || a.detail("reason") != "scope_insufficient" || len(scopes) != 2 || a.detail("state") != "connected" {
		t.Fatalf("%d %s", a.status, a.body)
	}
	if row, _ := r.st.Connections().Get(t.Context(), c.ID); row.State != store.StateConnected {
		t.Fatalf("the state moved: %s", row.State)
	}
	k := r.keyed()
	if a := r.send(http.MethodGet, address(k, "http")+"/user", "alice", nil); a.status != http.StatusForbidden || a.header.Get("WWW-Authenticate") != "" {
		t.Fatalf("a key's 403: %d %v", a.status, a.header)
	}
	if got := r.calls(c); len(got) != 1 || got[0].Outcome != OutcomeUpstreamRefused {
		t.Fatalf("records %+v", got)
	}
	if scopes, ok := insufficientScope([]string{`Bearer error="insufficient_scope"`}); !ok || len(scopes) != 0 {
		t.Fatalf("a challenge with no scope: %v %v", scopes, ok)
	}

	// The same at the MCP address.
	n, _ := r.signedInTo("notes-signed", "bob", time.Now().Add(time.Hour))
	r.mcp.Set(func(sw *stubs.ConnectorSwitches) { sw.Insufficient = []string{"notes:write"} })
	a = r.call(n, "bob", "create_note", nil)
	scopes, _ = a.detail("scopes").([]any)
	if a.status != http.StatusConflict || a.detail("reason") != "scope_insufficient" || len(scopes) != 1 || scopes[0] != "notes:write" {
		t.Fatalf("a scope challenge at the MCP address: %d %s", a.status, a.body)
	}
	if row, _ := r.st.Connections().Get(t.Context(), n.ID); row.State != store.StateConnected {
		t.Fatalf("the state moved: %s", row.State)
	}
	nk := r.noted()
	if a := r.list(nk, "alice"); a.status != http.StatusForbidden || a.header.Get("WWW-Authenticate") != "" {
		t.Fatalf("a key's 403 at the MCP address: %d %v", a.status, a.header)
	}
	if got := r.calls(n); len(got) != 1 || got[0].Outcome != OutcomeUpstreamRefused {
		t.Fatalf("records %+v", got)
	}
}

// A stream that goes silent past the idle bound is cut and recorded
// timeout, with what it carried before.
func TestAnIdleStreamIsCut(t *testing.T) {
	r := newRig(t, false)
	c := r.keyed()
	r.c.IdleTimeout = 100 * time.Millisecond
	a := r.send(http.MethodGet, address(c, "http")+"/stream?chunks=3&gap=20ms", "alice", nil)
	if a.status != http.StatusOK || strings.Count(string(a.body), "data:") != 3 {
		t.Fatalf("a stream within the bound: %d %s", a.status, a.body)
	}
	a = r.send(http.MethodGet, address(c, "http")+"/stream?chunks=3&gap=1s", "alice", nil)
	if strings.Count(string(a.body), "data:") != 1 {
		t.Fatalf("a silent stream: %d %s", a.status, a.body)
	}
	got := r.calls(c)
	if len(got) != 2 || got[0].Outcome != OutcomeOK || got[1].Outcome != OutcomeTimeout || got[1].BytesOut == 0 || got[1].Status != http.StatusOK {
		t.Fatalf("records %+v", got)
	}
}

// A refresh before use that the token endpoint refuses is the call's 409,
// recorded upstream_refused, and the connection needs a reconnect.
func TestARefreshRefusedBeforeUse(t *testing.T) {
	r := newRig(t, false)
	c, _ := r.signedIn(time.Now().Add(10 * time.Second))
	r.auth.Set(func(sw *stubs.AuthSwitches) { sw.RefuseRefresh = true })
	a := r.send(http.MethodGet, address(c, "http")+"/user", "alice", nil)
	if a.status != http.StatusConflict || a.detail("reason") != store.ReasonRefreshRefused {
		t.Fatalf("%d %s", a.status, a.body)
	}
	if got := r.calls(c); len(got) != 1 || got[0].Outcome != OutcomeUpstreamRefused {
		t.Fatalf("records %+v", got)
	}
	if len(r.api.Requests()) != 0 {
		t.Fatal("a call whose refresh was refused reached the connector")
	}
}
