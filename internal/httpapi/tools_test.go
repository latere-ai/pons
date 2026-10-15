// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"net/http"
	"slices"
	"testing"

	"latere.ai/x/pons/authorizer"
	"latere.ai/x/pons/internal/apierr"
	"latere.ai/x/pons/internal/signin"
	"latere.ai/x/pons/test/stubs"
)

// toolsOf reads a list of tools by name.
func toolsOf(t testing.TB, a answer) map[string]map[string]any {
	t.Helper()
	out := map[string]map[string]any{}
	for _, item := range a.json(t)["items"].([]any) {
		m := item.(map[string]any)
		out[m["name"].(string)] = m
	}
	return out
}

// GET /connections/{id}/tools answers the tools the server lists through
// the connection, with the effect its connector's marks give each, to the
// owner, asking connection.read and recording no call; it is 404 to anyone
// else, and a connection of kind http has none.
func TestAConnectionsTools(t *testing.T) {
	h := newHarness(t)
	wiki := idOf(t, h.add("alice", "wiki", map[string]any{"type": "token"}))
	if a := h.do(http.MethodPatch, "/v1/connectors/"+wiki, "alice", map[string]any{"tools": map[string]any{"read_only": []string{"get_*", "search_*"}, "hidden": []string{"delete_*"}}}); a.status != http.StatusOK {
		t.Fatal(a.status)
	}
	con := idOf(t, h.connect("alice", wiki, "", "the-key-of-alice"))
	before, reached := len(h.authz.questions()), len(h.up.mcp.Requests())
	a := h.do(http.MethodGet, "/v1/connections/"+con+"/tools", "alice", nil)
	if a.status != http.StatusOK {
		t.Fatalf("%d %s", a.status, a.body)
	}
	tools := toolsOf(t, a)
	if len(tools) != len(stubs.ConnectorTools) {
		t.Fatalf("the list %v", tools)
	}
	for name, want := range map[string]struct {
		effect string
		hidden bool
	}{
		"search_notes": {"read", false}, "get_note": {"read", false}, "count": {"write", false},
		"create_note": {"write", false}, "delete_notebook": {"write", true},
	} {
		got := tools[name]
		if got["effect"] != want.effect || (got["hidden"] == true) != want.hidden || got["description"] == "" {
			t.Errorf("%s: %v", name, got)
		}
	}
	if q := h.authz.questions()[before:]; len(q) != 1 || q[0].Action != authorizer.ActionConnectionRead || q[0].Resource.ID != con {
		t.Fatalf("the list asked %+v", q)
	}
	sent := h.up.mcp.Requests()[reached:]
	if len(sent) != 1 || sent[0].RPC != "tools/list" || sent[0].Credential != "Bearer the-key-of-alice" {
		t.Fatalf("the server was sent %+v", sent)
	}
	if calls := h.do(http.MethodGet, "/v1/connections/"+con+"/calls", "alice", nil).json(t)["items"].([]any); len(calls) != 0 {
		t.Fatalf("the list recorded %v", calls)
	}
	// Anyone else reads no connection there.
	if a := h.do(http.MethodGet, "/v1/connections/"+con+"/tools", "bob", nil); a.status != http.StatusNotFound || a.code() != apierr.CodeConnectionNotFound {
		t.Fatalf("bob: %d %s", a.status, a.body)
	}
	if len(h.up.mcp.Requests()) != reached+1 {
		t.Fatal("bob's list reached the server")
	}
	// A connection of kind http has no tools, and one the server refuses
	// moves as a call's does.
	web := idOf(t, h.connect("alice", "api", "", "the-api-key-of-alice"))
	if a := h.do(http.MethodGet, "/v1/connections/"+web+"/tools", "alice", nil); a.status != http.StatusConflict || a.code() != apierr.CodeWrongKind {
		t.Fatalf("kind http: %d %s", a.status, a.body)
	}
	h.up.mcp.Set(func(sw *stubs.ConnectorSwitches) { sw.Refuse = []string{"Bearer the-key-of-alice"} })
	if a := h.do(http.MethodGet, "/v1/connections/"+con+"/tools", "alice", nil); a.status != http.StatusConflict || a.code() != apierr.CodeConnectionNotConnected || a.detail("reason") != "credential_refused" {
		t.Fatalf("a refused key: %d %s", a.status, a.body)
	}
	h.up.mcp.Set(func(sw *stubs.ConnectorSwitches) { *sw = stubs.ConnectorSwitches{} })
	if a := h.do(http.MethodGet, "/v1/connections/"+con+"/tools", "alice", nil); a.status != http.StatusConflict || a.detail("reason") != "credential_refused" {
		t.Fatalf("a connection that needs a new key: %d %s", a.status, a.body)
	}
}

// A connection of a server of an earlier revision lists its tools in the
// session its handshake opens, and ends it; one that signs people in lists
// them with its token; a server's error is the connector's.
func TestAConnectionsToolsAtEveryServer(t *testing.T) {
	h := newHarness(t)
	h.up.mcp.Set(func(sw *stubs.ConnectorSwitches) { sw.Legacy = true })
	legacy := idOf(t, h.add("alice", "legacy", nil))
	con := idOf(t, h.connect("alice", legacy, "", ""))
	if a := h.do(http.MethodGet, "/v1/connections/"+con+"/tools", "alice", nil); a.status != http.StatusOK || len(toolsOf(t, a)) != len(stubs.ConnectorTools) {
		t.Fatalf("an earlier revision: %d %s", a.status, a.body)
	}
	if h.up.mcp.Sessions() != 0 {
		t.Fatalf("the list left %d sessions open", h.up.mcp.Sessions())
	}
	h.up.mcp.Set(func(sw *stubs.ConnectorSwitches) {
		*sw = stubs.ConnectorSwitches{Servers: []string{h.up.auth.Issuer()}}
	})
	h.up.auth.Set(func(sw *stubs.AuthSwitches) { sw.CIMD = true })
	signed := idOf(t, h.add("alice", "signed", nil))
	signedCon, _, back := h.signIn(t, "alice", signed)
	if a := h.confirm(t, "alice", signedCon, back); a.status != http.StatusOK {
		t.Fatalf("the confirm: %d %s", a.status, a.body)
	}
	if a := h.do(http.MethodGet, "/v1/connections/"+signedCon+"/tools", "alice", nil); a.status != http.StatusOK || len(toolsOf(t, a)) != len(stubs.ConnectorTools) {
		t.Fatalf("a connection that signed in: %d %s", a.status, a.body)
	}
	got := h.up.mcp.Requests()
	if last := got[len(got)-1]; last.RPC != "tools/list" || last.Credential == "" {
		t.Fatalf("the list was sent as %+v", last)
	}
	h.up.mcp.Set(func(sw *stubs.ConnectorSwitches) { sw.Redirect = true })
	if a := h.do(http.MethodGet, "/v1/connections/"+signedCon+"/tools", "alice", nil); a.status != http.StatusBadGateway || a.code() != apierr.CodeConnectorUnavailable {
		t.Fatalf("a server that answers a redirect: %d %s", a.status, a.body)
	}
}

// An added server that signs people in by its client metadata document or
// a registration, and sends no iss, signs in at its issuer's own callback,
// which its document names; an answer at another issuer's is refused.
func TestAnAddedServerSignsIn(t *testing.T) {
	h := newHarness(t)
	h.signsIn()
	h.up.auth.Set(func(sw *stubs.AuthSwitches) { sw.IssSupported = false; sw.CIMD = true })
	own := "https://pons.example.com/v1/callback/" + signin.IssuerKey(h.up.auth.Issuer())
	added := h.add("alice", "wiki", nil)
	if added.status != http.StatusCreated || added.json(t)["auth"].(map[string]any)["client"] != signin.ClientByDocument {
		t.Fatalf("the add: %d %s", added.status, added.body)
	}
	wiki := idOf(t, added)
	doc := h.do(http.MethodGet, "/v1/client/"+wiki, "", nil).json(t)
	if uris := doc["redirect_uris"].([]any); len(uris) != 1 || uris[0] != own || doc["client_id"] != "https://pons.example.com/v1/client/"+wiki {
		t.Fatalf("the document %v", doc)
	}
	con, landed, back := h.signIn(t, "alice", wiki)
	if landed.String() != own+"?"+landed.RawQuery || back.Query().Get("code") == "" {
		t.Fatalf("the sign-in came back at %s and went on to %s", landed, back)
	}
	if a := h.confirm(t, "alice", con, back); a.status != http.StatusOK || a.json(t)["state"] != "connected" {
		t.Fatalf("the confirm: %d %s", a.status, a.body)
	}
	if a := h.callTool("alice", con, "get_note"); a.status != http.StatusOK {
		t.Fatalf("a call: %d %s", a.status, a.body)
	}
	// An answer at another issuer's address goes nowhere.
	started := h.do(http.MethodPost, "/v1/connections", "alice", map[string]any{"connector": wiki, "name": "again", "return_to": "https://app.example.com/done"})
	landed = authorize(t, started.json(t)["authorization_url"].(string))
	landed.Path = "/v1/callback/" + signin.IssuerKey("https://elsewhere.example.net")
	tokens := h.tokenRequests()
	if back := h.callback(t, landed); back.Query().Get("error") != "sign_in_failed" || h.tokenRequests() != tokens {
		t.Fatalf("an answer at another issuer's address went on to %s", back)
	}
	// A registration names the same address, and a reconnect signs in
	// there again.
	h.up.auth.Set(func(sw *stubs.AuthSwitches) { sw.CIMD = false })
	registered := h.add("alice", "registered", nil)
	if registered.json(t)["auth"].(map[string]any)["client"] != signin.ClientRegistered {
		t.Fatalf("the add: %s", registered.body)
	}
	con, landed, back = h.signIn(t, "alice", idOf(t, registered))
	if landed.Path != "/v1/callback/"+signin.IssuerKey(h.up.auth.Issuer()) || h.confirm(t, "alice", con, back).status != http.StatusOK {
		t.Fatalf("a registered sign-in came back at %s", landed)
	}
	again := h.do(http.MethodPost, "/v1/connections/"+con+"/reconnect", "alice", map[string]any{"return_to": "https://app.example.com/done"})
	if again.status != http.StatusOK {
		t.Fatalf("a reconnect: %d %s", again.status, again.body)
	}
	if landed, back = h.browser(t, again.json(t)["authorization_url"].(string)); !slices.Contains([]string{own}, landed.Scheme+"://"+landed.Host+landed.Path) || h.confirm(t, "alice", con, back).status != http.StatusOK {
		t.Fatalf("the reconnect came back at %s", landed)
	}
}
