// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"latere.ai/x/pons/authorizer"
	"latere.ai/x/pons/internal/apierr"
	"latere.ai/x/pons/internal/store"
	"latere.ai/x/pons/internal/store/memory"
	"latere.ai/x/pons/test/stubs"
)

// signsIn makes the stub connector a protected resource at the stub
// authorization server, so an add finds that it signs people in.
func (h *harness) signsIn() {
	h.up.mcp.Set(func(sw *stubs.ConnectorSwitches) { sw.Servers = []string{h.up.auth.Issuer()} })
}

// PATCH changes each changeable member, holds the next sign-in to new
// scopes, answers 400 immutable_field for a member that never changes and
// takes one named with its stored value, and asks connector.update with
// the connector's id and owner.
func TestAnEditChangesWhatMayChange(t *testing.T) {
	h := newHarness(t)
	h.authz.set(orgPolicy)
	h.signsIn()
	added := h.add("admin", "wiki", nil)
	if added.status != http.StatusCreated || added.json(t)["auth"].(map[string]any)["type"] != "oauth" {
		t.Fatalf("the add: %d %s", added.status, added.body)
	}
	wiki := idOf(t, added)
	path := "/v1/connectors/" + wiki
	before := len(h.authz.questions())
	a := h.do(http.MethodPatch, path, "admin", map[string]any{
		"title": "Team wiki", "description": "The team's notes.", "icon": "https://mcp.example.com/icon.svg",
		"tools": map[string]any{"read_only": []string{"get_*", "search_*"}, "hidden": []string{"delete_*"}},
		"auth":  map[string]any{"scopes": []string{"notes:read"}},
		"name":  "wiki", "kind": "mcp", "url": addedURL,
	})
	if a.status != http.StatusOK {
		t.Fatalf("an edit: %d %s", a.status, a.body)
	}
	got := a.json(t)
	tools := got["tools"].(map[string]any)
	if got["title"] != "Team wiki" || got["description"] != "The team's notes." || got["icon"] != "https://mcp.example.com/icon.svg" ||
		len(tools["read_only"].([]any)) != 2 || tools["hidden"].([]any)[0] != "delete_*" ||
		got["auth"].(map[string]any)["scopes"].([]any)[0] != "notes:read" || got["connections"] != float64(0) || got["disabled"] != false {
		t.Fatalf("the edit answered %v", got)
	}
	if q := h.asked(before, authorizer.ActionConnectorUpdate); len(q) != 1 || q[0].Resource.ID != wiki || q[0].Resource.String(authorizer.FieldOwner) != orgOwner {
		t.Fatalf("the edit asked %+v", q)
	}
	if read := h.do(http.MethodGet, path, "alice", nil).json(t); read["title"] != "Team wiki" {
		t.Fatalf("a read after the edit: %v", read)
	}
	// The next sign-in asks for the new scopes.
	started := h.do(http.MethodPost, "/v1/connections", "alice", map[string]any{"connector": wiki, "return_to": "https://app.example.com/done"})
	if started.status != http.StatusCreated {
		t.Fatalf("a connect: %d %s", started.status, started.body)
	}
	address, err := url.Parse(started.json(t)["authorization_url"].(string))
	if err != nil || !strings.Contains(address.Query().Get("scope"), "notes:read") {
		t.Fatalf("the sign-in asks for %q", address.Query().Get("scope"))
	}
	// A member that never changes.
	for field, body := range map[string]map[string]any{
		"name":           {"name": "other"},
		"kind":           {"kind": "http"},
		"url":            {"url": "https://other.example.com/mcp"},
		"auth.type":      {"auth": map[string]any{"type": "token"}},
		"auth.client.id": {"auth": map[string]any{"client": map[string]any{"id": "another-client"}}},
	} {
		a := h.do(http.MethodPatch, path, "admin", body)
		if a.status != http.StatusBadRequest || a.code() != apierr.CodeImmutableField || a.detail("field") != field {
			t.Errorf("%s: %d %s", field, a.status, a.body)
		}
	}
	// What an edit holds a member to.
	for _, tc := range []struct {
		body        map[string]any
		code, field string
	}{
		{map[string]any{"title": ""}, apierr.CodeInvalidField, "title"},
		{map[string]any{"icon": "http://mcp.example.com/icon.svg"}, apierr.CodeInvalidField, "icon"},
		{map[string]any{"tools": map[string]any{"hidden": []string{""}}}, apierr.CodeInvalidField, "tools.hidden"},
		{map[string]any{"auth": map[string]any{"hint": "A key"}}, apierr.CodeUnknownField, "hint"},
		{map[string]any{"owner": "someone"}, apierr.CodeUnknownField, "owner"},
		{map[string]any{"auth": map[string]any{"client": map[string]any{"secret": "a-rotated-secret"}}}, apierr.CodeInvalidField, "auth.client.secret"},
	} {
		a := h.do(http.MethodPatch, path, "admin", tc.body)
		if a.code() != tc.code || a.detail("field") != tc.field {
			t.Errorf("%v: %d %s", tc.body, a.status, a.body)
		}
	}
	// Who may not change it, and what no edit reaches.
	if a := h.do(http.MethodPatch, path, "alice", map[string]any{"title": "Mine"}); a.status != http.StatusNotFound || a.code() != apierr.CodeConnectorNotFound {
		t.Fatalf("a member's edit: %d %s", a.status, a.body)
	}
	for _, ref := range []string{"search", "ctr_01jb2m7c0p5d8f2h6j9k3m4n7q"} {
		if a := h.do(http.MethodPatch, "/v1/connectors/"+ref, "admin", map[string]any{"title": "X"}); a.status != http.StatusNotFound {
			t.Fatalf("%s: %d %s", ref, a.status, a.body)
		}
	}
	// A connector that takes a key takes no scopes, and one nobody vouched
	// for takes no client.
	mine := idOf(t, h.add("alice", "mine", map[string]any{"type": "token"}))
	if a := h.do(http.MethodPatch, "/v1/connectors/"+mine, "alice", map[string]any{"auth": map[string]any{"scopes": []string{"x"}}}); a.code() != apierr.CodeInvalidField || a.detail("field") != "auth.scopes" {
		t.Fatalf("scopes of a key: %d %s", a.status, a.body)
	}
	if a := h.do(http.MethodPatch, "/v1/connectors/"+mine, "alice", map[string]any{"auth": map[string]any{"client": map[string]any{"secret": "a-client-secret"}}}); a.code() != apierr.CodeUnknownField || a.detail("field") != "auth.client" {
		t.Fatalf("a client of a person's add: %d %s", a.status, a.body)
	}
	if a := h.do(http.MethodPatch, "/v1/connectors/"+mine, "alice", map[string]any{"auth": map[string]any{"type": "token"}, "description": "Mine."}); a.status != http.StatusOK || a.json(t)["description"] != "Mine." {
		t.Fatalf("an edit naming its type as it is: %d %s", a.status, a.body)
	}
}

// A changed tool mark holds the next call on a second replica, which reads
// the connector from the store at the request, with no restart.
func TestAnEditHoldsTheNextCallOnEveryReplica(t *testing.T) {
	st := memory.New(memory.Options{})
	one, two := newHarnessOn(t, st), newHarnessOn(t, st)
	wiki := idOf(t, one.add("alice", "wiki", map[string]any{"type": "token"}))
	con := idOf(t, one.connect("alice", wiki, "", "the-key-of-alice"))
	if a := two.callTool("alice", con, "delete_notebook"); a.status != http.StatusOK {
		t.Fatalf("a call before the edit: %d %s", a.status, a.body)
	}
	if a := one.do(http.MethodPatch, "/v1/connectors/"+wiki, "alice", map[string]any{"tools": map[string]any{"hidden": []string{"delete_*"}}}); a.status != http.StatusOK {
		t.Fatalf("the edit: %d %s", a.status, a.body)
	}
	reached := len(two.up.mcp.Requests())
	if a := two.callTool("alice", con, "delete_notebook"); a.status != http.StatusForbidden || a.detail("field") != "tool" || a.detail("reason") != "hidden" {
		t.Fatalf("a call after the edit on the other replica: %d %s", a.status, a.body)
	}
	if len(two.up.mcp.Requests()) != reached {
		t.Fatal("the call the edit refused reached the server")
	}
	if a := two.do(http.MethodGet, "/v1/connections/"+con, "alice", nil).json(t); a["tools"].(map[string]any)["hidden"].([]any)[0] != "delete_*" {
		t.Fatalf("the other replica shows the connection's marks as %v", a["tools"])
	}
	if a := two.callTool("alice", con, "get_note"); a.status != http.StatusOK {
		t.Fatalf("a call the edit leaves: %d %s", a.status, a.body)
	}
}

// A connector turned off stays listed, refuses a connect and a call with
// their reasons, keeps its connections and their credentials, is not
// removed while used, and serves them again when turned on.
func TestTurningAConnectorOffAndOn(t *testing.T) {
	h := newHarness(t)
	wiki := idOf(t, h.add("alice", "wiki", map[string]any{"type": "token"}))
	con := idOf(t, h.connect("alice", wiki, "", "the-key-of-alice"))
	ctx := context.Background()
	_, version, err := h.store.Credentials().Get(ctx, con)
	if err != nil {
		t.Fatal(err)
	}
	off := h.do(http.MethodPatch, "/v1/connectors/"+wiki, "alice", map[string]any{"disabled": true})
	if off.status != http.StatusOK || off.json(t)["disabled"] != true || off.json(t)["connections"] != float64(1) {
		t.Fatalf("turning it off: %d %s", off.status, off.body)
	}
	if item := itemOf(t, h.do(http.MethodGet, "/v1/connectors", "alice", nil), wiki); item["disabled"] != true {
		t.Fatalf("listed as %v", item)
	}
	if a := h.connect("alice", wiki, "again", "the-key-of-alice"); a.status != http.StatusConflict || a.code() != apierr.CodeConnectorDisabled || a.detail("field") != "connector" {
		t.Fatalf("a connect: %d %s", a.status, a.body)
	}
	reached := len(h.up.mcp.Requests())
	notConnected := func(what string, a answer) {
		t.Helper()
		if a.status != http.StatusConflict || a.code() != apierr.CodeConnectionNotConnected || a.detail("reason") != "connector_disabled" || a.detail("state") != "connected" {
			t.Fatalf("%s: %d %s", what, a.status, a.body)
		}
	}
	notConnected("a call", h.callTool("alice", con, "get_note"))
	notConnected("a list of tools", h.do(http.MethodGet, "/v1/connections/"+con+"/tools", "alice", nil))
	if a := h.do(http.MethodPut, "/v1/connections/"+con+"/credential", "alice", map[string]any{"credential": map[string]any{"value": "a-new-key-of-alice"}}); a.code() != apierr.CodeConnectorDisabled {
		t.Fatalf("a new key: %d %s", a.status, a.body)
	}
	if len(h.up.mcp.Requests()) != reached {
		t.Fatal("a request through a connector turned off reached its server")
	}
	if a := h.do(http.MethodDelete, "/v1/connectors/"+wiki, "alice", nil); a.status != http.StatusConflict || a.code() != apierr.CodeConnectorInUse {
		t.Fatalf("a removal while used: %d %s", a.status, a.body)
	}
	if a := h.do(http.MethodGet, "/v1/connections/"+con, "alice", nil); a.status != http.StatusOK || a.json(t)["state"] != "connected" {
		t.Fatalf("the connection: %d %s", a.status, a.body)
	}
	if _, kept, err := h.store.Credentials().Get(ctx, con); err != nil || kept != version {
		t.Fatalf("the credential is at version %d, was %d: %v", kept, version, err)
	}
	on := h.do(http.MethodPatch, "/v1/connectors/"+wiki, "alice", map[string]any{"disabled": false})
	if on.status != http.StatusOK || on.json(t)["disabled"] != false {
		t.Fatalf("turning it on: %d %s", on.status, on.body)
	}
	if a := h.callTool("alice", con, "get_note"); a.status != http.StatusOK {
		t.Fatalf("a call once it is on: %d %s", a.status, a.body)
	}
	if got := h.up.mcp.Credentials(); got[len(got)-1] != "Bearer the-key-of-alice" {
		t.Fatalf("the call carried %q", got[len(got)-1])
	}
	if a := h.do(http.MethodDelete, "/v1/connections/"+con, "alice", nil); a.status != http.StatusNoContent {
		t.Fatalf("a disconnect: %d %s", a.status, a.body)
	}
	if a := h.do(http.MethodDelete, "/v1/connectors/"+wiki, "alice", nil); a.status != http.StatusNoContent {
		t.Fatalf("a removal once unused: %d %s", a.status, a.body)
	}
}

// A connector turned off refuses a reconnect of a connection that signs
// in, and keeps its pending flow and its credential.
func TestATurnedOffConnectorRefusesAReconnect(t *testing.T) {
	h := newHarness(t)
	h.signsIn()
	h.up.auth.Set(func(sw *stubs.AuthSwitches) { sw.CIMD = true })
	wiki := idOf(t, h.add("alice", "wiki", nil))
	con, _, back := h.signIn(t, "alice", wiki)
	if a := h.confirm(t, "alice", con, back); a.status != http.StatusOK {
		t.Fatalf("the confirm: %d %s", a.status, a.body)
	}
	if a := h.do(http.MethodPatch, "/v1/connectors/"+wiki, "alice", map[string]any{"disabled": true}); a.status != http.StatusOK {
		t.Fatal(a.status)
	}
	if a := h.do(http.MethodPost, "/v1/connections/"+con+"/reconnect", "alice", map[string]any{"return_to": "https://app.example.com/done"}); a.status != http.StatusConflict || a.code() != apierr.CodeConnectorDisabled {
		t.Fatalf("a reconnect: %d %s", a.status, a.body)
	}
	if _, _, err := h.store.Credentials().Get(context.Background(), con); err != nil {
		t.Fatalf("the credential: %v", err)
	}
	if rows, _, err := h.store.Connectors().List(context.Background(), []string{subject("alice")}, store.Page{}); err != nil || len(rows) != 1 || !rows[0].Disabled {
		t.Fatalf("the connector %+v %v", rows, err)
	}
	if !slices.Contains(ids(t, h.do(http.MethodGet, "/v1/connections", "alice", nil)), con) {
		t.Fatal("the connection is gone")
	}
}
