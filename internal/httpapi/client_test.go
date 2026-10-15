// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"net/http"
	"testing"

	"latere.ai/x/pons/catalog"
)

// GET /client serves the document with its own address as client_id, one
// redirect address and token_endpoint_auth_method none, and client_uri only
// when it is set; GET /client/{id} serves an added connector's own, whose
// client_name names its title, and 404 for any other id.
func TestClientMetadataDocument(t *testing.T) {
	h := newHarness(t)
	a := h.do(http.MethodGet, "/v1/client", "", nil)
	doc := a.json(t)
	if a.status != http.StatusOK || doc["client_id"] != "https://pons.example.com/v1/client" || doc["client_name"] != "Pons" ||
		doc["token_endpoint_auth_method"] != "none" || len(doc["redirect_uris"].([]any)) != 1 ||
		doc["redirect_uris"].([]any)[0] != "https://pons.example.com/v1/callback" || doc["client_uri"] != nil ||
		a.header.Get("Cache-Control") != "public, max-age=3600" {
		t.Fatalf("%d %v %v", a.status, doc, a.header)
	}
	hold(t, http.MethodGet, "/client", a)
	h.srv.Signin.ClientURI = "https://www.example.com"
	if got := h.do(http.MethodGet, "/v1/client", "", nil).json(t)["client_uri"]; got != "https://www.example.com" {
		t.Fatalf("client_uri %v", got)
	}
	ctr := idOf(t, h.do(http.MethodPost, "/v1/connectors", "alice", map[string]any{
		"name": "wiki", "title": "Team wiki", "kind": "mcp", "url": addedURL, "auth": map[string]any{"type": "none"},
	}))
	a = h.do(http.MethodGet, "/v1/client/"+ctr, "", nil)
	if doc := a.json(t); a.status != http.StatusOK || doc["client_id"] != "https://pons.example.com/v1/client/"+ctr || doc["client_name"] != "Pons for Team wiki" {
		t.Fatalf("%d %v", a.status, doc)
	}
	hold(t, http.MethodGet, "/client/"+ctr, a)
	a = h.do(http.MethodGet, "/v1/client/ctr_01jb2m7c0p5d8f2h6j9k3m4n7q", "", nil)
	if a.status != http.StatusNotFound || a.code() != "connector_not_found" {
		t.Fatalf("another id: %d %s", a.status, a.body)
	}
	hold(t, http.MethodGet, "/client/ctr_01jb2m7c0p5d8f2h6j9k3m4n7q", a)
	// The callback answers a page with no redirect for a state no flow has.
	a = h.do(http.MethodGet, "/v1/callback?state=none", "", nil)
	if a.status != http.StatusBadRequest || a.header.Get("Location") != "" || a.header.Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("a callback with no flow: %d %v", a.status, a.header)
	}
}

// The sign-in's routes refuse what they do not take: a reconnect of a key,
// of a connection whose connector left, and of an added connector; a
// return_to that is missing or not listed; a confirm with no code or no
// flow; and a connect whose discovery fails.
func TestSignInRoutesRefuse(t *testing.T) {
	h := newHarness(t)
	key := idOf(t, h.connect("alice", "search", "", "the-key-of-alice"))
	if a := h.do(http.MethodPost, "/v1/connections/"+key+"/reconnect", "alice", map[string]any{"return_to": "https://app.example.com/done"}); a.code() != "wrong_kind" {
		t.Fatalf("a reconnect of a key: %d %s", a.status, a.body)
	}
	for body, field := range map[string]string{`{}`: "return_to", `{"return_to": "https://elsewhere.example.net/"}`: "return_to"} {
		if a := h.do(http.MethodPost, "/v1/connections/"+key+"/reconnect", "alice", body); a.status != http.StatusBadRequest || a.detail("field") != field {
			t.Fatalf("%s: %d %s", body, a.status, a.body)
		}
	}
	if a := h.do(http.MethodPost, "/v1/connections/"+key+"/reconnect", "alice", `{"nonsense": 1}`); a.status != http.StatusBadRequest {
		t.Fatalf("an unknown member: %d %s", a.status, a.body)
	}
	started := h.do(http.MethodPost, "/v1/connections", "alice", map[string]any{"connector": "code", "return_to": "https://app.example.com/done"}).json(t)
	signed := started["connection"].(map[string]any)["id"].(string)
	if a := h.do(http.MethodPost, "/v1/connections/"+signed+"/reconnect", "alice", map[string]any{"return_to": "https://app.example.com/done", "scopes": []string{"more"}}); a.status != http.StatusOK {
		t.Fatalf("a reconnect of a pending connection: %d %s", a.status, a.body)
	}
	for body, code := range map[string]string{`{}`: "missing_field", `{"code": "x"}`: "connection_not_connected", `{"x": 1}`: "unknown_field"} {
		if a := h.do(http.MethodPost, "/v1/connections/"+signed+"/confirm", "alice", body); a.code() != code {
			t.Fatalf("%s: %d %s", body, a.status, a.body)
		}
	}
	if err := h.store.Flows().Delete(t.Context(), signed); err != nil {
		t.Fatal(err)
	}
	if a := h.do(http.MethodPost, "/v1/connections/"+signed+"/confirm", "alice", map[string]any{"code": "x"}); a.code() != "flow_expired" {
		t.Fatalf("no flow: %d %s", a.status, a.body)
	}
	// A connector that left the catalog.
	code, _ := h.srv.Catalog.Get("code")
	h.srv.Catalog.Connectors = slicesDelete(h.srv.Catalog.Connectors, "code")
	if a := h.do(http.MethodPost, "/v1/connections/"+signed+"/reconnect", "alice", map[string]any{"return_to": "https://app.example.com/done"}); a.detail("reason") != "connector_removed" {
		t.Fatalf("a connector that left: %d %s", a.status, a.body)
	}
	h.srv.Catalog.Connectors = append(h.srv.Catalog.Connectors, code)
	// A discovery that fails.
	if a := h.do(http.MethodPost, "/v1/connections", "alice", map[string]any{"connector": "tracker", "return_to": "https://app.example.com/done"}); a.code() != "connector_unreachable" {
		t.Fatalf("an unreachable issuer: %d %s", a.status, a.body)
	}
	// An added connector whose people sign in waits for its discovery.
	ctr := idOf(t, h.do(http.MethodPost, "/v1/connectors", "alice", map[string]any{
		"name": "wiki", "title": "Wiki", "kind": "mcp", "url": addedURL, "auth": map[string]any{"type": "none"},
	}))
	added, err := h.store.Connectors().Get(t.Context(), ctr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fromRow(added); err != nil {
		t.Fatal(err)
	}
	if a := h.do(http.MethodPost, "/v1/connections/con_01jb2m6x8q3v7k9n4w5t0zr1ya/reconnect", "alice", map[string]any{"return_to": "https://app.example.com/done"}); a.status != http.StatusNotFound {
		t.Fatalf("no connection: %d %s", a.status, a.body)
	}
	// A repeat of a connect whose sign-in was confirmed answers the
	// connection.
	first := h.do(http.MethodPost, "/v1/connections", "bob", map[string]any{"connector": "code", "return_to": "https://app.example.com/done"}, "Idempotency-Key", "k").json(t)
	id := first["connection"].(map[string]any)["id"].(string)
	if err := h.store.Connections().Move(t.Context(), id, "pending", "connected", ""); err != nil {
		t.Fatal(err)
	}
	again := h.do(http.MethodPost, "/v1/connections", "bob", map[string]any{"connector": "code", "return_to": "https://app.example.com/done"}, "Idempotency-Key", "k")
	if again.status != http.StatusCreated || again.json(t)["id"] != id {
		t.Fatalf("a repeat after the confirm: %d %s", again.status, again.body)
	}
}

// slicesDelete is the connectors without the one of a name.
func slicesDelete(cs []catalog.Connector, name string) []catalog.Connector {
	var out []catalog.Connector
	for _, c := range cs {
		if c.Name != name {
			out = append(out, c)
		}
	}
	return out
}
