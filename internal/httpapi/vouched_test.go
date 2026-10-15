// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strings"
	"testing"

	"latere.ai/x/pons/internal/apierr"
	"latere.ai/x/pons/internal/signin"
	"latere.ai/x/pons/internal/store"
	"latere.ai/x/pons/internal/store/memory"
	"latere.ai/x/pons/test/stubs"
)

// The client of the vouched-for server at the stub authorization server,
// whose secrets are the canary.
const (
	vouchedClient = "wiki-client"
	canary        = "canary-vouched-3b8e71"
)

// auth.client is taken from an add the authorizer vouched for alone; its
// secret is sealed bound to its connector and token endpoint, sent at the
// token request, rotated by an edit, and answered nowhere; vouching changes
// no other rule, so a vouched-for server that sends no iss signs in at its
// issuer's own callback.
func TestOnlyAVouchedForConnectorTakesAClient(t *testing.T) {
	h := newHarness(t)
	h.authz.set(orgPolicy)
	h.signsIn()
	secret := canary + "-secret"
	h.up.auth.AddClient(vouchedClient, secret)
	var seen bytes.Buffer
	do := func(method, path, bearer string, body any) answer {
		t.Helper()
		a := h.do(method, path, bearer, body)
		seen.Write(a.body)
		for k, v := range a.header {
			seen.WriteString(k + ": " + strings.Join(v, ",") + "\n")
		}
		return a
	}
	add := func(bearer, name string, auth map[string]any) answer {
		t.Helper()
		return do(http.MethodPost, "/v1/connectors", bearer, map[string]any{"name": name, "title": "Wiki", "kind": "mcp", "url": addedURL, "auth": auth})
	}
	client := func(id, secret string) map[string]any { return map[string]any{"id": id, "secret": secret} }

	a := add("admin", "wiki", map[string]any{"type": "oauth", "client": client(vouchedClient, secret)})
	if a.status != http.StatusCreated {
		t.Fatalf("a vouched-for add: %d %s", a.status, a.body)
	}
	view := a.json(t)
	auth := view["auth"].(map[string]any)
	if view["vouched"] != true || auth["client"] != signin.ClientOwn || auth["redirect_uri"] != "https://pons.example.com/v1/callback" || auth["client_id"] != nil {
		t.Fatalf("the view %v", view)
	}
	wiki := view["id"].(string)
	row, err := h.store.Connectors().Get(context.Background(), wiki)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := h.srv.Sealer.Open(row.ClientSecret, store.ConnectorClientBinding(wiki, h.up.auth.TokenURL()))
	if err != nil || string(opened) != secret {
		t.Fatalf("the secret does not open under its connector and token endpoint: %v", err)
	}
	if _, err := h.srv.Sealer.Open(row.ClientSecret, store.ConnectorClientBinding("ctr_another", h.up.auth.TokenURL())); err == nil {
		t.Fatal("the secret opens for another connector")
	}

	// The sign-in identifies itself by the client, and its secret goes to
	// the token endpoint.
	con, landed, back := h.signIn(t, "alice", wiki)
	if landed.Path != "/v1/callback" || back.Query().Get("code") == "" {
		t.Fatalf("the sign-in came back at %s and went on to %s", landed, back)
	}
	if a := h.confirm(t, "alice", con, back); a.status != http.StatusOK || a.json(t)["state"] != "connected" {
		t.Fatalf("the confirm: %d %s", a.status, a.body)
	}
	var exchange stubs.AuthRequest
	for _, q := range h.up.auth.Requests() {
		if q.Path == "/token" {
			exchange = q
		}
	}
	if exchange.ClientID != vouchedClient || !exchange.Basic || exchange.Form.Get("redirect_uri") != "https://pons.example.com/v1/callback" {
		t.Fatalf("the code was exchanged as %+v", exchange)
	}
	if a := h.callTool("alice", con, "get_note"); a.status != http.StatusOK {
		t.Fatalf("a call: %d %s", a.status, a.body)
	}

	// An edit rotates the secret, and never changes the client's id.
	rotated := canary + "-rotated"
	if a := do(http.MethodPatch, "/v1/connectors/"+wiki, "admin", map[string]any{"auth": map[string]any{"client": map[string]any{"id": vouchedClient, "secret": rotated}}}); a.status != http.StatusOK {
		t.Fatalf("a rotation: %d %s", a.status, a.body)
	}
	if row, err = h.store.Connectors().Get(context.Background(), wiki); err != nil {
		t.Fatal(err)
	}
	if opened, err := h.srv.Sealer.Open(row.ClientSecret, store.ConnectorClientBinding(wiki, h.up.auth.TokenURL())); err != nil || string(opened) != rotated {
		t.Fatalf("the rotated secret: %v", err)
	}
	if a := do(http.MethodPatch, "/v1/connectors/"+wiki, "admin", map[string]any{"auth": map[string]any{"client": map[string]any{"secret": "short"}}}); a.code() != apierr.CodeInvalidField || a.detail("field") != "auth.client.secret" {
		t.Fatalf("a short secret: %d %s", a.status, a.body)
	}

	// A person's add, nobody vouched for, takes no client.
	if a := add("alice", "mine", map[string]any{"type": "oauth", "client": client(vouchedClient, secret)}); a.status != http.StatusBadRequest || a.code() != apierr.CodeUnknownField || a.detail("field") != "auth.client" {
		t.Fatalf("an add nobody vouched for: %d %s", a.status, a.body)
	}
	for _, tc := range []struct {
		auth        map[string]any
		code, field string
	}{
		{map[string]any{"type": "token", "client": client(vouchedClient, secret)}, apierr.CodeInvalidField, "auth.client"},
		{map[string]any{"type": "oauth", "client": map[string]any{"secret": secret}}, apierr.CodeMissingField, "auth.client.id"},
		{map[string]any{"type": "oauth", "client": map[string]any{"id": vouchedClient}}, apierr.CodeMissingField, "auth.client.secret"},
		{map[string]any{"type": "oauth", "client": client(vouchedClient, "short")}, apierr.CodeInvalidField, "auth.client.secret"},
	} {
		if a := add("admin", "other", tc.auth); a.code() != tc.code || a.detail("field") != tc.field {
			t.Errorf("%v: %d %s", tc.auth, a.status, a.body)
		}
	}
	h.up.mcp.Set(func(sw *stubs.ConnectorSwitches) { *sw = stubs.ConnectorSwitches{} })
	if a := do(http.MethodPost, "/v1/connectors", "admin", map[string]any{
		"name": "open", "title": "Open", "kind": "mcp", "url": addedURL, "auth": map[string]any{"client": client(vouchedClient, secret), "type": "oauth"},
	}); a.code() != apierr.CodeAuthMismatch {
		t.Fatalf("a client for a server that signs nobody in: %d %s", a.status, a.body)
	}
	if a := do(http.MethodPost, "/v1/connectors", "admin", map[string]any{
		"name": "open", "title": "Open", "kind": "mcp", "url": addedURL, "auth": map[string]any{"client": client(vouchedClient, secret), "type": "token"},
	}); a.code() != apierr.CodeInvalidField {
		t.Fatalf("a client of a key: %d %s", a.status, a.body)
	}

	// Vouching changes no other rule: a vouched-for server whose
	// authorization server sends no iss signs in at its issuer's own
	// callback, and an answer at the shared one is refused.
	h.signsIn()
	h.up.auth.Set(func(sw *stubs.AuthSwitches) { sw.IssSupported = false })
	noIss := add("admin", "no-iss", map[string]any{"type": "oauth", "client": client(vouchedClient, secret)})
	own := "https://pons.example.com/v1/callback/" + signin.IssuerKey(h.up.auth.Issuer())
	if noIss.status != http.StatusCreated || noIss.json(t)["auth"].(map[string]any)["redirect_uri"] != own {
		t.Fatalf("a vouched-for server that sends no iss: %d %s", noIss.status, noIss.body)
	}
	con, landed, back = h.signIn(t, "alice", idOf(t, noIss))
	if landed.String() != own+"?"+landed.RawQuery || back.Query().Get("code") == "" {
		t.Fatalf("the sign-in came back at %s and went on to %s", landed, back)
	}
	if a := h.confirm(t, "alice", con, back); a.status != http.StatusOK {
		t.Fatalf("the confirm: %d %s", a.status, a.body)
	}
	started := do(http.MethodPost, "/v1/connections", "alice", map[string]any{"connector": idOf(t, noIss), "name": "again", "return_to": "https://app.example.com/done"})
	shared := *authorize(t, started.json(t)["authorization_url"].(string))
	shared.Path = "/v1/callback"
	tokens := h.tokenRequests()
	if back := h.callback(t, &shared); back.Query().Get("error") != "sign_in_failed" || h.tokenRequests() != tokens {
		t.Fatalf("an answer at the shared callback went on to %s", back)
	}

	// The secret is in no answer, header, log line, or value the store
	// holds in the clear.
	dump := string(h.store.(*memory.Store).Dump())
	everything := seen.String() + h.logText() + dump
	for _, value := range []string{secret, rotated} {
		for _, form := range []string{value, hex.EncodeToString([]byte(value)), base64.StdEncoding.EncodeToString([]byte(value)), base64.RawURLEncoding.EncodeToString([]byte(value))} {
			if strings.Contains(everything, form) {
				t.Fatalf("a client secret appears as %q", form)
			}
		}
	}
	if !strings.Contains(dump, wiki) {
		t.Fatal("the dump does not hold the connector, so it proves nothing")
	}
}

// tokenRequests counts the stub authorization server's token requests.
func (h *harness) tokenRequests() int {
	n := 0
	for _, q := range h.up.auth.Requests() {
		if q.Path == "/token" {
			n++
		}
	}
	return n
}
