// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"latere.ai/x/pons/internal/access"
	"latere.ai/x/pons/internal/apierr"
	"latere.ai/x/pons/internal/signin"
	"latere.ai/x/pons/test/stubs"
)

// An add without auth stores none, oauth or token from the server's answer
// to a request with no credential, made through the dialer after the
// question and within the add's rate; an add that names auth is held to
// the same answer; a server that does not answer as one that can be
// connected is refused without its address.
func TestAnAddAsksTheServerHowToSignIn(t *testing.T) {
	h := newHarness(t, func(s *Server) { s.CreatesPerMinute = 100 })
	set := func(change func(*stubs.ConnectorSwitches)) {
		h.up.mcp.Set(func(sw *stubs.ConnectorSwitches) { *sw = stubs.ConnectorSwitches{} })
		h.up.mcp.Set(change)
	}
	cases := []struct {
		name string
		set  func(*stubs.ConnectorSwitches)
		auth string
		hint string
	}{
		{"an open server", func(*stubs.ConnectorSwitches) {}, "none", ""},
		{"a server of an earlier revision", func(sw *stubs.ConnectorSwitches) { sw.Legacy = true }, "none", ""},
		{"a server that takes a key", func(sw *stubs.ConnectorSwitches) { sw.KeyOnly = true }, "token", "API key"},
		{"a server that signs people in", func(sw *stubs.ConnectorSwitches) { sw.Servers = []string{h.up.auth.Issuer()} }, "oauth", ""},
	}
	for i, tc := range cases {
		set(tc.set)
		before := len(h.up.mcp.Requests())
		a := h.add("alice", "wiki-"+string(rune('a'+i)), nil)
		if a.status != http.StatusCreated {
			t.Fatalf("%s: %d %s", tc.name, a.status, a.body)
		}
		auth := a.json(t)["auth"].(map[string]any)
		if auth["type"] != tc.auth || (auth["hint"] != nil && auth["hint"] != tc.hint) || (tc.hint != "" && auth["hint"] != tc.hint) {
			t.Fatalf("%s: auth %v", tc.name, auth)
		}
		if len(h.up.mcp.Requests()) == before || h.up.mcp.Requests()[before].Credential != "" {
			t.Fatalf("%s: the server was not asked, or was asked with a credential", tc.name)
		}
		if tc.auth == "oauth" && (auth["client"] != signin.ClientRegistered || auth["redirect_uri"] != nil) {
			t.Fatalf("%s: auth %v", tc.name, auth)
		}
	}
	if h.up.mcp.Sessions() != 0 {
		t.Fatalf("an add left %d sessions open", h.up.mcp.Sessions())
	}
	// An add that names auth is held to the answer.
	for i, tc := range []struct {
		name, auth string
		set        func(*stubs.ConnectorSwitches)
		code       string
		reason     string
	}{
		{"none for a server that signs people in", "none", func(sw *stubs.ConnectorSwitches) { sw.Servers = []string{h.up.auth.Issuer()} }, apierr.CodeAuthMismatch, "server_asks_oauth"},
		{"none for a server that takes a key", "none", func(sw *stubs.ConnectorSwitches) { sw.KeyOnly = true }, apierr.CodeAuthMismatch, "server_asks_token"},
		{"oauth for a server that takes a key", "oauth", func(sw *stubs.ConnectorSwitches) { sw.KeyOnly = true }, apierr.CodeAuthMismatch, "server_asks_token"},
		{"a key for an open server", "token", func(*stubs.ConnectorSwitches) {}, "", ""},
		{"a key for a server that signs people in", "token", func(sw *stubs.ConnectorSwitches) { sw.Servers = []string{h.up.auth.Issuer()} }, "", ""},
	} {
		set(tc.set)
		a := h.add("alice", "named-"+string(rune('a'+i)), map[string]any{"type": tc.auth})
		switch {
		case tc.code == "" && (a.status != http.StatusCreated || a.json(t)["auth"].(map[string]any)["type"] != tc.auth || a.json(t)["auth"].(map[string]any)["hint"] != nil):
			t.Errorf("%s: %d %s", tc.name, a.status, a.body)
		case tc.code != "" && (a.status != http.StatusUnprocessableEntity || a.code() != tc.code || a.detail("reason") != tc.reason || a.detail("field") != "auth.type"):
			t.Errorf("%s: %d %s", tc.name, a.status, a.body)
		}
	}
	// A server that does not answer as one that can be connected, named or
	// not, is refused with the status or the failure and no address.
	set(func(*stubs.ConnectorSwitches) {})
	for _, tc := range []struct {
		name, url, reason string
	}{
		{"another path", "https://mcp.example.com/elsewhere", "status_404"},
		{"a server that answers nothing", "https://nobody.example.com/mcp", "connect_failed"},
	} {
		for _, auth := range []map[string]any{nil, {"type": "token"}} {
			body := map[string]any{"name": "gone", "title": "Gone", "kind": "mcp", "url": tc.url}
			if auth != nil {
				body["auth"] = auth
			}
			a := h.do(http.MethodPost, "/v1/connectors", "alice", body)
			host, _, _ := strings.Cut(strings.TrimPrefix(tc.url, "https://"), "/")
			if a.status != http.StatusUnprocessableEntity || a.code() != apierr.CodeServerUnreachable || a.detail("reason") != tc.reason ||
				strings.Contains(string(a.body), host) || strings.Contains(h.logText(), host) {
				t.Errorf("%s, %v: %d %s", tc.name, auth, a.status, a.body)
			}
		}
	}
	// The question comes first: a denied add sends the server nothing.
	h.authz.set(orgPolicy)
	before := len(h.up.mcp.Requests())
	if a := h.add("bob", "denied", nil); a.status != http.StatusCreated {
		t.Fatalf("bob's own add under the policy: %d %s", a.status, a.body)
	}
	h.authz.set(func(access.Caller, access.Question) (access.Decision, error) {
		return access.Decision{Reason: "no"}, nil
	})
	reached := len(h.up.mcp.Requests())
	if a := h.add("bob", "refused", nil); a.status != http.StatusForbidden || len(h.up.mcp.Requests()) != reached || reached == before {
		t.Fatalf("a denied add: %d %s", a.status, a.body)
	}
	h.authz.set(nil)
	// The add's requests are the add's: within its rate, and none past it.
	slow := newHarness(t, func(s *Server) { s.CreatesPerMinute = 1 })
	if a := slow.add("alice", "first", nil); a.status != http.StatusCreated {
		t.Fatalf("the first add: %d %s", a.status, a.body)
	}
	reached = len(slow.up.mcp.Requests())
	if a := slow.add("alice", "second", nil); a.status != http.StatusTooManyRequests || len(slow.up.mcp.Requests()) != reached {
		t.Fatalf("an add past the rate: %d %s, the server asked %d times more", a.status, a.body, len(slow.up.mcp.Requests())-reached)
	}
	var stored map[string]any
	if err := json.Unmarshal(h.add("alice", "found", map[string]any{"type": "none"}).body, &stored); err != nil || stored["id"] == nil {
		t.Fatalf("an add after the refusals: %v %v", stored, err)
	}
}
