// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"

	"go.yaml.in/yaml/v3"

	"latere.ai/x/pons/api"
	"latere.ai/x/pons/test/stubs"
)

// called records, per test binary, the routes of the contract the e2e tier
// called, as METHOD /path-template.
var called = struct {
	sync.Mutex
	routes map[string]bool
}{routes: map[string]bool{}}

// routeOf is the contract's template of a request path below the base
// path.
func routeOf(method, path string) string {
	path, _, _ = strings.Cut(strings.TrimPrefix(path, "/v1"), "?")
	parts := strings.Split(path, "/")
	if len(parts) > 3 && parts[1] == "connections" && (parts[3] == "http" || parts[3] == "git") {
		// Everything after an address is its one path parameter.
		return method + " /connections/{}/" + parts[3] + "/{}"
	}
	for i, p := range parts {
		if strings.Contains(p, "_") || (i == 2 && parts[1] == "connectors" && p != "") {
			parts[i] = "{}"
		}
	}
	return method + " " + strings.Join(parts, "/")
}

// exercise calls every route of the contract with credentials that hold the
// canary, as alice, and records what it called.
func exercise(t *testing.T, s *stack, canary string) {
	t.Helper()
	call := func(method, path, sub string, body any, headers ...string) answer {
		t.Helper()
		a := s.do(method, path, sub, body, headers...)
		called.Lock()
		called.routes[routeOf(method, path)] = true
		called.Unlock()
		return a
	}
	call(http.MethodGet, "/v1/openapi.yaml", "", nil)
	call(http.MethodGet, "/v1/connectors", "alice", nil)
	call(http.MethodGet, "/v1/connectors/search", "alice", nil)
	ctr := call(http.MethodPost, "/v1/connectors", "alice", map[string]any{
		"name": "wiki", "title": "Wiki", "kind": "mcp", "url": "https://wiki.example.com/mcp", "auth": map[string]any{"type": "token"},
	}).id(t)
	keyed := call(http.MethodPost, "/v1/connections", "alice", map[string]any{"connector": "search", "credential": map[string]any{"value": canary + "-key"}}).id(t)
	call(http.MethodPost, "/v1/connections", "alice", map[string]any{"connector": "warehouse", "credential": map[string]any{"client_id": "wh", "client_secret": canary + "-secret"}})
	added := call(http.MethodPost, "/v1/connections", "alice", map[string]any{"connector": ctr, "credential": map[string]any{"value": canary + "-added"}}).id(t)
	// Every refusal a credential can meet, with the canary in the request.
	call(http.MethodPost, "/v1/connections", "alice", map[string]any{"connector": "search", "name": "search", "credential": map[string]any{"value": canary + "-taken"}})
	call(http.MethodPost, "/v1/connections", "alice", map[string]any{"connector": "weather", "credential": map[string]any{"value": canary + "-wrong"}})
	call(http.MethodPost, "/v1/connections", "alice", map[string]any{"connector": "search", "name": "x", "credential": map[string]any{"value": canary + "-extra", "client_id": canary}})
	call(http.MethodPost, "/v1/connections", "bob", map[string]any{"connector": "search", "owner": "someone", "credential": map[string]any{"value": canary + "-denied"}})
	call(http.MethodGet, "/v1/connections", "alice", nil)
	call(http.MethodGet, "/v1/connections/"+keyed, "alice", nil)
	call(http.MethodPatch, "/v1/connections/"+keyed, "alice", map[string]any{"name": "renamed"})
	call(http.MethodPut, "/v1/connections/"+keyed+"/credential", "alice", map[string]any{"credential": map[string]any{"value": canary + "-replaced"}})
	call(http.MethodPut, "/v1/connections/"+keyed+"/credential", "bob", map[string]any{"credential": map[string]any{"value": canary + "-bob"}})
	call(http.MethodGet, "/v1/connections/"+keyed+"/calls", "alice", nil)
	// The forwarding and the git address of a connection of kind http, with
	// the canary as its key.
	forge := call(http.MethodPost, "/v1/connections", "alice", map[string]any{"connector": "forge", "credential": map[string]any{"value": canary + "-forge"}}).id(t)
	web := "/v1/connections/" + forge + "/http"
	call(http.MethodGet, web+"/repos/acme/app/issues?token="+canary+"-query", "alice", nil)
	call(http.MethodPost, web+"/repos/acme/app/issues", "alice", map[string]any{"title": canary + "-argument"})
	call(http.MethodPut, web+"/upload", "alice", "uploaded")
	call(http.MethodPatch, web+"/repos/acme/app", "alice", map[string]any{"private": true})
	call(http.MethodDelete, web+"/repos/acme/app", "alice", nil)
	call(http.MethodOptions, web+"/user", "alice", nil)
	call(http.MethodHead, web+"/user", "alice", nil)
	call(http.MethodGet, web+"/headers", "alice", nil)
	git := "/v1/connections/" + forge + "/git/acme/app.git"
	call(http.MethodGet, git+"/info/refs?service=git-upload-pack", "alice", nil)
	call(http.MethodPost, git+"/git-upload-pack", "alice", "0000", "Content-Type", "application/x-git-upload-pack-request")
	call(http.MethodGet, "/v1/connections/"+forge+"/calls", "alice", nil)
	call(http.MethodDelete, "/v1/connections/"+added, "alice", nil)
	call(http.MethodDelete, "/v1/connectors/"+ctr, "alice", nil)
}

// encodings are the forms a value can be found in at rest or in a log.
func encodings(v string) []string {
	return []string{v, hex.EncodeToString([]byte(v)), base64.StdEncoding.EncodeToString([]byte(v)), base64.RawURLEncoding.EncodeToString([]byte(v))}
}

// A canary planted as a pasted key and as a client secret, with every route
// exercised, appears in no response body, header, log line, error or
// database row, over both stores. The canary's one place, the stub it
// belongs to, waits for the carrier.
func TestNoCredentialLeavesButTowardItsConnector(t *testing.T) {
	for name, over := range map[string]func(*testing.T) map[string]string{
		"memory":   func(*testing.T) map[string]string { return nil },
		"postgres": func(t *testing.T) map[string]string { return database(t) },
	} {
		t.Run(name, func(t *testing.T) {
			canary := "canary-" + strings.ToLower(rand.Text())
			catalogSecret := canary + "-catalog"
			t.Setenv("PONS_TEST_CODE_SECRET", catalogSecret)
			env := over(t)
			if env == nil {
				env = map[string]string{}
			}
			env["PONS_CATALOG_FILE"] = catalogFile(t, `
  - name: code
    title: Example Code
    kind: mcp
    url: https://mcp.code.example.com/mcp
    auth:
      type: oauth
      discovery: none
      authorize_url: https://code.example.com/authorize
      token_url: https://code.example.com/token
      client: {id: code-client, secret: {env: PONS_TEST_CODE_SECRET}}
`)
			s := startStack(t, stubs.NewIssuer(t), env)
			exercise(t, s, canary)
			s.do(http.MethodGet, "/v1/connectors/code", "alice", nil)
			everything := s.everything() + s.dump()
			// The key's one place is the stub it belongs to, in the place
			// its connector takes it.
			if creds := upstreamOf(t).api.Credentials(); !slices.Contains(creds, "Bearer "+canary+"-forge") {
				t.Fatalf("the key never reached its connector: %v", creds)
			}
			for _, value := range []string{canary, catalogSecret} {
				for _, form := range encodings(value) {
					if strings.Contains(everything, form) {
						i := strings.Index(everything, form)
						t.Fatalf("the canary %q appears: %s", form, everything[max(0, i-200):min(len(everything), i+200)])
					}
				}
			}
		})
	}
}

// Every route of the OpenAPI document is called by the e2e tier.
func TestEveryRouteIsExercised(t *testing.T) {
	exercise(t, startStack(t, stubs.NewIssuer(t), nil), "exercised-"+strings.ToLower(rand.Text()))
	var doc struct {
		Paths map[string]map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal(api.OpenAPI, &doc); err != nil {
		t.Fatal(err)
	}
	param := regexp.MustCompile(`\{[^}]+\}`)
	called.Lock()
	defer called.Unlock()
	for path, item := range doc.Paths {
		for method := range item {
			route := strings.ToUpper(method) + " " + param.ReplaceAllString(path, "{}")
			if !called.routes[route] {
				t.Errorf("%s is never called by the e2e tier", route)
			}
		}
	}
}
