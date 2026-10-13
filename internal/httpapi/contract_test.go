// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"latere.ai/x/pons/internal/apierr"

	"go.yaml.in/yaml/v3"

	"latere.ai/x/pons/api"
	"latere.ai/x/pons/internal/access"
)

// contract is api/openapi.yaml, read once.
var contract = func() map[string]any {
	var doc map[string]any
	if err := yaml.Unmarshal(api.OpenAPI, &doc); err != nil {
		panic(err)
	}
	return doc
}()

func at(v any, keys ...string) any {
	for _, k := range keys {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[k]
	}
	return v
}

// template is a path with its parameters' names dropped, so /connectors/{id}
// and /connectors/{ref} are one path, as OpenAPI holds them.
func template(path string) string {
	return regexp.MustCompile(`\{[^}]+\}`).ReplaceAllString(path, "{}")
}

// operation finds the contract's operation for a request path below the base
// path.
func operation(method, path string) map[string]any {
	paths, _ := contract["paths"].(map[string]any)
	want := strings.Split(path, "/")
	var found map[string]any
	best := -1
	for candidate, item := range paths {
		have := strings.Split(candidate, "/")
		if len(have) != len(want) {
			continue
		}
		match := true
		for i := range have {
			if have[i] != want[i] && !strings.HasPrefix(have[i], "{") {
				match = false
			}
		}
		literal := len(have) - strings.Count(candidate, "{")
		if op, ok := at(item, strings.ToLower(method)).(map[string]any); ok && match && literal > best {
			found, best = op, literal
		}
	}
	return found
}

// resolve follows a $ref inside the contract.
func resolve(schema any) map[string]any {
	m, _ := schema.(map[string]any)
	for {
		ref, ok := m["$ref"].(string)
		if !ok {
			return m
		}
		m, _ = at(contract, strings.Split(strings.TrimPrefix(ref, "#/"), "/")...).(map[string]any)
	}
}

// conform reports where a decoded JSON value departs from a schema: a
// required member that is missing, a member the schema does not describe, a
// value of another type, or one outside an enum.
func conform(schema, value any, where string) []string {
	s := resolve(schema)
	if s == nil {
		return nil
	}
	if enum, ok := s["enum"].([]any); ok && !slices.Contains(enum, value) {
		return []string{fmt.Sprintf("%s is %v, outside %v", where, value, enum)}
	}
	typ, _ := s["type"].(string)
	var out []string
	switch v := value.(type) {
	case map[string]any:
		if typ != "" && typ != "object" {
			return []string{where + " is an object"}
		}
		props, _ := s["properties"].(map[string]any)
		required, _ := s["required"].([]any)
		for _, name := range required {
			if _, ok := v[name.(string)]; !ok {
				out = append(out, fmt.Sprintf("%s lacks %s", where, name))
			}
		}
		for name, member := range v {
			p, ok := props[name]
			if !ok {
				if s["additionalProperties"] == false {
					out = append(out, fmt.Sprintf("%s has %s, which the schema does not describe", where, name))
				}
				continue
			}
			out = append(out, conform(p, member, where+"."+name)...)
		}
	case []any:
		if typ != "array" {
			return []string{where + " is an array"}
		}
		for i, item := range v {
			out = append(out, conform(s["items"], item, fmt.Sprintf("%s[%d]", where, i))...)
		}
	case string:
		if typ != "string" {
			out = append(out, where+" is a string")
		}
	case float64:
		if typ != "integer" && typ != "number" {
			out = append(out, where+" is a number")
		}
	case bool:
		if typ != "boolean" {
			out = append(out, where+" is a boolean")
		}
	}
	return out
}

// hold holds one answer to the contract: its status is one the operation
// names, and its body validates against that status's schema.
func hold(t testing.TB, method, path string, a answer) {
	t.Helper()
	path, _, _ = strings.Cut(path, "?")
	op := operation(method, path)
	if op == nil {
		t.Errorf("%s %s is not in the contract", method, path)
		return
	}
	resp := resolve(at(op, "responses", strconv.Itoa(a.status)))
	if resp == nil {
		t.Errorf("%s %s answered %d, which the contract does not name: %s", method, path, a.status, a.body)
		return
	}
	schema := at(resp, "content", "application/json", "schema")
	if schema == nil {
		if len(a.body) > 0 && !strings.HasPrefix(a.header.Get("Content-Type"), "application/yaml") {
			t.Errorf("%s %s answered %d with a body the contract does not describe", method, path, a.status)
		}
		return
	}
	var v any
	if err := json.Unmarshal(a.body, &v); err != nil {
		t.Errorf("%s %s answered %d with no JSON: %s", method, path, a.status, a.body)
		return
	}
	for _, p := range conform(schema, v, "body") {
		t.Errorf("%s %s %d: %s", method, path, a.status, p)
	}
}

// The served routes and the contract's paths are one set.
func TestTheContractIsTheServedRoutes(t *testing.T) {
	served := map[string]bool{}
	for _, rt := range Routes() {
		served[rt.Method+" "+template(rt.Path)] = true
	}
	documented := map[string]bool{}
	for path, item := range contract["paths"].(map[string]any) {
		for method := range item.(map[string]any) {
			documented[strings.ToUpper(method)+" "+template(path)] = true
		}
	}
	for k := range served {
		if !documented[k] {
			t.Errorf("%s is served and not in the contract", k)
		}
	}
	for k := range documented {
		if !served[k] {
			t.Errorf("%s is in the contract and not served", k)
		}
	}
	for _, rt := range Routes() {
		row, ok := access.RouteOf(rt.Method, rt.Path)
		if !ok {
			t.Errorf("%s %s has no row in the table of routes", rt.Method, rt.Path)
		}
		if (row.Action == "") != (rt.Path == "/openapi.yaml") {
			t.Errorf("%s %s asks %q", rt.Method, rt.Path, row.Action)
		}
	}
}

// Every error has a code of the table of spec 003, the status of its code,
// and the code's fixed sentence.
func TestErrorTable(t *testing.T) {
	f, err := os.Open(filepath.Join("..", "..", "specs", "003-api.md"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			t.Error(err)
		}
	}()
	row := regexp.MustCompile("^\\| ([0-9]{3}) \\| (`.*)\\|$")
	code := regexp.MustCompile("`([a-z_]+)`")
	spec := map[string]int{}
	scan := bufio.NewScanner(f)
	for scan.Scan() {
		m := row.FindStringSubmatch(scan.Text())
		if m == nil {
			continue
		}
		status, _ := strconv.Atoi(m[1])
		for _, c := range code.FindAllStringSubmatch(m[2], -1) {
			spec[c[1]] = status
		}
	}
	if err := scan.Err(); err != nil {
		t.Fatal(err)
	}
	if len(spec) != len(apierr.Codes()) {
		t.Errorf("the spec has %d codes and the table %d", len(spec), len(apierr.Codes()))
	}
	documented, _ := at(resolve(at(contract, "components", "schemas", "Error")), "properties", "error", "properties", "code", "enum").([]any)
	for c, status := range spec {
		message := apierr.Message(c)
		if !slices.Contains(apierr.Codes(), c) || apierr.Status(c) != status {
			t.Errorf("%s: the spec says %d, the table has %d", c, status, apierr.Status(c))
		}
		if message == "" || !strings.HasSuffix(message, ".") {
			t.Errorf("%s has no sentence", c)
		}
		if !slices.Contains(documented, any(c)) {
			t.Errorf("%s is not in the contract's enum", c)
		}
		st, body := (&apierr.Error{Code: c, Reason: "r"}).Envelope()
		if st != status || body.Code != c || body.Message != message {
			t.Errorf("%s renders %d %+v", c, st, body)
		}
	}
	if st, body := (&apierr.Error{Code: "nothing"}).Envelope(); st != http.StatusInternalServerError || body.Code != apierr.CodeInternal || body.Details != nil {
		t.Errorf("an unknown code renders %d %+v", st, body)
	}
	if apierr.Status("nothing") != http.StatusInternalServerError || apierr.Message("nothing") != "" {
		t.Error("a code the table lacks has a status or a sentence")
	}
}

// Every route below the base path but the contract answers 401
// missing_token without a bearer.
func TestRoutesNeedABearer(t *testing.T) {
	h := newHarness(t)
	for _, rt := range Routes() {
		path := strings.NewReplacer("{ref}", "notion", "{id}", "con_01jb2m6x8q3v7k9n4w5t0zr1ya").Replace(rt.Path)
		a := h.do(rt.Method, "/v1"+path, "", nil)
		if rt.Path == "/openapi.yaml" {
			if a.status != http.StatusOK || !strings.Contains(string(a.body), "openapi: 3.1.0") {
				t.Errorf("the contract answered %d", a.status)
			}
			continue
		}
		if rt.Method == http.MethodHead {
			// An answer to HEAD has no body to carry the code.
			if a.status != http.StatusUnauthorized {
				t.Errorf("HEAD %s without a bearer: %d", path, a.status)
			}
			continue
		}
		if a.status != http.StatusUnauthorized || a.code() != apierr.CodeMissingToken {
			t.Errorf("%s %s without a bearer: %d %s", rt.Method, path, a.status, a.body)
		}
		hold(t, rt.Method, path, a)
	}
	if len(h.authz.questions()) != 0 {
		t.Error("a request with no bearer asked the authorizer")
	}
}

// The surface moves whole under the base path.
func TestBasePath(t *testing.T) {
	h := newHarness(t, func(s *Server) { s.BasePath = "/pons/api" })
	if a := h.do(http.MethodGet, "/pons/api/connectors", "alice", nil); a.status != http.StatusOK {
		t.Fatalf("under the base path: %d %s", a.status, a.body)
	}
	if a := h.do(http.MethodGet, "/v1/connectors", "alice", nil); a.status != http.StatusNotFound {
		t.Fatalf("under another path: %d", a.status)
	}
	if a := h.do(http.MethodGet, "/pons/api/openapi.yaml", "", nil); a.status != http.StatusOK {
		t.Fatalf("the contract: %d", a.status)
	}
	a := h.connect("alice", "weather", "", "")
	if got := a.json(t)["address"]; got != "https://pons.example.com/pons/api/connections/"+idOf(t, a)+"/mcp" {
		t.Fatalf("the address is %v", got)
	}
	if a := h.do(http.MethodGet, "/livez", "", nil); a.status != http.StatusOK {
		t.Fatalf("the probes moved with the base path: %d", a.status)
	}
}

// Every request and response of the handlers holds the contract.
func TestHandlersHoldTheContract(t *testing.T) {
	h := newHarness(t)
	check := func(method, path, bearer string, body any) answer {
		t.Helper()
		a := h.do(method, path, bearer, body)
		hold(t, method, strings.TrimPrefix(path, "/v1"), a)
		return a
	}
	check(http.MethodGet, "/v1/connectors", "alice", nil)
	check(http.MethodGet, "/v1/connectors?kind=mcp&limit=2", "alice", nil)
	check(http.MethodGet, "/v1/connectors?kind=ftp", "alice", nil)
	check(http.MethodGet, "/v1/connectors/search", "alice", nil)
	check(http.MethodGet, "/v1/connectors/nothing", "alice", nil)
	added := check(http.MethodPost, "/v1/connectors", "alice", map[string]any{
		"name": "wiki", "title": "Wiki", "kind": "mcp", "url": "https://wiki.example.com/mcp",
		"auth":  map[string]any{"type": "token", "inject": map[string]any{"header": "X-Key", "format": "{value}"}},
		"tools": map[string]any{"read_only": []string{"get_*"}},
	})
	ctr := idOf(t, added)
	check(http.MethodPost, "/v1/connectors", "alice", map[string]any{"name": "wiki", "title": "W", "kind": "mcp", "url": "https://wiki.example.com/mcp", "auth": map[string]any{"type": "none"}})
	check(http.MethodPost, "/v1/connectors", "alice", map[string]any{"name": "oauth", "title": "O", "kind": "mcp", "url": "https://o.example.com/mcp", "auth": map[string]any{"type": "oauth"}})
	check(http.MethodPost, "/v1/connectors", "alice", `{"name": 1}`)
	check(http.MethodGet, "/v1/connectors/"+ctr, "alice", nil)
	conn := check(http.MethodPost, "/v1/connections", "alice", map[string]any{"connector": ctr, "credential": map[string]any{"value": "a-key-of-alice"}})
	con := idOf(t, conn)
	check(http.MethodDelete, "/v1/connectors/"+ctr, "alice", nil)
	check(http.MethodPost, "/v1/connections", "alice", map[string]any{"connector": "tracker", "return_to": "https://app.example.com/done"})
	check(http.MethodPost, "/v1/connections", "alice", map[string]any{"connector": "warehouse", "credential": map[string]any{"client_id": "wh", "client_secret": "a-secret-of-alice"}})
	check(http.MethodPost, "/v1/connections", "alice", map[string]any{"connector": "search", "credential": map[string]any{"value": "short"}})
	check(http.MethodGet, "/v1/connections", "alice", nil)
	check(http.MethodGet, "/v1/connections?state=connected&limit=1", "alice", nil)
	check(http.MethodGet, "/v1/connections/"+con, "alice", nil)
	check(http.MethodGet, "/v1/connections/"+con, "bob", nil)
	check(http.MethodPatch, "/v1/connections/"+con, "alice", map[string]any{"name": "wiki-two"})
	check(http.MethodPut, "/v1/connections/"+con+"/credential", "alice", map[string]any{"credential": map[string]any{"value": "another-key-of-alice"}})
	check(http.MethodGet, "/v1/connections/"+con+"/calls", "alice", nil)
	check(http.MethodDelete, "/v1/connections/"+con, "alice", nil)
	check(http.MethodDelete, "/v1/connectors/"+ctr, "alice", nil)
	check(http.MethodGet, "/v1/openapi.yaml", "", nil)
}
