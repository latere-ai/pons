// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package carry

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"latere.ai/x/pons/authorizer"
	"latere.ai/x/pons/catalog"
	"latere.ai/x/pons/internal/store"
	"latere.ai/x/pons/internal/version"
	"latere.ai/x/pons/test/stubs"
)

// Only the headers of the table reach the connector: the caller's
// Authorization, cookies, Origin, forwarding and hop-by-hop headers and a
// header named like the credential's never do, and the credential is in its
// place, with User-Agent pons/<version>, for each way to give access.
func TestRequestHeaders(t *testing.T) {
	r := newRig(t, false)
	r.auth.AddClient("wh-client", "the-client-secret-01")
	signed, access := r.signedInTo("notes-signed", "bob", time.Now().Add(time.Hour))
	cases := []struct {
		name, bearer, header, want string
		c                          store.Connection
	}{
		{name: "token", bearer: "alice", c: r.noted(), header: "Authorization", want: "Bearer the-notes-key-of-alice"},
		{name: "token in a header of its own", bearer: "carol", header: "X-Api-Key", want: "key the-x-key-of-carol",
			c: r.connect("carol", "notes-key", store.Secrets{Value: "the-x-key-of-carol"}, store.Meta{Header: "X-Api-Key", Format: "key {value}"})},
		{name: "oauth", bearer: "bob", c: signed, header: "Authorization", want: "Bearer " + access},
		{name: "client_credentials", bearer: "dave", header: "Authorization", want: "Bearer stub-",
			c: r.connect("dave", "notes-minted", store.Secrets{ClientSecret: "the-client-secret-01"}, store.Meta{ClientID: "wh-client", TokenEndpoint: r.auth.TokenURL(), Scopes: []string{"read"}})},
		{name: "none", bearer: "erin", c: r.connect("erin", "notes-open", store.Secrets{}, store.Meta{}), header: "Authorization"},
	}
	hostile := []string{
		"Cookie", "session=caller", "Origin", "https://app.example.com", "Forwarded", "for=10.0.0.1",
		"X-Forwarded-For", "10.0.0.1", "X-Forwarded-Host", "inside.example.com", "X-Real-Ip", "10.0.0.2", "Via", "1.1 proxy",
		"Connection", "X-Hop", "X-Hop", "1", "Keep-Alive", "timeout=5", "Proxy-Authorization", "Basic eA==",
		"X-Api-Key", "the-caller-chose-this", "User-Agent", "caller/1.0", "X-Other", "2",
		"Mcp-Param-Region", "eu", "Last-Event-Id", "3", "Mcp-Session-Id", "sess-caller",
	}
	passes := []string{"Accept", "Content-Type", "Content-Length", "Mcp-Protocol-Version", "Mcp-Method", "Mcp-Param-Region",
		"Last-Event-Id", "Mcp-Session-Id", "User-Agent", "Accept-Encoding"}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := len(r.mcp.Requests())
			if a := r.list(tc.c, tc.bearer, hostile...); a.status != http.StatusOK {
				t.Fatalf("%d %s", a.status, a.body)
			}
			got := r.mcp.Requests()[before:]
			if len(got) != 1 {
				t.Fatalf("%d requests reached the connector", len(got))
			}
			h := got[0].Header
			for name := range h {
				if !slices.Contains(passes, name) && name != tc.header {
					t.Errorf("%s reached the connector", name)
				}
			}
			if v := h.Get(tc.header); (tc.want == "" && v != "") || !strings.HasPrefix(v, tc.want) || strings.Contains(v, tc.bearer+"\x00") {
				t.Errorf("the credential's place %s is %q", tc.header, v)
			}
			if v := h.Get("Authorization"); v == "Bearer "+tc.bearer {
				t.Error("the caller's token reached the connector")
			}
			if tc.header != "X-Api-Key" && h.Get("X-Api-Key") != "" {
				t.Error("a header named like another credential's reached the connector")
			}
			for name, want := range map[string]string{
				"User-Agent": version.UserAgent(), "Accept-Encoding": "identity", "Mcp-Param-Region": "eu",
				"Last-Event-Id": "3", "Mcp-Session-Id": "sess-caller", "Mcp-Method": "tools/list", "Mcp-Protocol-Version": stubs.MCPRevision,
			} {
				if h.Get(name) != want {
					t.Errorf("%s is %q, want %q", name, h.Get(name), want)
				}
			}
		})
	}
	if got := headersTowardMCP(http.Header{"X-Api-Key": {"caller"}, "Authorization": {"Bearer caller"}}); len(got) != 1 {
		t.Fatalf("toward %v", got)
	}
}

// The status and the body pass byte for byte, of a result, a JSON-RPC
// error, an accepted notification and a status the connector chose; the
// body is forwarded as the caller wrote it.
func TestAnswerPassesUnchanged(t *testing.T) {
	r := newRig(t, false)
	c := r.noted()
	body := `{"jsonrpc":"2.0", "id":7, "method":"tools/call","params":{"arguments":{"q":"kittens", "n": 1e999},"name":"search_notes",` +
		`"_meta":{"io.modelcontextprotocol/protocolVersion":"` + stubs.MCPRevision + `"}}}`
	_, headers := rpc("tools/call", map[string]any{"name": "search_notes"})
	a := r.send(http.MethodPost, address(c, "mcp"), "alice", strings.NewReader(body), headers...)
	want, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": json.RawMessage("7"), "result": map[string]any{
		"content": []map[string]any{{"type": "text", "text": `search_notes {"q":"kittens", "n": 1e999}`}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if a.status != http.StatusOK || !bytes.Equal(a.body, append(want, '\n')) {
		t.Fatalf("a result: %d %s", a.status, a.body)
	}
	if got := r.mcp.Requests(); len(got) != 1 || string(got[0].Body) != body {
		t.Fatalf("the body was changed on the way: %s", got[0].Body)
	}
	if a := r.call(c, "alice", "nope", nil); a.status != http.StatusOK || !strings.Contains(string(a.body), `"code":-32602`) {
		t.Fatalf("a JSON-RPC error: %d %s", a.status, a.body)
	}
	note := `{"jsonrpc":"2.0","method":"notifications/initialized","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"` + stubs.MCPRevision + `"}}}`
	if a := r.send(http.MethodPost, address(c, "mcp"), "alice", strings.NewReader(note), "MCP-Protocol-Version", stubs.MCPRevision, "Mcp-Method", "notifications/initialized"); a.status != http.StatusAccepted || len(a.body) != 0 {
		t.Fatalf("a notification: %d %s", a.status, a.body)
	}
	if a := r.send(http.MethodGet, address(c, "mcp"), "alice", nil); a.status != http.StatusMethodNotAllowed || string(a.body) != "the current revision takes POST alone\n" {
		t.Fatalf("a GET the connector does not take: %d %s", a.status, a.body)
	}
	// A version the connector does not speak is the connector's to refuse.
	stale := strings.Replace(body, stubs.MCPRevision, "2025-06-18", 1)
	if a := r.send(http.MethodPost, address(c, "mcp"), "alice", strings.NewReader(stale), headers...); a.status != http.StatusBadRequest || !strings.Contains(string(a.body), `"code":-32020`) {
		t.Fatalf("the connector's own 400: %d %s", a.status, a.body)
	}
}

// Only the listed headers pass back: WWW-Authenticate, Set-Cookie and
// Location never do, an event stream is marked so no proxy holds it, and a
// session of an earlier revision passes back.
func TestResponseHeaders(t *testing.T) {
	r := newRig(t, false)
	c := r.noted()
	r.mcp.Set(func(sw *stubs.ConnectorSwitches) { sw.Cookie = true })
	a := r.call(c, "alice", "count", nil)
	if a.status != http.StatusOK || a.header.Get("Set-Cookie") != "" || a.header.Get("X-Accel-Buffering") != "no" ||
		a.header.Get("Content-Type") != "text/event-stream" || a.header.Get("Cache-Control") != "no-cache" {
		t.Fatalf("a stream: %d %v", a.status, a.header)
	}
	if a := r.list(c, "alice"); a.header.Get("X-Accel-Buffering") != "" || a.header.Get("Content-Type") != "application/json" {
		t.Fatalf("a JSON answer: %v", a.header)
	}
	open := r.connect("bob", "notes-open", store.Secrets{}, store.Meta{})
	r.mcp.Set(func(sw *stubs.ConnectorSwitches) { sw.Cookie, sw.RefuseAll = false, true })
	if a := r.list(open, "bob"); a.status != http.StatusUnauthorized || a.header.Get("WWW-Authenticate") != "" {
		t.Fatalf("a challenge: %d %v", a.status, a.header)
	}
	r.mcp.Set(func(sw *stubs.ConnectorSwitches) { sw.RefuseAll, sw.Redirect = false, true })
	if a := r.list(c, "alice"); a.status != http.StatusBadGateway || a.code() != "connector_unavailable" ||
		a.detail("reason") != "redirect_refused" || a.header.Get("Location") != "" {
		t.Fatalf("a redirect: %d %v %s", a.status, a.header, a.body)
	}
	r.mcp.Set(func(sw *stubs.ConnectorSwitches) { sw.Redirect, sw.Legacy = false, true })
	init := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"` + stubs.MCPLegacy + `","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`
	if a := r.send(http.MethodPost, address(c, "mcp"), "alice", strings.NewReader(init), "Accept", "application/json, text/event-stream"); a.status != http.StatusOK || !strings.HasPrefix(a.header.Get("Mcp-Session-Id"), "sess-") {
		t.Fatalf("a session: %d %v", a.status, a.header)
	}
	dst := http.Header{}
	headersBackMCP(dst, http.Header{
		"Retry-After": {"7"}, "Mcp-Session-Id": {"s"}, "Content-Length": {"3"}, "Location": {"https://elsewhere.example.net"},
		"Www-Authenticate": {"Bearer"}, "Set-Cookie": {"a=b"}, "X-Other": {"1"}, "Content-Type": {"text/event-stream; charset=utf-8"},
	})
	if len(dst) != 4 || dst.Get("Retry-After") != "7" || dst.Get("Mcp-Session-Id") != "s" || dst.Get("X-Accel-Buffering") != "no" {
		t.Fatalf("back %v", dst)
	}
}

// A caller receives each event of a stream before the connector sends the
// next: the stub sends an event only once the test has read the one before.
func TestStreamIsFlushedPerEvent(t *testing.T) {
	r := newRig(t, false)
	c := r.noted()
	r.mcp.Set(func(sw *stubs.ConnectorSwitches) { sw.Stepped = true })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	body, headers := rpc("tools/call", map[string]any{"name": "count"})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.srv.URL+address(c, "mcp"), strings.NewReader(body))
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
	defer closeBody(resp)
	events := bufio.NewReader(resp.Body)
	for i := range 4 {
		if i > 0 {
			r.mcp.Step()
		}
		event, err := readEvent(events)
		if err != nil {
			t.Fatalf("event %d: %v", i+1, err)
		}
		if !strings.Contains(event, `"jsonrpc":"2.0"`) || (i < 3) != strings.Contains(event, "notifications/progress") {
			t.Fatalf("event %d: %q", i+1, event)
		}
	}
}

// readEvent reads one event of a stream, up to its blank line.
func readEvent(r *bufio.Reader) (string, error) {
	var b strings.Builder
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return b.String(), err
		}
		if line == "\n" {
			return b.String(), nil
		}
		b.WriteString(line)
	}
}

// A body over the limit is 413 before it is read; a body that is not one
// object, a duplicate or differently cased key, or a mirrored header that
// differs from the body is 400; arguments are never decoded; nothing
// refused reaches the connector or the authorizer.
func TestParseOnlyTheMethodAndTool(t *testing.T) {
	r := newRig(t, false)
	c := r.noted()
	meta := `"_meta":{"io.modelcontextprotocol/protocolVersion":"` + stubs.MCPRevision + `"}`
	for body, why := range map[string]string{
		`[{"jsonrpc":"2.0","id":1,"method":"tools/list"}]`: whyNotAnObject,
		`"tools/list"`: whyNotAnObject,
		`{"jsonrpc":"2.0","id":1,"method":"tools/list"}{}`:                               whyNotAnObject,
		`{"jsonrpc":"2.0","id":1,"method":"tools/list"} x`:                               whyNotAnObject,
		`{"jsonrpc":"2.0","method":`:                                                     whyNotAnObject,
		`{"method":"tools/list","method":"tools/call"}`:                                  whyDuplicate,
		`{"method":"tools/list","Method":"tools/call","params":{"name":"create_note"}}`:  whyKeyCase,
		`{"method":"tools/call","params":{"name":"get_note"},"PARAMS":{}}`:               whyKeyCase,
		`{"method":"tools/call","params":{"name":"get_note"},"params":{}}`:               whyDuplicate,
		`{"method":"tools/call","params":{"name":"get_note","name":"create_note"}}`:      whyDuplicate,
		`{"method":"tools/call","params":{"name":"get_note","Name":"create_note"}}`:      whyKeyCase,
		`{"method":"tools/call","params":{"nam\u0065":"get_note","name":"create_note"}}`: whyDuplicate,
		`{"method":"tools/call","params":{}}`:                                            whyToolName,
		`{"method":"tools/call","params":{"name":""}}`:                                   whyToolName,
		`{"method":"tools/call","params":{"name":3}}`:                                    whyToolName,
		`{"method":"tools/call","params":[]}`:                                            whyToolName,
		`{"method":7}`:                                                                   whyMethod,
	} {
		for _, id := range []string{c.ID, "con_nothing"} {
			a := r.send(http.MethodPost, "/v1/connections/"+id+"/mcp", "alice", strings.NewReader(body))
			if a.status != http.StatusBadRequest || a.code() != "invalid_request" || a.detail("reason") != why {
				t.Errorf("%s on %s: %d %s", body, id, a.status, a.body)
			}
		}
	}
	for name, headers := range map[string][]string{
		"another method":         {"Mcp-Method", "tools/list"},
		"another tool":           {"Mcp-Method", "tools/call", "Mcp-Name", "create_note"},
		"another tool in base64": {"Mcp-Name", "=?base64?" + base64.StdEncoding.EncodeToString([]byte("create_note")) + "?="},
		"base64 that is not":     {"Mcp-Name", "=?base64?***?="},
	} {
		body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_note",` + meta + `}}`
		if a := r.send(http.MethodPost, address(c, "mcp"), "alice", strings.NewReader(body), headers...); a.status != http.StatusBadRequest || a.detail("reason") != whyMirrored {
			t.Errorf("%s: %d %s", name, a.status, a.body)
		}
	}
	if len(r.mcp.Requests()) != 0 || len(r.az.questions()) != 0 {
		t.Fatal("a refused body reached the connector or the authorizer")
	}
	// A tool's name that is not plain ASCII is mirrored in base64, and the
	// name the body holds is the one asked about.
	exotic := "notizen_süß"
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + exotic + `","arguments":{"name":"create_note","Method":"x"},` + meta + `}}`
	a := r.send(http.MethodPost, address(c, "mcp"), "alice", strings.NewReader(body), "Mcp-Protocol-Version", stubs.MCPRevision,
		"Mcp-Method", "tools/call", "Mcp-Name", "=?base64?"+base64.StdEncoding.EncodeToString([]byte(exotic))+"?=")
	if a.status != http.StatusOK || r.az.questions()[0].Resource.Fields["tool"] != exotic {
		t.Fatalf("a name in base64: %d %s %+v", a.status, a.body, r.az.questions())
	}
	if m, why := parseMessage([]byte(`{"jsonrpc":"2.0","result":{"method":"tools/call"},"id":3}`)); why != "" || m.method != "" || m.tool != "" {
		t.Fatalf("a reply: %+v %s", m, why)
	}
	if m, why := parseMessage([]byte(`{"\u006dethod":"tools/call","params":{"name":"get_note"}}`)); why != "" || m.method != MethodToolsCall || m.tool != "get_note" {
		t.Fatalf("an escaped key is the key: %+v %s", m, why)
	}

	// The bound: a length above it before a byte is read, and a body that
	// runs past it, whether the id exists or not.
	asked := len(r.az.questions())
	big := `{"method":"tools/list","pad":"` + strings.Repeat("x", int(r.c.MaxRequestBytes)) + `"}`
	for _, id := range []string{c.ID, "con_nothing"} {
		if a := r.send(http.MethodPost, "/v1/connections/"+id+"/mcp", "alice", strings.NewReader(big)); a.status != http.StatusRequestEntityTooLarge || a.code() != "request_too_large" {
			t.Errorf("a length past the bound on %s: %d %s", id, a.status, a.body)
		}
		if a := r.send(http.MethodPost, "/v1/connections/"+id+"/mcp", "alice", io.MultiReader(strings.NewReader(big))); a.status != http.StatusRequestEntityTooLarge {
			t.Errorf("a body that runs past the bound on %s: %d %s", id, a.status, a.body)
		}
	}
	if len(r.az.questions()) != asked || len(r.mcp.Requests()) != 1 {
		t.Fatal("a body past the bound was asked about or forwarded")
	}
}

// FuzzParse holds the parse to what a connector reads: when it accepts a
// body, the body is one JSON object whose method, and for tools/call whose
// params.name, are what Pons read, and no other key spells either by case.
func FuzzParse(f *testing.F) {
	for _, seed := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_note","arguments":{"a":1}}}`,
		`{"method":"tools/list"}`, `{"result":{},"id":1}`, `{"method":"tools/call","params":{"name":"a","Name":"b"}}`,
		`{"Method":"x"}`, `[]`, `{"method":"tools/call","params":{"nam\u0065":"a"}}`, `{}`, `{"method":"tools/call","params":{"name":"\u00e9"}}`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		m, why := parseMessage(body)
		if why != "" {
			return
		}
		var top map[string]json.RawMessage
		if err := json.Unmarshal(body, &top); err != nil {
			t.Fatalf("accepted a body that is not one object: %q", body)
		}
		var method string
		if raw, ok := top["method"]; ok {
			if err := json.Unmarshal(raw, &method); err != nil {
				t.Fatalf("accepted a method that is no string: %q", body)
			}
		}
		if method != m.method {
			t.Fatalf("read %q, a connector reads %q: %q", m.method, method, body)
		}
		var loose struct {
			Method string `json:"method"`
			Params struct {
				Name string `json:"name"`
			} `json:"params"`
		}
		// encoding/json matches keys without regard to case, as many a
		// connector does: it reads the same call.
		if json.Unmarshal(body, &loose) == nil && (loose.Method != m.method || (m.method == MethodToolsCall && loose.Params.Name != m.tool)) {
			t.Fatalf("read %+v, a case-blind connector reads %+v: %q", m, loose, body)
		}
	})
}

// A caller that may not use a connection gets 404 connection_not_found for
// every request to it, a wrong kind included, byte for byte the answer of
// an id that names nothing; an oversized body is 413 whether the id exists
// or not; one question is asked per request, and none for an id that names
// nothing.
func TestNothingTellsAnIdBeforeTheQuestion(t *testing.T) {
	r := newRig(t, false)
	c := r.noted()
	web := r.keyed()
	body, headers := rpc("tools/list", nil)
	nothing := r.send(http.MethodPost, "/v1/connections/con_nothing/mcp", "bob", strings.NewReader(body), headers...)
	if nothing.status != http.StatusNotFound || len(r.az.questions()) != 0 {
		t.Fatalf("an id that names nothing: %d %s", nothing.status, nothing.body)
	}
	for _, id := range []string{c.ID, web.ID} {
		before := len(r.az.questions())
		for _, method := range MCPMethods {
			var rd io.Reader
			if method == http.MethodPost {
				rd = strings.NewReader(body)
			}
			a := r.send(method, "/v1/connections/"+id+"/mcp", "bob", rd, headers...)
			if a.status != http.StatusNotFound || !bytes.Equal(a.body, nothing.body) {
				t.Errorf("%s by another owner to %s: %d %s", method, id, a.status, a.body)
			}
		}
		if got := len(r.az.questions()) - before; got != len(MCPMethods) {
			t.Errorf("%d questions for %d requests", got, len(MCPMethods))
		}
	}
	if a := r.send(http.MethodPost, address(web, "mcp"), "alice", strings.NewReader(body), headers...); a.status != http.StatusConflict || a.code() != "wrong_kind" {
		t.Fatalf("the owner at an address of another kind: %d %s", a.status, a.body)
	}
	if a := r.send(http.MethodGet, address(c, "http")+"/user", "alice", nil); a.status != http.StatusConflict || a.code() != "wrong_kind" {
		t.Fatalf("a connection of kind mcp at the forwarding address: %d %s", a.status, a.body)
	}
	before := len(r.az.questions())
	for _, id := range []string{c.ID, "con_nothing"} {
		if a := r.send(http.MethodPut, "/v1/connections/"+id+"/mcp", "alice", strings.NewReader(body)); a.status != http.StatusBadRequest || a.detail("reason") != "method" {
			t.Errorf("a method the address does not take on %s: %d %s", id, a.status, a.body)
		}
	}
	if len(r.az.questions()) != before || len(r.mcp.Requests()) != 0 {
		t.Fatal("a refused request was asked about or forwarded")
	}
	if r.c.Handles(httpRequest(t, address(c, "mcp")+"/below")) || !r.c.Handles(httpRequest(t, address(c, "mcp"))) {
		t.Fatal("the MCP address has no path below it")
	}
	if got := r.c.Pattern(httpRequest(t, address(c, "mcp"))); got != "/v1/connections/{id}/mcp" {
		t.Fatalf("the pattern %s", got)
	}
}

// The effect follows the marks and not the server's hints; a writing tool
// under ReadOnly, a tool outside Tools and a hidden tool are 403, a
// tools/list under ReadOnly passes, the limit per minute and the
// seventeenth request in flight on one connection are 429, and a refused
// call opens no credential and reaches no connector.
func TestLimitsOfAnAllow(t *testing.T) {
	r := newRig(t, false)
	c := r.noted()
	for tool, effect := range map[string]string{"search_notes": "read", "get_note": "read", "count": "read", "create_note": "write"} {
		before := len(r.az.questions())
		if a := r.call(c, "alice", tool, nil); a.status != http.StatusOK {
			t.Fatalf("%s: %d %s", tool, a.status, a.body)
		}
		if q := r.az.questions()[before]; q.Resource.Fields["effect"] != effect || q.Resource.Fields["tool"] != tool {
			t.Errorf("%s asked %+v", tool, q.Resource.Fields)
		}
	}
	opened, reached := r.sealer.opens(), len(r.mcp.Requests())
	refused := func(l authorizer.Limits, tool, reason string) {
		t.Helper()
		r.az.set(l)
		a := r.call(c, "alice", tool, nil)
		if a.status != http.StatusForbidden || a.detail("field") != "tool" || a.detail("reason") != reason {
			t.Errorf("%s under %+v: %d %s", tool, l, a.status, a.body)
		}
	}
	refused(authorizer.Limits{ReadOnly: true}, "create_note", "read_only")
	refused(authorizer.Limits{Tools: []string{"get_*"}}, "search_notes", "tools")
	refused(authorizer.Limits{}, "delete_notebook", "hidden")
	if r.sealer.opens() != opened || len(r.mcp.Requests()) != reached {
		t.Fatal("a refused call opened the credential or reached the connector")
	}
	r.az.set(authorizer.Limits{ReadOnly: true, Tools: []string{"get_*"}})
	if a := r.list(c, "alice"); a.status != http.StatusOK {
		t.Fatalf("a list under ReadOnly and Tools: %d %s", a.status, a.body)
	}
	if a := r.call(c, "alice", "get_note", nil); a.status != http.StatusOK {
		t.Fatalf("a reading tool inside Tools: %d %s", a.status, a.body)
	}
	r.az.set(authorizer.Limits{CallsPerMinute: 1})
	if a := r.list(c, "alice"); a.status != http.StatusOK {
		t.Fatalf("the first of the minute: %d %s", a.status, a.body)
	}
	if a := r.list(c, "alice"); a.status != http.StatusTooManyRequests || a.detail("reason") != "calls_per_minute=1" {
		t.Fatalf("past the rate: %d %s", a.status, a.body)
	}
	got := r.calls(c)
	denied := 0
	for _, call := range got {
		if call.Outcome == OutcomeDenied {
			denied++
		}
	}
	if denied != 1 {
		t.Fatalf("denied calls recorded %d times in a minute: %+v", denied, got)
	}

	// Sixteen streams that never end hold the connection's places; the
	// seventeenth is refused, and another connection is served.
	r.az.set(authorizer.Limits{})
	r.mcp.Set(func(sw *stubs.ConnectorSwitches) { sw.Endless = true })
	ctx, cancel := context.WithCancel(context.Background())
	held := make([]*http.Response, 0, PerConnection)
	for range PerConnection {
		body, headers := rpc("tools/call", map[string]any{"name": "count"})
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.srv.URL+address(c, "mcp"), strings.NewReader(body))
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
		held = append(held, resp)
	}
	a := r.list(c, "alice")
	if a.status != http.StatusTooManyRequests || a.detail("reason") != "connection_inflight=16" || a.header.Get("Retry-After") != "1" {
		t.Fatalf("the seventeenth: %d %v %s", a.status, a.header, a.body)
	}
	other := r.connect("alice", "notes-open", store.Secrets{}, store.Meta{})
	if a := r.list(other, "alice"); a.status != http.StatusOK {
		t.Fatalf("another connection: %d %s", a.status, a.body)
	}
	cancel()
	for _, resp := range held {
		closeBody(resp)
	}
	r.serving.Wait()
	if a := r.list(c, "alice"); a.status != http.StatusOK {
		t.Fatalf("the places came back: %d %s", a.status, a.body)
	}
}

// A 401 gets one refresh and one more attempt with the same body, a second
// moves the connection to needs_reconnect with revoked, a client's token is
// minted anew once, a pasted key moves at once with credential_refused, a
// connection with no credential passes the 401 less its challenge, and a
// pending connection keeps its state and takes the reason.
func TestConnectorRefusesTheCredential(t *testing.T) {
	r := newRig(t, false)
	ctx := t.Context()
	state := func(c store.Connection) store.Connection {
		t.Helper()
		row, err := r.st.Connections().Get(ctx, c.ID)
		if err != nil {
			t.Fatal(err)
		}
		return row
	}
	refuse := func(credentials ...string) {
		r.mcp.Set(func(sw *stubs.ConnectorSwitches) { sw.Refuse, sw.RefuseAll = credentials, len(credentials) == 0 })
	}
	accept := func() { r.mcp.Set(func(sw *stubs.ConnectorSwitches) { sw.Refuse, sw.RefuseAll = nil, false }) }

	signed, old := r.signedInTo("notes-signed", "alice", time.Now().Add(time.Hour))
	refuse("Bearer " + old)
	if a := r.call(signed, "alice", "get_note", map[string]any{"id": 1}); a.status != http.StatusOK {
		t.Fatalf("a refused token, refreshed: %d %s", a.status, a.body)
	}
	got := r.mcp.Requests()
	if len(got) != 2 || got[0].Credential != "Bearer "+old || got[1].Credential == got[0].Credential || !bytes.Equal(got[0].Body, got[1].Body) {
		t.Fatalf("the connector saw %+v", got)
	}
	refuse()
	if a := r.list(signed, "alice"); a.status != http.StatusConflict || a.detail("reason") != store.ReasonRevoked {
		t.Fatalf("refused after a refresh: %d %s", a.status, a.body)
	}
	if row := state(signed); row.State != store.StateNeedsReconnect || row.Reason != store.ReasonRevoked {
		t.Fatalf("the connection is %s %s", row.State, row.Reason)
	}
	norefresh := r.connect("bob", "notes-signed", store.Secrets{AccessToken: "an-access-token-of-bob"}, store.Meta{TokenEndpoint: r.auth.TokenURL(), ClientID: "pons-client"})
	if a := r.list(norefresh, "bob"); a.status != http.StatusConflict || a.detail("reason") != store.ReasonRevoked {
		t.Fatalf("no refresh token: %d %s", a.status, a.body)
	}

	r.auth.AddClient("wh-client", "the-client-secret-01")
	accept()
	m := r.connect("carol", "notes-minted", store.Secrets{ClientSecret: "the-client-secret-01"}, store.Meta{ClientID: "wh-client", TokenEndpoint: r.auth.TokenURL(), Scopes: []string{"read"}})
	if a := r.list(m, "carol"); a.status != http.StatusOK {
		t.Fatalf("a minted token: %d %s", a.status, a.body)
	}
	creds := r.mcp.Credentials()
	refuse(creds[len(creds)-1])
	if a := r.call(m, "carol", "create_note", map[string]any{"title": "x"}); a.status != http.StatusOK {
		t.Fatalf("a token minted anew, the body sent again: %d %s", a.status, a.body)
	}
	refuse()
	if a := r.list(m, "carol"); a.status != http.StatusConflict || a.detail("reason") != store.ReasonCredentialRefused {
		t.Fatalf("a client refused twice: %d %s", a.status, a.body)
	}

	k := r.connect("dave", "notes", store.Secrets{Value: "the-notes-key-of-dave"}, store.Meta{})
	before := len(r.mcp.Requests())
	if a := r.list(k, "dave"); a.status != http.StatusConflict || a.detail("reason") != store.ReasonCredentialRefused {
		t.Fatalf("a refused key: %d %s", a.status, a.body)
	}
	if len(r.mcp.Requests())-before != 1 {
		t.Fatal("a refused key was tried again")
	}

	open := r.connect("erin", "notes-open", store.Secrets{}, store.Meta{})
	if a := r.list(open, "erin"); a.status != http.StatusUnauthorized || a.header.Get("WWW-Authenticate") != "" {
		t.Fatalf("no credential: %d %v", a.status, a.header)
	}
	if row := state(open); row.State != store.StateConnected {
		t.Fatalf("a connection with no credential moved to %s", row.State)
	}

	pending := r.connect("frank", "notes", store.Secrets{Value: "the-notes-key-of-frank"}, store.Meta{})
	if err := r.st.Connections().Move(ctx, pending.ID, store.StateConnected, store.StatePending, ""); err != nil {
		t.Fatal(err)
	}
	if a := r.list(pending, "frank"); a.status != http.StatusConflict {
		t.Fatalf("a pending connection refused: %d %s", a.status, a.body)
	}
	if row := state(pending); row.State != store.StatePending || row.Reason != store.ReasonCredentialRefused {
		t.Fatalf("the pending connection is %s %s", row.State, row.Reason)
	}
	accept()
	if a := r.list(pending, "frank"); a.status != http.StatusConflict || a.detail("state") != "pending" {
		t.Fatalf("a pending connection with a reason: %d %s", a.status, a.body)
	}
	for _, call := range r.calls(signed)[1:] {
		if call.Outcome != OutcomeUpstreamRefused {
			t.Fatalf("records %+v", r.calls(signed))
		}
	}
}

// A request with a foreign Origin is 403 before its token is read; the
// origin of a return address and no origin pass.
func TestOriginIsChecked(t *testing.T) {
	r := newRig(t, false)
	c := r.noted()
	for bearer, want := range map[string]int{"alice": http.StatusForbidden, "": http.StatusForbidden} {
		if a := r.list(c, bearer, "Origin", "https://elsewhere.example.net"); a.status != want || a.detail("reason") != "origin" {
			t.Fatalf("a foreign origin as %q: %d %s", bearer, a.status, a.body)
		}
	}
	if a := r.list(c, "alice", "Origin", "https://app.example.com"); a.status != http.StatusOK {
		t.Fatalf("the origin of a return address: %d %s", a.status, a.body)
	}
	if a := r.list(c, "alice"); a.status != http.StatusOK {
		t.Fatalf("no origin: %d %s", a.status, a.body)
	}
	if len(r.mcp.Requests()) != 2 {
		t.Fatal("a foreign origin reached the connector")
	}
}

// The probe of kind mcp accepts a key with a tools/list, falls back to the
// handshake for a connector of an earlier revision and ends its session,
// and refuses a key the connector answers 401; a connector that cannot be
// reached, or that answers neither, is unreachable.
func TestProbe(t *testing.T) {
	r := newRig(t, false)
	notes, keyed := r.conns["notes"], r.conns["notes-key"]
	key := store.Secrets{Value: "a-probed-key-00001"}
	if err := r.c.Probe(t.Context(), notes, key, store.Meta{}); err != nil {
		t.Fatalf("an accepted key: %v", err)
	}
	got := r.mcp.Requests()
	if len(got) != 1 || got[0].RPC != "tools/list" || got[0].Credential != "Bearer a-probed-key-00001" ||
		got[0].Header.Get("Mcp-Method") != "tools/list" || !strings.Contains(string(got[0].Body), `clientInfo":{"name":"pons"`) {
		t.Fatalf("the probe %+v", got)
	}
	if err := r.c.Probe(t.Context(), keyed, key, store.Meta{Header: "X-Api-Key", Format: "key {value}"}); err != nil {
		t.Fatalf("a key in a header of its own: %v", err)
	}
	if h := r.mcp.Requests()[1].Header; h.Get("X-Api-Key") != "key a-probed-key-00001" || h.Get("Authorization") != "" {
		t.Fatalf("the key's place %v", h)
	}
	r.mcp.Set(func(sw *stubs.ConnectorSwitches) { sw.Refuse = []string{"Bearer a-probed-key-00001"} })
	if err := r.c.Probe(t.Context(), notes, key, store.Meta{}); err == nil || !strings.Contains(err.Error(), "credential_refused") {
		t.Fatalf("a refused key: %v", err)
	}

	r.mcp.Set(func(sw *stubs.ConnectorSwitches) { sw.Refuse, sw.Legacy = nil, true })
	before := len(r.mcp.Requests())
	if err := r.c.Probe(t.Context(), notes, key, store.Meta{}); err != nil {
		t.Fatalf("a connector of an earlier revision: %v", err)
	}
	var steps []string
	for _, q := range r.mcp.Requests()[before:] {
		steps = append(steps, q.Method+" "+q.RPC+" "+q.Session)
	}
	if !slices.Equal(steps, []string{"POST tools/list ", "POST initialize ", "POST notifications/initialized sess-1", "POST tools/list sess-1", "DELETE  sess-1"}) || r.mcp.Sessions() != 0 {
		t.Fatalf("the handshake %q, %d sessions open", steps, r.mcp.Sessions())
	}
	r.mcp.Set(func(sw *stubs.ConnectorSwitches) { sw.RefuseAll = true })
	if err := r.c.Probe(t.Context(), notes, key, store.Meta{}); err == nil || !strings.Contains(err.Error(), "credential_refused") {
		t.Fatalf("a key an earlier revision refuses: %v", err)
	}
	r.mcp.Set(func(sw *stubs.ConnectorSwitches) { sw.RefuseAll, sw.Legacy = false, false })

	elsewhere := notes
	elsewhere.URL = strings.TrimSuffix(r.mcp.URL(), "/mcp") + "/other"
	if err := r.c.Probe(t.Context(), elsewhere, key, store.Meta{}); err == nil || !strings.Contains(err.Error(), "status_404") {
		t.Fatalf("a connector that answers neither: %v", err)
	}
	gone := notes
	gone.URL = "https://nothing.example.org/mcp"
	if err := r.c.Probe(t.Context(), gone, key, store.Meta{}); err == nil || !strings.Contains(err.Error(), "connector_unreachable") {
		t.Fatalf("an unreachable connector: %v", err)
	}
	gone.URL = "https://%zz"
	if err := r.c.Probe(t.Context(), gone, key, store.Meta{}); err == nil || !strings.Contains(err.Error(), "connector_unreachable") {
		t.Fatalf("a url that does not parse: %v", err)
	}
	_ = catalog.KindMCP
}

// A deny of a use for the session's sake, kept_apart_from_google, is 409
// connection_not_connected with that reason at the MCP address and the
// forwarding address alike, recorded as denied and forwarded nowhere; any
// other reason of a deny stays the 404 of an id that names nothing.
func TestASessionsRefusalSaysWhy(t *testing.T) {
	r := newRig(t, false)
	c := r.noted()
	web := r.keyed()
	r.az.deny(authorizer.ReasonKeptApartFromGoogle)
	body, headers := rpc("tools/list", nil)
	for name, a := range map[string]answer{
		"mcp":  r.send(http.MethodPost, address(c, "mcp"), "alice", strings.NewReader(body), headers...),
		"http": r.send(http.MethodGet, address(web, "http")+"/user", "alice", nil),
	} {
		if a.status != http.StatusConflict || a.code() != "connection_not_connected" ||
			a.detail("reason") != authorizer.ReasonKeptApartFromGoogle || a.detail("state") != string(store.StateConnected) {
			t.Errorf("%s: %d %s", name, a.status, a.body)
		}
	}
	if len(r.mcp.Requests()) != 0 || len(r.api.Requests()) != 0 {
		t.Fatal("a refused request was forwarded")
	}
	if got := r.calls(c); len(got) != 1 || got[0].Outcome != OutcomeDenied {
		t.Fatalf("the record %+v", got)
	}
	r.az.deny("not_attached")
	nothing := r.send(http.MethodPost, "/v1/connections/con_nothing/mcp", "alice", strings.NewReader(body), headers...)
	if a := r.send(http.MethodPost, address(c, "mcp"), "alice", strings.NewReader(body), headers...); a.status != http.StatusNotFound || !bytes.Equal(a.body, nothing.body) {
		t.Fatalf("another reason: %d %s", a.status, a.body)
	}
}
