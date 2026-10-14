// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package stubs_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"latere.ai/x/pons/catalog"
	"latere.ai/x/pons/internal/dial"
	"latere.ai/x/pons/test/stubs"
)

// reply is one answer of the stub connector.
type reply struct {
	status int
	header http.Header
	body   string
}

// mcpSend sends one request to the stub connector through the dialer: a
// message of the current revision, with its mirrored headers, unless
// headers say otherwise.
func mcpSend(t *testing.T, c *stubs.Connector, method, credential, body string, headers ...string) reply {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(t.Context(), method, c.URL(), rd)
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Method string `json:"method"`
		Params struct {
			Name string `json:"name"`
		} `json:"params"`
	}
	if body != "" && json.Unmarshal([]byte(body), &m) == nil {
		req.Header.Set("MCP-Protocol-Version", stubs.MCPRevision)
		req.Header.Set("Mcp-Method", m.Method)
		req.Header.Set("Mcp-Name", m.Params.Name)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	var secrets []dial.Secret
	if credential != "" {
		secrets = append(secrets, dial.Secret{Value: credential, Header: "Authorization", Hosts: catalog.Matcher([]string{"*.example.com"})})
	}
	resp, err := outside(c.Port()).Do(t.Context(), dial.Request{HTTP: req, Secrets: secrets, Forward: true, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("%s: %v", method, err)
	}
	raw, err := io.ReadAll(resp.Body)
	if cerr := resp.Body.Close(); err != nil || cerr != nil {
		t.Fatal(err, cerr)
	}
	return reply{status: resp.StatusCode, header: resp.Header, body: string(raw)}
}

// message is a JSON-RPC request of the current revision.
func message(method, params string) string {
	meta := `"_meta":{"io.modelcontextprotocol/protocolVersion":"` + stubs.MCPRevision + `"}`
	if params == "" {
		params = "{" + meta + "}"
	} else {
		params = strings.Replace(params, "{", "{"+meta+",", 1)
	}
	return `{"jsonrpc":"2.0","id":1,"method":"` + method + `","params":` + params + `}`
}

// The stub connector answers an initialize, a tool list, a tool call and a
// streamed call by its name through the dialer, holds a message's mirrored
// headers to its body, and records the credential each request carried.
func TestConnectorSpeaksStreamableHTTP(t *testing.T) {
	c := stubs.NewConnector(t)
	if !strings.HasPrefix(c.URL(), "https://mcp.example.com:") || !strings.HasSuffix(c.URL(), "/mcp") {
		t.Fatalf("the stub is not named: %s", c.URL())
	}
	if a := mcpSend(t, c, http.MethodPost, "Bearer k", message("initialize", "")); a.status != http.StatusOK || !strings.Contains(a.body, stubs.MCPRevision) {
		t.Fatalf("initialize: %d %s", a.status, a.body)
	}
	a := mcpSend(t, c, http.MethodPost, "Bearer k", message("tools/list", ""))
	for _, name := range stubs.ConnectorTools {
		if !strings.Contains(a.body, `"name":"`+name+`"`) {
			t.Errorf("tools/list lacks %s: %s", name, a.body)
		}
	}
	if a := mcpSend(t, c, http.MethodPost, "Bearer k", message("tools/call", `{"name":"get_note","arguments":{"id":1}}`)); a.status != http.StatusOK ||
		!strings.Contains(a.body, `get_note {\"id\":1}`) || a.header.Get("Content-Type") != "application/json" {
		t.Fatalf("a call: %d %s", a.status, a.body)
	}
	a = mcpSend(t, c, http.MethodPost, "Bearer k", message("tools/call", `{"name":"count"}`))
	if a.header.Get("Content-Type") != "text/event-stream" || strings.Count(a.body, "notifications/progress") != 3 || !strings.Contains(a.body, `"result"`) {
		t.Fatalf("a streamed call: %v %s", a.header, a.body)
	}
	for body, want := range map[string]int{
		message("tools/call", `{"name":"nope"}`):                                    http.StatusOK,
		message("resources/list", ""):                                               http.StatusOK,
		strings.Replace(message("notifications/initialized", ""), `"id":1,`, "", 1): http.StatusAccepted,
		`not json`: http.StatusBadRequest,
		strings.Replace(message("tools/list", ""), stubs.MCPRevision, "x", 1): http.StatusBadRequest,
	} {
		if a := mcpSend(t, c, http.MethodPost, "", body); a.status != want {
			t.Errorf("%s: %d %s", body, a.status, a.body)
		}
	}
	if a := mcpSend(t, c, http.MethodPost, "", message("tools/call", `{"name":"get_note"}`), "Mcp-Name", "create_note"); a.status != http.StatusBadRequest || !strings.Contains(a.body, "-32020") {
		t.Fatalf("a mirrored name that differs: %d %s", a.status, a.body)
	}
	if a := mcpSend(t, c, http.MethodPost, "", message("tools/call", `{"name":"get_note"}`), "Mcp-Name", "=?base64?Z2V0X25vdGU=?="); a.status != http.StatusOK {
		t.Fatalf("a mirrored name in base64: %d %s", a.status, a.body)
	}
	if a := mcpSend(t, c, http.MethodPost, "", message("tools/list", ""), "Mcp-Method", "tools/call"); a.status != http.StatusBadRequest {
		t.Fatalf("a mirrored method that differs: %d %s", a.status, a.body)
	}
	if a := mcpSend(t, c, http.MethodGet, "", ""); a.status != http.StatusMethodNotAllowed {
		t.Fatalf("a GET of the current revision: %d", a.status)
	}
	got := c.Requests()
	if got[0].RPC != "initialize" || got[0].Credential != "Bearer k" || got[2].Tool != "get_note" || c.Credentials()[0] != "Bearer k" {
		t.Fatalf("recorded %+v", got[:3])
	}
}

// Each switch changes one answer and nothing else, and the earlier
// revision speaks its handshake, its session, GET and DELETE.
func TestEachSwitchChangesOneAnswer(t *testing.T) {
	c := stubs.NewConnector(t)
	list := message("tools/list", "")
	set := func(change func(*stubs.ConnectorSwitches)) {
		c.Set(func(sw *stubs.ConnectorSwitches) { *sw = stubs.ConnectorSwitches{} })
		c.Set(change)
	}
	set(func(sw *stubs.ConnectorSwitches) { sw.Refuse = []string{"Bearer bad"} })
	if a := mcpSend(t, c, http.MethodPost, "Bearer bad", list); a.status != http.StatusUnauthorized || a.header.Get("WWW-Authenticate") == "" {
		t.Fatalf("a refused credential: %d", a.status)
	}
	if a := mcpSend(t, c, http.MethodPost, "Bearer good", list); a.status != http.StatusOK {
		t.Fatalf("another credential: %d", a.status)
	}
	set(func(sw *stubs.ConnectorSwitches) { sw.RefuseAll = true })
	if a := mcpSend(t, c, http.MethodPost, "Bearer good", list); a.status != http.StatusUnauthorized {
		t.Fatalf("every credential refused: %d", a.status)
	}
	set(func(sw *stubs.ConnectorSwitches) { sw.Insufficient = []string{"notes:write"} })
	if a := mcpSend(t, c, http.MethodPost, "Bearer good", list); a.status != http.StatusForbidden || !strings.Contains(a.header.Get("WWW-Authenticate"), `scope="notes:write"`) {
		t.Fatalf("a scope challenge: %d %v", a.status, a.header)
	}
	set(func(sw *stubs.ConnectorSwitches) { sw.Redirect = true })
	if a := mcpSend(t, c, http.MethodPost, "", list); a.status != http.StatusTemporaryRedirect || a.header.Get("Location") == "" {
		t.Fatalf("a redirect: %d", a.status)
	}
	set(func(sw *stubs.ConnectorSwitches) { sw.Cookie = true })
	if a := mcpSend(t, c, http.MethodPost, "", list); a.status != http.StatusOK || a.header.Get("Set-Cookie") == "" {
		t.Fatalf("a cookie: %d %v", a.status, a.header)
	}
	set(func(sw *stubs.ConnectorSwitches) { sw.Slow = 200 * time.Millisecond })
	if start := time.Now(); mcpSend(t, c, http.MethodPost, "", list).status != http.StatusOK || time.Since(start) < 200*time.Millisecond {
		t.Fatal("slow headers")
	}
	set(func(sw *stubs.ConnectorSwitches) { sw.Gap = 100 * time.Millisecond })
	if start := time.Now(); mcpSend(t, c, http.MethodPost, "", message("tools/call", `{"name":"count"}`)).status != http.StatusOK || time.Since(start) < 300*time.Millisecond {
		t.Fatal("a slow stream")
	}
	set(func(sw *stubs.ConnectorSwitches) { sw.AnswerBytes = 1 << 20 })
	if a := mcpSend(t, c, http.MethodPost, "", message("tools/call", `{"name":"get_note"}`)); len(a.body) < 1<<20 {
		t.Fatalf("an oversized answer of %d bytes", len(a.body))
	}
	set(func(sw *stubs.ConnectorSwitches) { sw.HugeHeaders = true })
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, c.URL(), strings.NewReader(list))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := outside(c.Port()).Do(t.Context(), dial.Request{HTTP: req, Forward: true}); err == nil || !strings.Contains(err.Error(), dial.ResponseTooLarge) {
		t.Fatalf("oversized headers: %v", err)
	}
	set(func(sw *stubs.ConnectorSwitches) {
		sw.Servers, sw.Scopes = []string{"https://auth.example.com"}, []string{"notes"}
	})
	a := mcpSend(t, c, http.MethodPost, "", list)
	if a.status != http.StatusUnauthorized || !strings.Contains(a.header.Get("WWW-Authenticate"), "resource_metadata=") {
		t.Fatalf("a protected resource: %d %v", a.status, a.header)
	}
	answer, err := outside(c.Port()).Fetch(t.Context(), strings.TrimSuffix(c.URL(), "/mcp")+"/.well-known/oauth-protected-resource/mcp", []int{c.Port()})
	if err != nil || answer.Status != http.StatusOK || !strings.Contains(string(answer.Body), `"authorization_servers":["https://auth.example.com"]`) {
		t.Fatalf("the metadata: %v %+v", err, answer)
	}
	if a := mcpSend(t, c, http.MethodPost, "Bearer k", list); a.status != http.StatusOK {
		t.Fatalf("a protected resource with a credential: %d", a.status)
	}

	// A stream that never ends, and one that waits for the test, each end
	// when their caller goes away.
	for _, sw := range []func(*stubs.ConnectorSwitches){
		func(sw *stubs.ConnectorSwitches) { sw.Endless = true },
		func(sw *stubs.ConnectorSwitches) { sw.Stepped = true },
	} {
		set(sw)
		before := c.Left()
		ctx, cancel := context.WithCancel(t.Context())
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL(), strings.NewReader(message("tools/call", `{"name":"count"}`)))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("MCP-Protocol-Version", stubs.MCPRevision)
		req.Header.Set("Mcp-Method", "tools/call")
		req.Header.Set("Mcp-Name", "count")
		resp, err := outside(c.Port()).Do(ctx, dial.Request{HTTP: req, Forward: true})
		if err != nil {
			t.Fatal(err)
		}
		first := make([]byte, 16)
		if _, err := io.ReadFull(resp.Body, first); err != nil {
			t.Fatal(err)
		}
		cancel()
		if err := resp.Body.Close(); err != nil && !strings.Contains(err.Error(), "canceled") {
			t.Fatal(err)
		}
		deadline := time.Now().Add(5 * time.Second)
		for c.Left() == before && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if c.Left() != before+1 {
			t.Fatal("a stream outlived its caller")
		}
	}
	set(func(sw *stubs.ConnectorSwitches) { sw.Stepped = true })
	done := make(chan reply, 1)
	go func() { done <- mcpSend(t, c, http.MethodPost, "", message("tools/call", `{"name":"count"}`)) }()
	for range 3 {
		c.Step()
	}
	if a := <-done; strings.Count(a.body, "event: message") != 4 {
		t.Fatalf("a stepped stream: %s", a.body)
	}

	set(func(sw *stubs.ConnectorSwitches) { sw.Legacy = true })
	if a := mcpSend(t, c, http.MethodPost, "", list); a.status != http.StatusBadRequest || strings.Contains(a.body, "jsonrpc") {
		t.Fatalf("the current revision at an earlier one: %d %s", a.status, a.body)
	}
	init := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"` + stubs.MCPLegacy + `"}}`
	a = mcpSend(t, c, http.MethodPost, "", init, "MCP-Protocol-Version", "")
	session := a.header.Get("Mcp-Session-Id")
	if a.status != http.StatusOK || session == "" || c.Sessions() != 1 {
		t.Fatalf("initialize: %d %v", a.status, a.header)
	}
	legacy := []string{"MCP-Protocol-Version", stubs.MCPLegacy, "Mcp-Session-Id", session, "Mcp-Method", "", "Mcp-Name", ""}
	if a := mcpSend(t, c, http.MethodPost, "", `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`, legacy...); a.status != http.StatusOK || a.header.Get("Mcp-Session-Id") != session {
		t.Fatalf("a list in the session: %d %s", a.status, a.body)
	}
	if a := mcpSend(t, c, http.MethodPost, "", `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`, "MCP-Protocol-Version", stubs.MCPLegacy, "Mcp-Session-Id", "sess-none", "Mcp-Method", ""); a.status != http.StatusNotFound {
		t.Fatalf("a session the stub does not hold: %d", a.status)
	}
	if a := mcpSend(t, c, http.MethodPost, "", `not json`, legacy...); a.status != http.StatusBadRequest {
		t.Fatalf("a body that does not parse in a session: %d", a.status)
	}
	if a := mcpSend(t, c, http.MethodPut, "", "", legacy...); a.status != http.StatusMethodNotAllowed {
		t.Fatalf("a method of no revision: %d", a.status)
	}
	ctx, cancel := context.WithCancel(t.Context())
	req, err = http.NewRequestWithContext(ctx, http.MethodGet, c.URL(), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Mcp-Session-Id", session)
	resp, err := outside(c.Port()).Do(ctx, dial.Request{HTTP: req, Forward: true})
	if err != nil {
		t.Fatal(err)
	}
	first := make([]byte, 16)
	if _, err := io.ReadFull(resp.Body, first); err != nil || resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("a GET stream: %v %v", err, resp.Header)
	}
	cancel()
	if err := resp.Body.Close(); err != nil && !strings.Contains(err.Error(), "canceled") {
		t.Fatal(err)
	}
	if a := mcpSend(t, c, http.MethodDelete, "", "", legacy...); a.status != http.StatusOK || c.Sessions() != 0 {
		t.Fatalf("a DELETE: %d, %d sessions", a.status, c.Sessions())
	}
	if a := mcpSend(t, c, http.MethodPost, "", list, "Mcp-Session-Id", session); a.status != http.StatusBadRequest {
		t.Fatalf("the current revision in an ended session: %d", a.status)
	}
	if a := mcpSend(t, c, http.MethodGet, "", "", "Mcp-Session-Id", session); a.status != http.StatusNotFound {
		t.Fatalf("an ended session: %d", a.status)
	}
	other, err := http.NewRequestWithContext(t.Context(), http.MethodGet, strings.TrimSuffix(c.URL(), "/mcp")+"/other", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err = outside(c.Port()).Do(t.Context(), dial.Request{HTTP: other, Forward: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := resp.Body.Close(); err != nil || resp.StatusCode != http.StatusNotFound {
		t.Fatalf("another path: %d %v", resp.StatusCode, err)
	}
}
