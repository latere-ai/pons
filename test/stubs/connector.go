// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package stubs

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The protocol revisions the stub connector speaks: Revision by default,
// and Legacy alone under the switch of that name.
const (
	MCPRevision = "2026-07-28"
	MCPLegacy   = "2025-11-25"
)

// ConnectorTools are the tools the stub connector lists, by name. A catalog
// entry for it marks the first two read-only, as their names say, and may
// hide the last. A tool's answer holds its arguments and never a header of
// the request it answers, so a credential found in an answer came from
// somewhere other than the stub.
var ConnectorTools = []string{"search_notes", "get_note", "count", "create_note", "delete_notebook"}

// Connector is the stub connector: a Model Context Protocol server over
// streamable HTTP at /mcp, behind a connector of kind mcp
// (specs/008-carrying-a-call.md). It speaks revision 2026-07-28, a message
// per POST with its mirrored headers held to its body, and answers
// initialize, tools/list, tools/call and a notification. count answers on
// an event stream, a progress notification per step before its result. It
// records every request with the credential it carried.
//
// Its switches, set with Set, are the answers of a connector that misbehaves
// or speaks an earlier revision: a 401, a scope challenge, a redirect, a
// cookie, slow headers, a slow or an endless stream, a stream that waits for
// the test between events, an oversized answer, oversized headers, a
// protected resource that challenges a request with no credential, and
// revision 2025-11-25 with its initialize handshake, its sessions, GET and
// DELETE.
type Connector struct {
	url  string
	port int
	// steps release the events of a stepped stream, one each.
	steps chan struct{}

	mu       sync.Mutex
	requests []ConnectorRequest
	sw       ConnectorSwitches
	sessions map[string]bool
	next     int
	// left counts the streams that ended because their caller went away.
	left int
}

// ConnectorSwitches change the stub connector's answers. The zero value is
// a well-behaved server of the current revision.
type ConnectorSwitches struct {
	// Refuse answers 401 with a challenge to every request that carries
	// one of these credentials, the whole Authorization header; RefuseAll
	// to every request.
	Refuse    []string
	RefuseAll bool
	// Insufficient answers every request 403 with a challenge for these
	// scopes (RFC 6750, section 3.1), while it is not nil.
	Insufficient []string
	// Redirect answers every request 307 to an address elsewhere.
	Redirect bool
	// Cookie sets a cookie on every answer.
	Cookie bool
	// Slow delays the headers of every answer.
	Slow time.Duration
	// Gap is the time between two events of a stream; 10ms when zero.
	Gap time.Duration
	// Endless makes count's stream send keep-alive comments and never its
	// result, until the caller goes away.
	Endless bool
	// Stepped makes count's stream wait for Step before each event after
	// its first.
	Stepped bool
	// AnswerBytes pads every answer to a tools/call to at least this many
	// bytes.
	AnswerBytes int
	// HugeHeaders adds a header of more than 64 KiB to every answer.
	HugeHeaders bool
	// Servers and Scopes make the stub a protected resource (RFC 9728),
	// while Servers is not nil: a request with no credential is answered
	// 401 with a challenge naming its metadata and the scopes, and the
	// metadata names the authorization servers.
	Servers []string
	Scopes  []string
	// Legacy speaks revision 2025-11-25 alone: a request of the current
	// revision is answered 400 with no JSON-RPC error, initialize opens a
	// session, every later request names one, GET opens a stream in it and
	// DELETE ends it.
	Legacy bool
}

// ConnectorRequest is one request the stub connector served.
type ConnectorRequest struct {
	// Method is the HTTP method; RPC the JSON-RPC method of a POST, empty
	// for a reply; Tool the name a tools/call names.
	Method, RPC, Tool string
	Header            http.Header
	// Credential is the Authorization header the request carried.
	Credential string
	// Session is the Mcp-Session-Id it carried.
	Session string
	Body    []byte
}

// NewConnector starts a stub connector for the test, at mcp.example.com.
func NewConnector(t TB) *Connector {
	t.Helper()
	c := &Connector{sessions: map[string]bool{}, steps: make(chan struct{}, 64)}
	srv := serveTLS(t, http.HandlerFunc(c.serve), "mcp."+Domain)
	c.port = portOf(srv.URL)
	c.url = named("mcp."+Domain, c.port) + "/mcp"
	return c
}

// URL is the server's MCP address, by its name: the value of a catalog
// entry's url.
func (c *Connector) URL() string { return c.url }

// Port is the port the stub listens on.
func (c *Connector) Port() int { return c.port }

// Set changes the switches.
func (c *Connector) Set(change func(*ConnectorSwitches)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	change(&c.sw)
}

// Step releases the next event of a stepped stream.
func (c *Connector) Step() { c.steps <- struct{}{} }

// Requests is every request served, in order.
func (c *Connector) Requests() []ConnectorRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.requests)
}

// Credentials is the credential every request carried, in order.
func (c *Connector) Credentials() []string {
	var out []string
	for _, r := range c.Requests() {
		out = append(out, r.Credential)
	}
	return out
}

// Left is how many of the stub's streams ended because the request that
// opened them was canceled, the caller having gone away.
func (c *Connector) Left() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.left
}

// leave counts a stream whose caller went away.
func (c *Connector) leave() {
	c.mu.Lock()
	c.left++
	c.mu.Unlock()
}

// Sessions is how many sessions of the earlier revision are open.
func (c *Connector) Sessions() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.sessions)
}

// rpc is the part of a JSON-RPC message the stub reads.
type rpc struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
		Meta      map[string]any  `json:"_meta"`
	} `json:"params"`
}

func (c *Connector) serve(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "the body did not read", http.StatusBadRequest)
		return
	}
	var m rpc
	if r.Method == http.MethodPost {
		// A body that does not parse is answered below, once recorded.
		_ = json.Unmarshal(body, &m)
	}
	c.mu.Lock()
	c.requests = append(c.requests, ConnectorRequest{
		Method: r.Method, RPC: m.Method, Tool: m.Params.Name, Header: r.Header.Clone(),
		Credential: r.Header.Get("Authorization"), Session: r.Header.Get("Mcp-Session-Id"), Body: body,
	})
	sw := c.sw
	c.mu.Unlock()
	credential := r.Header.Get("Authorization")
	if sw.Slow > 0 {
		select {
		case <-time.After(sw.Slow):
		case <-r.Context().Done():
			return
		}
	}
	if sw.Cookie {
		w.Header().Set("Set-Cookie", "session=stub; Secure; HttpOnly")
	}
	if sw.HugeHeaders {
		w.Header().Set("X-Stub-Padding", strings.Repeat("h", 65<<10))
	}
	if r.URL.Path == "/.well-known/oauth-protected-resource/mcp" && sw.Servers != nil {
		writeStubJSON(w, http.StatusOK, map[string]any{"resource": c.url, "authorization_servers": sw.Servers, "scopes_supported": sw.Scopes})
		return
	}
	switch {
	case r.URL.Path != "/mcp":
		http.NotFound(w, r)
		return
	case sw.Servers != nil && credential == "" && r.Header.Get("X-Api-Key") == "":
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata=%q, scope=%q`,
			named("mcp."+Domain, c.port)+"/.well-known/oauth-protected-resource/mcp", strings.Join(sw.Scopes, " ")))
		writeStubJSON(w, http.StatusUnauthorized, map[string]any{"message": "Requires authentication"})
		return
	case sw.RefuseAll || (credential != "" && slices.Contains(sw.Refuse, credential)):
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", resource_metadata="https://elsewhere.example.net/.well-known/oauth-protected-resource"`)
		writeStubJSON(w, http.StatusUnauthorized, map[string]any{"message": "Bad credentials"})
		return
	case sw.Insufficient != nil:
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer error="insufficient_scope", scope=%q`, strings.Join(sw.Insufficient, " ")))
		writeStubJSON(w, http.StatusForbidden, map[string]any{"message": "Insufficient scope"})
		return
	case sw.Redirect:
		w.Header().Set("Location", "https://elsewhere.example.net/mcp")
		w.WriteHeader(http.StatusTemporaryRedirect)
		return
	}
	if sw.Legacy {
		c.legacy(w, r, m, body, sw)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "the current revision takes POST alone", http.StatusMethodNotAllowed)
		return
	}
	if json.Unmarshal(body, &m) != nil {
		writeRPCError(w, http.StatusBadRequest, nil, -32700, "Parse error")
		return
	}
	if why := mirrored(r.Header, m); why != "" {
		writeRPCError(w, http.StatusBadRequest, m.ID, -32020, "Header mismatch: "+why)
		return
	}
	c.answer(w, r, m, sw)
}

// mirrored is why a request of the current revision's headers differ from
// its body, "" when they agree.
func mirrored(h http.Header, m rpc) string {
	version, _ := m.Params.Meta["io.modelcontextprotocol/protocolVersion"].(string)
	switch {
	case m.Method == "":
		return ""
	case h.Get("MCP-Protocol-Version") != MCPRevision || version != MCPRevision:
		return fmt.Sprintf("MCP-Protocol-Version %q, the body's %q", h.Get("MCP-Protocol-Version"), version)
	case h.Get("Mcp-Method") != m.Method:
		return fmt.Sprintf("Mcp-Method %q, the body's %q", h.Get("Mcp-Method"), m.Method)
	case m.Method == "tools/call" && decodeHeader(h.Get("Mcp-Name")) != m.Params.Name:
		return fmt.Sprintf("Mcp-Name %q, the body's %q", h.Get("Mcp-Name"), m.Params.Name)
	}
	return ""
}

// decodeHeader is a header value in the transport's base64 form decoded.
func decodeHeader(v string) string {
	if inner, ok := strings.CutPrefix(v, "=?base64?"); ok {
		if inner, ok = strings.CutSuffix(inner, "?="); ok {
			if b, err := base64.StdEncoding.DecodeString(inner); err == nil {
				return string(b)
			}
		}
	}
	return v
}

// legacy speaks revision 2025-11-25.
func (c *Connector) legacy(w http.ResponseWriter, r *http.Request, m rpc, body []byte, sw ConnectorSwitches) {
	if r.Header.Get("MCP-Protocol-Version") == MCPRevision {
		http.Error(w, "Bad Request: no valid session ID provided", http.StatusBadRequest)
		return
	}
	if r.Method == http.MethodPost && m.Method == "initialize" {
		c.mu.Lock()
		c.next++
		id := "sess-" + strconv.Itoa(c.next)
		c.sessions[id] = true
		c.mu.Unlock()
		w.Header().Set("Mcp-Session-Id", id)
		writeStubJSON(w, http.StatusOK, map[string]any{"jsonrpc": "2.0", "id": m.ID, "result": map[string]any{
			"protocolVersion": MCPLegacy, "capabilities": map[string]any{"tools": map[string]any{}},
			"serverInfo": map[string]string{"name": "stub-connector", "version": "1"},
		}})
		return
	}
	session := r.Header.Get("Mcp-Session-Id")
	c.mu.Lock()
	known := c.sessions[session]
	c.mu.Unlock()
	switch {
	case !known:
		http.Error(w, "no such session", http.StatusNotFound)
	case r.Method == http.MethodDelete:
		c.mu.Lock()
		delete(c.sessions, session)
		c.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	case r.Method == http.MethodGet:
		c.listen(w, r)
	case r.Method != http.MethodPost:
		http.Error(w, "not a method of the protocol", http.StatusMethodNotAllowed)
	case json.Unmarshal(body, &m) != nil:
		writeRPCError(w, http.StatusBadRequest, nil, -32700, "Parse error")
	default:
		w.Header().Set("Mcp-Session-Id", session)
		c.answer(w, r, m, sw)
	}
}

// listen is the stream a GET opens in a session of the earlier revision:
// one notification that the tools changed, then nothing until the caller
// goes away.
func (c *Connector) listen(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	note := map[string]any{"jsonrpc": "2.0", "method": "notifications/tools/list_changed"}
	if !writeEvent(w, "1", note) {
		return
	}
	<-r.Context().Done()
	c.leave()
}

// answer answers one message: a notification or a reply is accepted, and a
// request by its method.
func (c *Connector) answer(w http.ResponseWriter, r *http.Request, m rpc, sw ConnectorSwitches) {
	if len(m.ID) == 0 || m.Method == "" {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	switch m.Method {
	case "initialize":
		writeStubJSON(w, http.StatusOK, map[string]any{"jsonrpc": "2.0", "id": m.ID, "result": map[string]any{
			"protocolVersion": MCPRevision, "capabilities": map[string]any{"tools": map[string]any{}},
			"serverInfo": map[string]string{"name": "stub-connector", "version": "1"},
		}})
	case "tools/list":
		var tools []map[string]any
		for _, name := range ConnectorTools {
			tools = append(tools, map[string]any{
				"name": name, "inputSchema": map[string]any{"type": "object"},
				// A server's own hint, which a caller does not trust: it
				// calls every tool read-only.
				"annotations": map[string]any{"readOnlyHint": true},
			})
		}
		writeStubJSON(w, http.StatusOK, map[string]any{"jsonrpc": "2.0", "id": m.ID, "result": map[string]any{"tools": tools}})
	case "tools/call":
		c.call(w, r, m, sw)
	default:
		writeRPCError(w, http.StatusOK, m.ID, -32601, "Method not found")
	}
}

// call answers a tools/call with its arguments, count on an event stream.
func (c *Connector) call(w http.ResponseWriter, r *http.Request, m rpc, sw ConnectorSwitches) {
	if !slices.Contains(ConnectorTools, m.Params.Name) {
		writeRPCError(w, http.StatusOK, m.ID, -32602, "Unknown tool")
		return
	}
	args := string(m.Params.Arguments)
	if args == "" {
		args = "{}"
	}
	text := m.Params.Name + " " + args
	if pad := sw.AnswerBytes - len(text); pad > 0 {
		text += strings.Repeat(".", pad)
	}
	result := map[string]any{"jsonrpc": "2.0", "id": m.ID, "result": map[string]any{
		"content": []map[string]any{{"type": "text", "text": text}},
	}}
	if m.Params.Name != "count" {
		writeStubJSON(w, http.StatusOK, result)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	gap := sw.Gap
	if gap == 0 {
		gap = 10 * time.Millisecond
	}
	for i := 1; ; i++ {
		if i > 1 && !c.wait(r, sw, gap) {
			c.leave()
			return
		}
		if sw.Endless {
			if _, err := io.WriteString(w, ": keep-alive\n\n"); err != nil || http.NewResponseController(w).Flush() != nil {
				return
			}
			continue
		}
		if i > 3 {
			writeEvent(w, strconv.Itoa(i), result)
			return
		}
		progress := map[string]any{"jsonrpc": "2.0", "method": "notifications/progress", "params": map[string]any{"progressToken": "count", "progress": i, "total": 3}}
		if !writeEvent(w, strconv.Itoa(i), progress) {
			return
		}
	}
}

// wait waits before the next event of a stream: for the test's step when
// the stream is stepped, else for the gap. It reports false once the caller
// went away.
func (c *Connector) wait(r *http.Request, sw ConnectorSwitches, gap time.Duration) bool {
	if sw.Stepped {
		select {
		case <-c.steps:
			return true
		case <-r.Context().Done():
			return false
		}
	}
	select {
	case <-time.After(gap):
		return true
	case <-r.Context().Done():
		return false
	}
}

// writeEvent writes one event of a stream and flushes it, and reports
// whether the caller took it.
func writeEvent(w http.ResponseWriter, id string, v any) bool {
	b, err := json.Marshal(v)
	if err != nil {
		return false
	}
	if _, err := fmt.Fprintf(w, "id: %s\nevent: message\ndata: %s\n\n", id, b); err != nil {
		return false
	}
	return http.NewResponseController(w).Flush() == nil
}

// writeRPCError answers a JSON-RPC error.
func writeRPCError(w http.ResponseWriter, status int, id json.RawMessage, code int, message string) {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	writeStubJSON(w, status, map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": code, "message": message}})
}
