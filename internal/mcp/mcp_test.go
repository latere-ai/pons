// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"encoding/json/v2"
	"io"
	"net/http"
	"testing"

	"latere.ai/x/pons/internal/version"
)

// A mirrored value is itself, or its base64 form decoded; a base64 form that
// does not decode is no value.
func TestHeaderValue(t *testing.T) {
	for in, want := range map[string]string{
		"tools/call":                      "tools/call",
		"=?base64?bm90aXplbl9zw7zDnw==?=": "notizen_süß",
		"=?base64?abc":                    "=?base64?abc",
		"plain?=":                         "plain?=",
		"":                                "",
	} {
		if got, ok := HeaderValue(in); !ok || got != want {
			t.Errorf("%q: %q %v", in, got, ok)
		}
	}
	if _, ok := HeaderValue("=?base64?***?="); ok {
		t.Error("a base64 form that does not decode")
	}
}

// Only a JSON-RPC error whose code the current revision defines is one of
// that revision.
func TestModernError(t *testing.T) {
	for body, want := range map[string]bool{
		`{"jsonrpc":"2.0","id":1,"error":{"code":-32020,"message":"Header mismatch"}}`: true,
		`{"jsonrpc":"2.0","id":1,"error":{"code":-32099,"message":"x"}}`:               true,
		`{"jsonrpc":"2.0","id":null,"error":{"code":-32000,"message":"No session"}}`:   false,
		`{"jsonrpc":"2.0","id":1,"error":{"code":-32019,"message":"x"}}`:               false,
		`{"jsonrpc":"2.0","id":1,"error":{"message":"no code"}}`:                       false,
		`{"jsonrpc":"1.0","id":1,"error":{"code":-32020}}`:                             false,
		`{"jsonrpc":"2.0","id":1,"result":{}}`:                                         false,
		`Bad Request: no valid session ID provided`:                                    false,
	} {
		if ModernError([]byte(body)) != want {
			t.Errorf("%s: want %v", body, want)
		}
	}
}

// The version an initialize negotiated is read from a JSON answer or the
// first event of a stream, and is Legacy when none can be read.
func TestNegotiated(t *testing.T) {
	for body, want := range map[string]string{
		`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}`:                                       "2025-06-18",
		"event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2025-03-26\"}}\n\n": "2025-03-26",
		`{"jsonrpc":"2.0","id":1,"result":{}}`:                                                                     Legacy,
		`not json`:                                                                                                 Legacy,
	} {
		if got := Negotiated([]byte(body)); got != want {
			t.Errorf("%q: %s", body, got)
		}
	}
}

// The probe's requests: the current revision's tools/list with its headers
// and its _meta, the earlier revision's handshake, a list and an end in its
// session.
func TestTheProbesRequests(t *testing.T) {
	ctx := t.Context()
	const url = "https://mcp.example.com/mcp"
	req, err := ListTools(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	var body struct {
		Method string `json:"method"`
		Params struct {
			Meta map[string]any `json:"_meta"`
		} `json:"params"`
	}
	read(t, req, &body)
	info, _ := body.Params.Meta["io.modelcontextprotocol/clientInfo"].(map[string]any)
	if req.Method != http.MethodPost || body.Method != "tools/list" || body.Params.Meta["io.modelcontextprotocol/protocolVersion"] != Revision ||
		info["name"] != "pons" || req.Header.Get(HeaderVersion) != Revision || req.Header.Get(HeaderMethod) != "tools/list" ||
		req.Header.Get("Accept") != "application/json, text/event-stream" || req.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("tools/list %v %+v", req.Header, body)
	}
	if req, err = Initialize(ctx, url); err != nil {
		t.Fatal(err)
	}
	var init struct {
		Method string `json:"method"`
		Params struct {
			ProtocolVersion string `json:"protocolVersion"`
		} `json:"params"`
	}
	read(t, req, &init)
	if init.Method != "initialize" || init.Params.ProtocolVersion != Legacy || req.Header.Get(HeaderVersion) != "" {
		t.Fatalf("initialize %v %+v", req.Header, init)
	}
	for name, build := range map[string]func() (*http.Request, error){
		"notifications/initialized": func() (*http.Request, error) { return Initialized(ctx, url, "s-1", "2025-06-18") },
		"tools/list":                func() (*http.Request, error) { return ListToolsIn(ctx, url, "s-1", "2025-06-18", "") },
		"":                          func() (*http.Request, error) { return End(ctx, url, "s-1", "2025-06-18") },
	} {
		req, err := build()
		if err != nil {
			t.Fatal(err)
		}
		if req.Header.Get(HeaderSession) != "s-1" || req.Header.Get(HeaderVersion) != "2025-06-18" {
			t.Errorf("%s: %v", name, req.Header)
		}
		if name == "" {
			if req.Method != http.MethodDelete {
				t.Errorf("the end is %s", req.Method)
			}
			continue
		}
		var m struct {
			Method string `json:"method"`
		}
		read(t, req, &m)
		if m.Method != name {
			t.Errorf("%s: %s", name, m.Method)
		}
	}
	if req, err := End(ctx, url, "", Legacy); err != nil || req.Header.Get(HeaderSession) != "" {
		t.Fatalf("an end with no session: %v %v", req, err)
	}
	for name, build := range map[string]func() (*http.Request, error){
		"list":       func() (*http.Request, error) { return ListTools(ctx, "https://%zz") },
		"init":       func() (*http.Request, error) { return Initialize(ctx, "https://%zz") },
		"note":       func() (*http.Request, error) { return Initialized(ctx, "https://%zz", "s", Legacy) },
		"in session": func() (*http.Request, error) { return ListToolsIn(ctx, "https://%zz", "s", Legacy, "") },
		"end":        func() (*http.Request, error) { return End(ctx, "https://%zz", "s", Legacy) },
	} {
		if _, err := build(); err == nil {
			t.Errorf("%s: a url that does not parse", name)
		}
	}
}

// read decodes a request's body.
func read(t *testing.T, req *http.Request, v any) {
	t.Helper()
	raw, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatalf("%s: %v", raw, err)
	}
}

// A list of tools names the page it asks for in either revision, and its
// answer is read from a JSON body or from the event that carries it, with
// the cursor of the next page.
func TestAListOfTools(t *testing.T) {
	ctx := t.Context()
	const url = "https://mcp.example.com/mcp"
	var after struct {
		Params struct {
			Cursor string `json:"cursor"`
		} `json:"params"`
	}
	req, err := ListToolsAfter(ctx, url, "page-2")
	if err != nil {
		t.Fatal(err)
	}
	read(t, req, &after)
	if after.Params.Cursor != "page-2" || req.Header.Get(HeaderMethod) != "tools/list" {
		t.Fatalf("the page after a cursor: %+v %v", after, req.Header)
	}
	req, err = ListToolsIn(ctx, url, "s-1", Legacy, "page-3")
	if err != nil {
		t.Fatal(err)
	}
	read(t, req, &after)
	if after.Params.Cursor != "page-3" {
		t.Fatalf("the page after a cursor in a session: %+v", after)
	}
	answer := `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"get_note","description":"Reads a note."}],"nextCursor":"n"}}`
	tools, next, err := ToolsOf("application/json", []byte(answer))
	if err != nil || len(tools) != 1 || tools[0].Name != "get_note" || tools[0].Description != "Reads a note." || next != "n" {
		t.Fatalf("a JSON answer: %+v %q %v", tools, next, err)
	}
	stream := "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\ndata: " + answer + "\n\n"
	if tools, _, err := ToolsOf("text/event-stream; charset=utf-8", []byte(stream)); err != nil || len(tools) != 1 {
		t.Fatalf("an event stream: %+v %v", tools, err)
	}
	for _, body := range []string{`{"jsonrpc":"2.0","id":1,"error":{"code":-32601}}`, `not json`} {
		if _, _, err := ToolsOf("application/json", []byte(body)); err == nil {
			t.Errorf("%s read as a list", body)
		}
	}
}

// The probe's request is the same bytes every time, members in key order,
// so a server that caches by content sees one request.
func TestTheProbesRequestBytes(t *testing.T) {
	req, err := ListToolsAfter(t.Context(), "https://mcp.example.com/mcp", "c1")
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"id":1,"jsonrpc":"2.0","method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/clientCapabilities":{},` +
		`"io.modelcontextprotocol/clientInfo":{"name":"pons","version":"` + version.Version + `"},` +
		`"io.modelcontextprotocol/protocolVersion":"` + Revision + `"},"cursor":"c1"}}`
	if string(got) != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

// What a server answers is read as the lenient servers write it: a
// repeated member takes its last value, a member name in another letter
// case is the member, and bytes that are no UTF-8 do not refuse the answer.
func TestAnswersOfServersAreReadLeniently(t *testing.T) {
	body := []byte("{\"JSONRPC\":\"2.0\",\"Result\":{\"tools\":[{\"Name\":\"a\",\"description\":\"x\xff\"}],\"nextCursor\":\"p1\",\"nextCursor\":\"p2\"}}")
	tools, next, err := ToolsOf("application/json", body)
	if err != nil || len(tools) != 1 || tools[0].Name != "a" || next != "p2" {
		t.Fatalf("%+v %q %v", tools, next, err)
	}
	if v := Negotiated([]byte(`{"result":{"protocolVersion":"x","ProtocolVersion":"2025-11-25"}}`)); v != "2025-11-25" {
		t.Errorf("negotiated %q", v)
	}
	if !ModernError([]byte(`{"jsonrpc":"2.0","Error":{"Code":-32020},"error":{"code":-32021}}`)) {
		t.Error("a repeated error member")
	}
}
