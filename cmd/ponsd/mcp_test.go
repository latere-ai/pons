// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"latere.ai/x/pons/internal/store"
	"latere.ai/x/pons/test/stubs"
)

// mcpMessage is one JSON-RPC request of the current revision, its _meta
// naming the revision as the transport requires.
func mcpMessage(method string, params map[string]any) map[string]any {
	p := maps.Clone(params)
	if p == nil {
		p = map[string]any{}
	}
	p["_meta"] = map[string]any{"io.modelcontextprotocol/protocolVersion": stubs.MCPRevision}
	return map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": p}
}

// toolCall is a tools/call of a tool with its arguments.
func toolCall(tool string, args map[string]any) map[string]any {
	params := map[string]any{"name": tool}
	if args != nil {
		params["arguments"] = args
	}
	return mcpMessage("tools/call", params)
}

// mcpHeaders are the headers of a request of the current revision: what a
// client accepts, the revision, and the method and tool mirrored from the
// body.
func mcpHeaders(method, tool string) []string {
	h := []string{"Accept", "application/json, text/event-stream", "MCP-Protocol-Version", stubs.MCPRevision, "Mcp-Method", method}
	if tool != "" {
		h = append(h, "Mcp-Name", tool)
	}
	return h
}

// mcpAddress is the path of a connection's MCP address.
func mcpAddress(con string) string { return "/v1/connections/" + con + "/mcp" }

// listTools lists a connection's tools through its MCP address as sub.
func (s *stack) listTools(sub, con string) answer {
	s.t.Helper()
	return s.do(http.MethodPost, mcpAddress(con), sub, mcpMessage("tools/list", nil), mcpHeaders("tools/list", "")...)
}

// callTool calls a tool through a connection's MCP address as sub.
func (s *stack) callTool(sub, con, tool string, args map[string]any) answer {
	s.t.Helper()
	return s.do(http.MethodPost, mcpAddress(con), sub, toolCall(tool, args), mcpHeaders("tools/call", tool)...)
}

// notes connects the notes connector, of kind mcp at the stub connector,
// for sub with a key, and answers the connection's id.
func (s *stack) notes(sub, name, key string) string {
	s.t.Helper()
	a := s.connect(sub, "notes", name, map[string]any{"value": key})
	if a.status != http.StatusCreated {
		s.t.Fatalf("connect notes: %d %s", a.status, a.body)
	}
	return a.id(s.t)
}

// open sends one request to a connection's MCP address as sub and answers
// once its headers arrived, its body still streaming; end stops the caller
// and closes the body. The test ends it too.
func (s *stack) open(method, sub, con string, body any, headers ...string) (resp *http.Response, end func()) {
	s.t.Helper()
	var rd io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			s.t.Fatal(err)
		}
		rd = bytes.NewReader(raw)
	}
	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, method, s.base+mcpAddress(con), rd)
	if err != nil {
		cancel()
		s.t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+s.iss.Token(sub, nil))
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		cancel()
		s.t.Fatal(err)
	}
	end = func() {
		cancel()
		// The caller went away on purpose; what the close says is not read.
		_ = resp.Body.Close()
	}
	s.t.Cleanup(end)
	return resp, end
}

// readUntil reads a streaming body until it holds want, and answers what it
// read; the test fails when the body ends first.
func readUntil(t *testing.T, body io.Reader, want string) string {
	t.Helper()
	var got []byte
	buf := make([]byte, 4<<10)
	for !bytes.Contains(got, []byte(want)) {
		n, err := body.Read(buf)
		got = append(got, buf[:n]...)
		if err != nil && !bytes.Contains(got, []byte(want)) {
			t.Fatalf("the stream ended before %q: %v %s", want, err, got)
		}
	}
	return string(got)
}

// hold opens n calls of count on a connection as sub while the stub
// connector's stream is endless, each holding one of the connection's
// places in flight until the answered function ends them.
func (s *stack) hold(t *testing.T, sub, con string, n int) func() {
	t.Helper()
	var ends []func()
	for range n {
		resp, end := s.open(http.MethodPost, sub, con, toolCall("count", nil), mcpHeaders("tools/call", "count")...)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("a held call: %d", resp.StatusCode)
		}
		ends = append(ends, end)
	}
	return func() {
		for _, end := range ends {
			end()
		}
	}
}

// records are a connection's call records, oldest first, once there are at
// least n of them or five seconds have passed: a record is written after
// its answer.
func (s *stack) records(t *testing.T, con string, n int) []store.Call {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		got, _, err := s.store.Calls().List(t.Context(), con, store.Page{Limit: 200})
		if err != nil {
			t.Fatal(err)
		}
		if len(got) >= n || time.Now().After(deadline) {
			slices.Reverse(got)
			return got
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// settled are a connection's records once n are written and a moment has
// passed in which no more were, for a test that counts them exactly.
func (s *stack) settled(t *testing.T, con string, n int) []store.Call {
	t.Helper()
	s.records(t, con, n)
	time.Sleep(200 * time.Millisecond)
	return s.records(t, con, n)
}

// scratch is an entry of kind mcp at the stub connector that takes no
// credential.
func scratch(t testing.TB) string {
	return `
  - name: scratch
    title: Example Scratch
    kind: mcp
    url: ` + upstreamOf(t).mcp.URL() + `
    auth: {type: none}
`
}

// A 3xx from the connector is 502 connector_unavailable and the redirect is
// not followed: one request reached the connector, and no Location passes.
func TestCarrierFollowsNoRedirect(t *testing.T) {
	s := startStack(t, stubs.NewIssuer(t), nil)
	up := upstreamOf(t)
	con := s.notes("alice", "", "a-key-of-alice-0101")
	up.mcp.Set(func(sw *stubs.ConnectorSwitches) { sw.Redirect = true })
	before := len(up.mcp.Requests())
	a := s.listTools("alice", con)
	if a.status != http.StatusBadGateway || a.code() != "connector_unavailable" || a.detail("reason") != "redirect_refused" || a.header.Get("Location") != "" {
		t.Fatalf("%d %v %s", a.status, a.header, a.body)
	}
	if got := up.mcp.Requests()[before:]; len(got) != 1 {
		t.Fatalf("the connector was asked %d times", len(got))
	}
	if got := s.records(t, con, 1); len(got) != 1 || got[0].Outcome != "upstream_error" || got[0].Status != http.StatusTemporaryRedirect {
		t.Fatalf("records %+v", got)
	}
}

// A connector's challenge reaches no caller: a 401 to a connection that
// takes no credential passes less its WWW-Authenticate, and one to a key
// moves the connection and answers 409 with none; the caller's token never
// reaches the connector.
func TestAConnectorsChallengeReachesNoCaller(t *testing.T) {
	iss := stubs.NewIssuer(t)
	s := startStack(t, iss, map[string]string{"PONS_CATALOG_FILE": catalogFile(t, scratch(t))})
	up := upstreamOf(t)
	open := s.connect("alice", "scratch", "", nil).id(t)
	keyed := s.notes("alice", "", "a-key-of-alice-0102")
	token := iss.Token("alice", nil)
	up.mcp.Set(func(sw *stubs.ConnectorSwitches) { sw.RefuseAll = true })
	a := s.doBearer(http.MethodPost, mcpAddress(open), token, mcpMessage("tools/list", nil), mcpHeaders("tools/list", "")...)
	if a.status != http.StatusUnauthorized || a.header.Get("WWW-Authenticate") != "" || !strings.Contains(string(a.body), "Bad credentials") {
		t.Fatalf("a 401 to no credential: %d %v %s", a.status, a.header, a.body)
	}
	a = s.doBearer(http.MethodPost, mcpAddress(keyed), token, mcpMessage("tools/list", nil), mcpHeaders("tools/list", "")...)
	if a.status != http.StatusConflict || a.detail("reason") != "credential_refused" || a.header.Get("WWW-Authenticate") != "" {
		t.Fatalf("a 401 to a key: %d %v %s", a.status, a.header, a.body)
	}
	if got := s.do(http.MethodGet, "/v1/connections/"+keyed, "alice", nil).json(t)["state"]; got != "needs_reconnect" {
		t.Fatalf("the refused key's connection is %v", got)
	}
	for _, q := range up.mcp.Requests() {
		for name, values := range q.Header {
			if strings.Contains(strings.Join(values, ","), token) {
				t.Fatalf("the caller's token reached the connector in %s", name)
			}
		}
	}
}

// A connector's cookie is neither passed to a caller nor sent back to it.
func TestAConnectorSetsNoCookie(t *testing.T) {
	s := startStack(t, stubs.NewIssuer(t), nil)
	up := upstreamOf(t)
	con := s.notes("alice", "", "a-key-of-alice-0103")
	up.mcp.Set(func(sw *stubs.ConnectorSwitches) { sw.Cookie = true })
	before := len(up.mcp.Requests())
	for _, a := range []answer{s.listTools("alice", con), s.callTool("alice", con, "get_note", nil), s.callTool("alice", con, "count", nil)} {
		if a.status != http.StatusOK || len(a.header.Values("Set-Cookie")) != 0 {
			t.Fatalf("%d %v", a.status, a.header)
		}
	}
	for _, q := range up.mcp.Requests()[before:] {
		if q.Header.Get("Cookie") != "" {
			t.Fatalf("a cookie went back to the connector: %v", q.Header)
		}
	}
}

// An answer is bounded: headers past 64 KiB end as 502, a large answer
// passes whole as it streams, a stream that goes silent ends at its idle
// time with outcome timeout, and an endless stream holds one place, so the
// connection still answers, until its caller goes away.
func TestAnAnswerIsBounded(t *testing.T) {
	s := startStack(t, stubs.NewIssuer(t), map[string]string{"PONS_STREAM_IDLE_TIMEOUT": "300ms"})
	up := upstreamOf(t)
	con := s.notes("alice", "", "a-key-of-alice-0104")
	set := func(change func(*stubs.ConnectorSwitches)) { up.mcp.Set(change) }

	set(func(sw *stubs.ConnectorSwitches) { sw.HugeHeaders = true })
	if a := s.listTools("alice", con); a.status != http.StatusBadGateway || a.detail("reason") != "response_too_large" {
		t.Fatalf("headers past 64 KiB: %d %s", a.status, a.body)
	}
	set(func(sw *stubs.ConnectorSwitches) { sw.HugeHeaders, sw.AnswerBytes = false, 6<<20 })
	if a := s.callTool("alice", con, "get_note", nil); a.status != http.StatusOK || len(a.body) < 6<<20 {
		t.Fatalf("a large answer: %d, %d bytes", a.status, len(a.body))
	}
	set(func(sw *stubs.ConnectorSwitches) { sw.AnswerBytes, sw.Gap = 0, 3*time.Second })
	start := time.Now()
	if a := s.callTool("alice", con, "count", nil); a.status != http.StatusOK || strings.Count(string(a.body), "data:") != 1 || time.Since(start) > 2*time.Second {
		t.Fatalf("a silent stream: %d in %v: %s", a.status, time.Since(start), a.body)
	}
	set(func(sw *stubs.ConnectorSwitches) { sw.Gap, sw.Endless = 0, true })
	resp, end := s.open(http.MethodPost, "alice", con, toolCall("count", nil), mcpHeaders("tools/call", "count")...)
	readUntil(t, resp.Body, ": keep-alive")
	if a := s.listTools("alice", con); a.status != http.StatusOK {
		t.Fatalf("beside an endless stream: %d %s", a.status, a.body)
	}
	end()
	got := s.records(t, con, 5)
	outcomes := []string{}
	for _, c := range got {
		outcomes = append(outcomes, c.Outcome)
	}
	if !slices.Equal(outcomes, []string{"upstream_error", "ok", "timeout", "ok", "canceled"}) {
		t.Fatalf("outcomes %v", outcomes)
	}
	if got[1].BytesOut < 6<<20 || got[2].Status != http.StatusOK || got[2].BytesOut == 0 {
		t.Fatalf("records %+v", got)
	}
}

// An oversized request, a connector that sends no headers and a silent
// stream each end with their code within their bound, and calls past a
// connection's places are refused without touching another connection.
func TestSizesAndTimeoutsEndACall(t *testing.T) {
	s := startStack(t, stubs.NewIssuer(t), map[string]string{
		"PONS_MAX_REQUEST_BYTES": "4096", "PONS_CALL_HEADER_TIMEOUT": "300ms", "PONS_STREAM_IDLE_TIMEOUT": "300ms",
	})
	up := upstreamOf(t)
	con := s.notes("alice", "", "a-key-of-alice-0105")
	other := s.notes("alice", "notes-2", "a-key-of-alice-0106")
	before := len(up.mcp.Requests())
	for _, id := range []string{con, "con_01jb2m6x8q3v7k9n4w5t0zr1ya"} {
		a := s.callTool("alice", id, "get_note", map[string]any{"pad": strings.Repeat("x", 5000)})
		if a.status != http.StatusRequestEntityTooLarge || a.code() != "request_too_large" || a.detail("reason") != "max_request_bytes=4096" {
			t.Fatalf("an oversized request to %s: %d %s", id, a.status, a.body)
		}
	}
	if len(up.mcp.Requests()) != before {
		t.Fatal("an oversized request reached the connector")
	}
	up.mcp.Set(func(sw *stubs.ConnectorSwitches) { sw.Slow = 3 * time.Second })
	start := time.Now()
	if a := s.listTools("alice", con); a.status != http.StatusGatewayTimeout || a.code() != "connector_timeout" || time.Since(start) > 2*time.Second {
		t.Fatalf("no headers: %d in %v: %s", a.status, time.Since(start), a.body)
	}
	up.mcp.Set(func(sw *stubs.ConnectorSwitches) { sw.Slow, sw.Gap = 0, 3*time.Second })
	start = time.Now()
	if a := s.callTool("alice", con, "count", nil); a.status != http.StatusOK || strings.Count(string(a.body), "data:") != 1 || time.Since(start) > 2*time.Second {
		t.Fatalf("a silent stream: %d in %v: %s", a.status, time.Since(start), a.body)
	}
	up.mcp.Set(func(sw *stubs.ConnectorSwitches) { sw.Gap, sw.Endless = 0, true })
	release := s.hold(t, "alice", con, 16)
	if a := s.listTools("alice", con); a.status != http.StatusTooManyRequests || a.code() != "rate_limited" {
		t.Fatalf("past the connection's places: %d %s", a.status, a.body)
	}
	if a := s.listTools("alice", other); a.status != http.StatusOK {
		t.Fatalf("another connection: %d %s", a.status, a.body)
	}
	release()
}

// The seventeenth request in flight on one connection is 429 with
// Retry-After 1, another connection of the same caller is served, and the
// places come back when the calls end.
func TestAConnectionsConcurrencyIsBounded(t *testing.T) {
	s := startStack(t, stubs.NewIssuer(t), nil)
	up := upstreamOf(t)
	con := s.notes("alice", "", "a-key-of-alice-0107")
	other := s.notes("alice", "notes-2", "a-key-of-alice-0108")
	up.mcp.Set(func(sw *stubs.ConnectorSwitches) { sw.Endless = true })
	release := s.hold(t, "alice", con, 16)
	a := s.listTools("alice", con)
	if a.status != http.StatusTooManyRequests || a.detail("reason") != "connection_inflight=16" || a.header.Get("Retry-After") != "1" {
		t.Fatalf("the seventeenth: %d %v %s", a.status, a.header, a.body)
	}
	if a := s.listTools("alice", other); a.status != http.StatusOK {
		t.Fatalf("another connection: %d %s", a.status, a.body)
	}
	release()
	deadline := time.Now().Add(5 * time.Second)
	for {
		a := s.listTools("alice", con)
		if a.status == http.StatusOK {
			break
		}
		if a.status != http.StatusTooManyRequests || time.Now().After(deadline) {
			t.Fatalf("the places did not come back: %d %s", a.status, a.body)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A subject past PONS_MAX_INFLIGHT_PER_SUBJECT requests in flight, across
// its connections, and a process past PONS_MAX_INFLIGHT are 429 before the
// body is read and before anything is asked, with no authorizer and under
// an allow that names no limit.
func TestACallersConcurrencyIsBounded(t *testing.T) {
	for name, withAz := range map[string]bool{"owner policy": false, "an allow with no limit": true} {
		t.Run(name, func(t *testing.T) {
			over := map[string]string{"PONS_MAX_INFLIGHT_PER_SUBJECT": "2", "PONS_MAX_INFLIGHT": "3", "PONS_MAX_REQUEST_BYTES": "1024"}
			var asked func() int
			if withAz {
				az, withAuthz := withAuthorizer(t, over)
				over = withAuthz
				asked = func() int { return len(az.Requests()) }
			}
			s := startStack(t, stubs.NewIssuer(t), over)
			up := upstreamOf(t)
			one := s.notes("alice", "n1", "a-key-of-alice-0109")
			two := s.notes("alice", "n2", "a-key-of-alice-0110")
			bobs := s.notes("bob", "", "a-key-of-bob-0111")
			up.mcp.Set(func(sw *stubs.ConnectorSwitches) { sw.Endless = true })
			releaseOne := s.hold(t, "alice", one, 1)
			releaseTwo := s.hold(t, "alice", two, 1)
			before := 0
			if asked != nil {
				before = asked()
			}
			// A body past PONS_MAX_REQUEST_BYTES would be 413 were it read.
			big := map[string]any{"pad": strings.Repeat("x", 4096)}
			for _, id := range []string{one, "con_01jb2m6x8q3v7k9n4w5t0zr1ya"} {
				a := s.callTool("alice", id, "get_note", big)
				if a.status != http.StatusTooManyRequests || a.detail("reason") != "max_inflight_per_subject=2" {
					t.Fatalf("alice past her places, to %s: %d %s", id, a.status, a.body)
				}
			}
			if asked != nil && asked() != before {
				t.Fatal("a request past the places was asked about")
			}
			releaseBob := s.hold(t, "bob", bobs, 1)
			if a := s.callTool("carol", "con_01jb2m6x8q3v7k9n4w5t0zr1ya", "get_note", big); a.status != http.StatusTooManyRequests || a.detail("reason") != "max_inflight=3" {
				t.Fatalf("the process past its places: %d %s", a.status, a.body)
			}
			releaseOne()
			releaseTwo()
			releaseBob()
		})
	}
}

// Each request whose connection was found writes one record with its
// method, tool, effect, outcome, status and sizes, and none holds an
// argument or a result; a 503 Pons raises leaves none, and a 502 or a 504
// about the connector leaves one.
func TestEveryCallIsRecorded(t *testing.T) {
	iss := stubs.NewIssuer(t)
	az, over := withAuthorizer(t, map[string]string{"PONS_CALL_HEADER_TIMEOUT": "300ms"})
	s := startStack(t, iss, over)
	up := upstreamOf(t)
	con := s.notes("alice", "", "a-key-of-alice-0112")
	marker := "argument-" + strings.ToLower(rand.Text())
	answers := []answer{
		s.listTools("alice", con),
		s.callTool("alice", con, "get_note", map[string]any{"id": marker}),
		s.callTool("alice", con, "create_note", map[string]any{"title": marker}),
		s.do(http.MethodGet, mcpAddress(con), "alice", nil),
	}
	up.mcp.Set(func(sw *stubs.ConnectorSwitches) { sw.Redirect = true })
	answers = append(answers, s.callTool("alice", con, "count", nil))
	up.mcp.Set(func(sw *stubs.ConnectorSwitches) { sw.Redirect, sw.Slow = false, time.Second })
	answers = append(answers, s.callTool("alice", con, "search_notes", nil))
	up.mcp.Set(func(sw *stubs.ConnectorSwitches) { sw.Slow = 0 })
	for i, want := range []int{200, 200, 200, 405, 502, 504} {
		if answers[i].status != want {
			t.Fatalf("answer %d: %d %s", i, answers[i].status, answers[i].body)
		}
	}
	type row struct {
		method, tool, effect, outcome string
		status                        int
	}
	want := []row{
		{"tools/list", "", "", "ok", 200},
		{"tools/call", "get_note", "read", "ok", 200},
		{"tools/call", "create_note", "write", "ok", 200},
		{"GET", "", "", "ok", 405},
		{"tools/call", "count", "read", "upstream_error", 307},
		{"tools/call", "search_notes", "read", "timeout", 0},
	}
	got := s.settled(t, con, len(want))
	if len(got) != len(want) {
		t.Fatalf("%d records: %+v", len(got), got)
	}
	for i, w := range want {
		c := got[i]
		if (row{c.Method, c.Tool, c.Effect, c.Outcome, c.Status}) != w {
			t.Errorf("record %d: %+v, want %+v", i, c, w)
		}
		if c.ID == "" || c.Owner != iss.Subject("alice") || c.Subject != iss.Subject("alice") || c.Connector != "notes" || c.At.IsZero() || c.DurationMS < 0 {
			t.Errorf("record %d: %+v", i, c)
		}
		if (c.Method == "GET") != (c.BytesIn == 0) {
			t.Errorf("record %d's bytes in: %d", i, c.BytesIn)
		}
	}
	if got[1].BytesOut != int64(len(answers[1].body)) {
		t.Errorf("bytes out %d of an answer of %d", got[1].BytesOut, len(answers[1].body))
	}
	if strings.Contains(s.dump()+s.logs.String(), marker) {
		t.Fatal("an argument or a result is kept")
	}
	// An authorizer that does not answer is a 503 of Pons's own: no record.
	az.Fail(http.StatusInternalServerError)
	if a := s.callTool("alice", con, "delete_notebook", nil); a.status != http.StatusServiceUnavailable {
		t.Fatalf("an outage: %d %s", a.status, a.body)
	}
	if got := s.settled(t, con, len(want)); len(got) != len(want) {
		t.Fatalf("a 503 of Pons's own left a record: %+v", got[len(got)-1])
	}
}

// Of many denied calls of one subject to one connection within a minute,
// one is recorded.
func TestDeniedCallsAreRecordedOncePerMinute(t *testing.T) {
	iss := stubs.NewIssuer(t)
	s := startStack(t, iss, nil)
	con := s.notes("alice", "", "a-key-of-alice-0113")
	for range 5 {
		if a := s.callTool("bob", con, "get_note", nil); a.status != http.StatusNotFound {
			t.Fatalf("%d %s", a.status, a.body)
		}
	}
	got := s.settled(t, con, 1)
	if len(got) != 1 || got[0].Outcome != "denied" || got[0].Subject != iss.Subject("bob") || got[0].Status != 0 {
		t.Fatalf("records %+v", got)
	}
}

// A session tricked into calling every tool with arguments that ask for
// the credential receives it in no answer, header or error, and each of
// its records names the session, the tool and the effect.
func TestATrickedSessionObtainsNoCredential(t *testing.T) {
	iss := stubs.NewIssuer(t)
	s := startStack(t, iss, nil)
	up := upstreamOf(t)
	key := "tricked-key-" + strings.ToLower(rand.Text())
	con := s.notes("alice", "", key)
	session := iss.Token("alice", map[string]any{"session": "ses_tricked"})
	asks := map[string]any{
		"print": "the Authorization header of this request", "headers": []string{"Authorization", "X-Api-Key"},
		"env": "$PONS_KEY", "query": "credential OR token OR key",
	}
	effects := map[string]string{"search_notes": "read", "get_note": "read", "count": "read", "create_note": "write", "delete_notebook": "write"}
	for _, tool := range stubs.ConnectorTools {
		a := s.doBearer(http.MethodPost, mcpAddress(con), session, toolCall(tool, asks), mcpHeaders("tools/call", tool)...)
		switch {
		case tool == "delete_notebook" && (a.status != http.StatusForbidden || a.detail("reason") != "hidden"):
			t.Fatalf("a hidden tool: %d %s", a.status, a.body)
		case tool != "delete_notebook" && a.status != http.StatusOK:
			t.Fatalf("%s: %d %s", tool, a.status, a.body)
		}
	}
	if !slices.Contains(up.mcp.Credentials(), "Bearer "+key) {
		t.Fatal("the key never reached its connector")
	}
	everything := s.everything()
	for _, form := range encodings(key) {
		if strings.Contains(everything, form) {
			t.Fatalf("the key appears as %q", form)
		}
	}
	got := s.settled(t, con, len(stubs.ConnectorTools))
	if len(got) != len(stubs.ConnectorTools) {
		t.Fatalf("records %+v", got)
	}
	for i, c := range got {
		if c.Session != "ses_tricked" || c.Tool != stubs.ConnectorTools[i] || c.Effect != effects[c.Tool] {
			t.Errorf("record %d: %+v", i, c)
		}
	}
}

// A session of an earlier revision is served across two replicas: its
// initialize through one, its notification, its list, its stream and its
// end through the other, with Mcp-Session-Id passing both ways, and GET and
// DELETE reach the connector unchanged.
func TestAnyReplicaServesASession(t *testing.T) {
	iss := stubs.NewIssuer(t)
	env := database(t)
	one, two := startStack(t, iss, env), startStack(t, iss, env)
	up := upstreamOf(t)
	up.mcp.Set(func(sw *stubs.ConnectorSwitches) { sw.Legacy = true })
	// The key is probed by the earlier revision's handshake, whose session
	// the probe ends.
	con := one.notes("alice", "", "a-key-of-alice-0114")
	if up.mcp.Sessions() != 0 {
		t.Fatalf("the probe left %d sessions open", up.mcp.Sessions())
	}
	accept := []string{"Accept", "application/json, text/event-stream"}
	init := one.do(http.MethodPost, mcpAddress(con), "alice", map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]any{
		"protocolVersion": stubs.MCPLegacy, "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "a-test", "version": "1"},
	}}, accept...)
	session := init.header.Get("Mcp-Session-Id")
	if init.status != http.StatusOK || session == "" {
		t.Fatalf("initialize: %d %v %s", init.status, init.header, init.body)
	}
	in := append(slices.Clone(accept), "MCP-Protocol-Version", stubs.MCPLegacy, "Mcp-Session-Id", session)
	if a := two.do(http.MethodPost, mcpAddress(con), "alice", map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}, in...); a.status != http.StatusAccepted {
		t.Fatalf("initialized: %d %s", a.status, a.body)
	}
	list := two.do(http.MethodPost, mcpAddress(con), "alice", map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, in...)
	if list.status != http.StatusOK || !strings.Contains(string(list.body), "search_notes") || list.header.Get("Mcp-Session-Id") != session {
		t.Fatalf("tools/list: %d %v %s", list.status, list.header, list.body)
	}
	resp, end := two.open(http.MethodGet, "alice", con, nil, "Accept", "text/event-stream", "MCP-Protocol-Version", stubs.MCPLegacy,
		"Mcp-Session-Id", session, "Last-Event-ID", "0")
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "text/event-stream" || resp.Header.Get("X-Accel-Buffering") != "no" {
		t.Fatalf("the stream: %d %v", resp.StatusCode, resp.Header)
	}
	readUntil(t, resp.Body, "list_changed")
	end()
	// The stream's record is written when it ends, before the session's.
	one.records(t, con, 4)
	if a := one.do(http.MethodDelete, mcpAddress(con), "alice", nil, "MCP-Protocol-Version", stubs.MCPLegacy, "Mcp-Session-Id", session); a.status != http.StatusOK {
		t.Fatalf("the end: %d %s", a.status, a.body)
	}
	if up.mcp.Sessions() != 0 {
		t.Fatalf("%d sessions open", up.mcp.Sessions())
	}
	var get, del *stubs.ConnectorRequest
	for _, q := range up.mcp.Requests() {
		switch {
		case q.Session != session:
		case q.Method == http.MethodGet:
			get = &q
		case q.Method == http.MethodDelete:
			del = &q
		}
	}
	if get == nil || get.Header.Get("Accept") != "text/event-stream" || get.Header.Get("MCP-Protocol-Version") != stubs.MCPLegacy ||
		get.Header.Get("Last-Event-ID") != "0" || len(get.Body) != 0 || get.Credential != "Bearer a-key-of-alice-0114" {
		t.Fatalf("the GET the connector received: %+v", get)
	}
	if del == nil || len(del.Body) != 0 || del.Credential != "Bearer a-key-of-alice-0114" {
		t.Fatalf("the DELETE the connector received: %+v", del)
	}
	if got := one.records(t, con, 5); len(got) != 5 || got[0].Method != "initialize" || got[3].Method != http.MethodGet || got[4].Method != http.MethodDelete {
		methods := []string{}
		for _, c := range got {
			methods = append(methods, c.Method+":"+strconv.Itoa(c.Status))
		}
		t.Fatalf("records %v", methods)
	}
}
