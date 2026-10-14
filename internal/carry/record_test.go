// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package carry

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"latere.ai/x/pons/authorizer"
	"latere.ai/x/pons/internal/store"
	"latere.ai/x/pons/internal/store/memory"
	"latere.ai/x/pons/test/stubs"
)

// A call through the stub connector leaves one record with every field
// filled as spec 010 says, and a refused token or an unknown id leaves
// none.
func TestACallLeavesOneRecord(t *testing.T) {
	r := newRig(t, false)
	c := r.noted()
	start := time.Now()
	body, headers := rpc("tools/call", map[string]any{"name": "search_notes", "arguments": map[string]any{"q": "an argument never kept"}})
	a := r.send(http.MethodPost, address(c, "mcp"), "agent", strings.NewReader(body), headers...)
	if a.status != http.StatusOK {
		t.Fatalf("%d %s", a.status, a.body)
	}
	r.list(c, "expired")
	r.send(http.MethodPost, "/v1/connections/con_nothing/mcp", "agent", strings.NewReader(body), headers...)
	got := r.calls(c)
	if len(got) != 1 {
		t.Fatalf("%d records: %+v", len(got), got)
	}
	call := got[0]
	if !strings.HasPrefix(call.ID, "call_") || call.Connection != c.ID || call.Owner != c.Owner || call.Connector != "notes" ||
		call.Subject != subject("agent") || call.Session != "ses_01" || call.At.Before(start.Add(-time.Second)) || call.DurationMS < 0 ||
		call.Method != "tools/call" || call.Tool != "search_notes" || call.Effect != "read" || call.Outcome != OutcomeOK ||
		call.Status != http.StatusOK || call.BytesIn != int64(len(body)) || call.BytesOut != int64(len(a.body)) || call.Refs != 0 {
		t.Fatalf("the record %+v", call)
	}
	if strings.Contains(r.logs.String(), "never kept") || strings.Contains(r.logs.String(), "search_notes {") {
		t.Fatal("an argument or a result reached a log line")
	}
}

// Each outcome of spec 008 is produced by a call to the MCP address that
// ends that way, and a record is written for it.
func TestEveryOutcomeIsRecorded(t *testing.T) {
	r := newRig(t, false)
	c := r.noted()
	ctx := t.Context()
	set := func(change func(*stubs.ConnectorSwitches)) {
		r.serving.Wait()
		r.mcp.Set(func(sw *stubs.ConnectorSwitches) { *sw = stubs.ConnectorSwitches{} })
		r.mcp.Set(change)
	}
	r.list(c, "alice")
	r.az.set(authorizer.Limits{ReadOnly: true})
	r.call(c, "alice", "create_note", nil)
	r.az.set(authorizer.Limits{})
	set(func(sw *stubs.ConnectorSwitches) { sw.Redirect = true })
	r.list(c, "alice")
	set(func(sw *stubs.ConnectorSwitches) { sw.Slow = time.Second })
	r.serving.Wait()
	r.c.HeaderTimeout = 100 * time.Millisecond
	r.list(c, "alice")
	r.serving.Wait()
	r.c.HeaderTimeout = 5 * time.Second
	set(func(sw *stubs.ConnectorSwitches) { sw.Endless = true })
	cctx, cancel := context.WithCancel(ctx)
	body, headers := rpc("tools/call", map[string]any{"name": "count"})
	req, err := http.NewRequestWithContext(cctx, http.MethodPost, r.srv.URL+address(c, "mcp"), strings.NewReader(body))
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
	cancel()
	closeBody(resp)
	set(func(sw *stubs.ConnectorSwitches) { sw.RefuseAll = true })
	r.list(c, "alice")
	set(func(*stubs.ConnectorSwitches) {})
	r.list(c, "alice")
	want := []string{OutcomeOK, OutcomeDenied, OutcomeUpstreamError, OutcomeTimeout, OutcomeCanceled, OutcomeUpstreamRefused, OutcomeNotConnected}
	deadline := time.Now().Add(5 * time.Second)
	for len(r.calls(c)) < len(want) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	got := r.calls(c)
	if len(got) != len(want) {
		t.Fatalf("%d records: %+v", len(got), got)
	}
	for i, call := range got {
		if call.Outcome != want[i] {
			t.Errorf("record %d is %s, want %s", i, call.Outcome, want[i])
		}
	}
}

// A streamed call is recorded when the stream ends, from either side or by
// its idle bound, with the bytes and the duration of the whole stream, and
// a caller that leaves is recorded canceled.
func TestAStreamIsRecordedWhenItEnds(t *testing.T) {
	r := newRig(t, false)
	c := r.noted()
	r.mcp.Set(func(sw *stubs.ConnectorSwitches) { sw.Gap = 50 * time.Millisecond })
	a := r.call(c, "alice", "count", nil)
	if a.status != http.StatusOK || strings.Count(string(a.body), "event: message") != 4 {
		t.Fatalf("a stream: %d %s", a.status, a.body)
	}
	got := r.calls(c)
	if len(got) != 1 || got[0].Outcome != OutcomeOK || got[0].BytesOut != int64(len(a.body)) || got[0].DurationMS < 150 {
		t.Fatalf("the record of a whole stream %+v", got)
	}
	r.serving.Wait()
	r.c.IdleTimeout = 100 * time.Millisecond
	r.mcp.Set(func(sw *stubs.ConnectorSwitches) { sw.Gap = time.Second })
	a = r.call(c, "alice", "count", nil)
	got = r.calls(c)
	if len(got) != 2 || got[1].Outcome != OutcomeTimeout || got[1].BytesOut != int64(len(a.body)) || got[1].BytesOut == 0 {
		t.Fatalf("the record of a silent stream %+v", got)
	}
}

// failingCalls is a store whose call records do not write.
type failingCalls struct {
	*memory.Store
}

func (f failingCalls) Calls() store.Calls { return failingInsert{f.Store.Calls()} }

type failingInsert struct{ store.Calls }

func (failingInsert) Insert(context.Context, store.Call) error {
	return errors.New("the record table is gone")
}

// A record that fails to write leaves the call's answer whole and logs a
// warning with the record's and the connection's ids and no content.
func TestARecordFailureNeverFailsTheCall(t *testing.T) {
	r := newRig(t, false)
	c := r.noted()
	r.c.Store = failingCalls{r.st}
	a := r.call(c, "alice", "count", map[string]any{"secret": "an argument never logged"})
	if a.status != http.StatusOK || !strings.Contains(string(a.body), `"result"`) {
		t.Fatalf("the answer: %d %s", a.status, a.body)
	}
	r.serving.Wait()
	logged := r.logs.String()
	if !strings.Contains(logged, "a call record was not written") || !strings.Contains(logged, c.ID) || strings.Contains(logged, "never logged") {
		t.Fatalf("the warning: %s", logged)
	}
}
