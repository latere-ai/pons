// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package carry

import (
	"context"
	"net/http"
	"time"

	"latere.ai/x/pons/internal/access"
	"latere.ai/x/pons/internal/apierr"
	"latere.ai/x/pons/internal/id"
	"latere.ai/x/pons/internal/store"
)

// The bounds of a record (specs/010-records-and-observability.md).
const (
	// maxRecorded bounds the tool and the session a record keeps.
	maxRecorded = 128
	// recordTimeout bounds the write of a record, detached from its
	// request so a caller who leaves still leaves one.
	recordTimeout = 5 * time.Second
	// deniedEvery is how often a denied call of one subject to one
	// connection is recorded on a replica.
	deniedEvery = time.Minute
)

// call is one request to an address as it is recorded: the record, when
// the request began, and how it is ending.
type call struct {
	store.Call
	start time.Time
	// due says the connection was found, so the request leaves a record;
	// skip says Pons failed on its own, a 500 or a 503, which leaves none.
	due, skip bool
	// wrote says the answer's headers are out, so an error is not
	// answered.
	wrote   bool
	outcome string
}

// found fills what a record says once the connection is found.
func (c *call) found(row store.Connection, caller access.Caller, method, tool, effect string, refs int, bytesIn int64) {
	c.due = true
	c.Connection, c.Owner, c.Connector = row.ID, row.Owner, row.Connector
	c.Subject, c.Session = caller.Subject, session(caller.Claims)
	c.Method, c.Tool, c.Effect, c.Refs, c.BytesIn = method, truncate(tool), effect, refs, bytesIn
}

// fail sets the outcome of a request that ends with an error, when no step
// named it: a refusal of Pons's own is no call of the connector.
func (c *call) fail(e *apierr.Error) {
	if !c.due || c.outcome != "" {
		return
	}
	switch e.Code {
	case apierr.CodeInternal, apierr.CodeAuthorizerUnavailable, apierr.CodeSealingUnavailable:
		c.skip = true
	case apierr.CodeConnectorTimeout:
		c.outcome = OutcomeTimeout
	case apierr.CodeConnectionNotConnected:
		c.outcome = OutcomeNotConnected
	case apierr.CodeConnectorUnavailable:
		c.outcome = OutcomeUpstreamError
	default:
		c.outcome = OutcomeDenied
	}
}

// upstream names the outcome of a refresh or a mint that failed: refused
// by the other service, or not answered.
func (c *call) upstream(err error) {
	switch apierr.Classify(err).Code {
	case apierr.CodeConnectionNotConnected:
		c.outcome = OutcomeUpstreamRefused
	case apierr.CodeConnectorUnavailable, apierr.CodeConnectorTimeout:
		c.outcome = OutcomeUpstreamError
	}
}

// session is the record's copy of a token's session claim: the claim when it
// is a string, its id when it is an object, at most 128 bytes, and nothing
// for any other shape. The claim is not read for meaning.
func session(claims map[string]any) string {
	var s string
	switch v := claims["session"].(type) {
	case string:
		s = v
	case map[string]any:
		s, _ = v["id"].(string)
	}
	if len(s) > maxRecorded {
		return ""
	}
	return s
}

// truncate bounds what a record keeps of a tool.
func truncate(s string) string {
	if len(s) > maxRecorded {
		return s[:maxRecorded]
	}
	return s
}

// record writes the request's record when it ends, detached from the
// request, and touches the connection's last use. A denied call is recorded
// at most once per subject and connection per minute; a record that fails
// to write is logged and never the call's failure.
func (c *Carrier) record(r *http.Request, call *call) {
	if !call.due || call.skip {
		return
	}
	if call.outcome == "" {
		call.outcome = OutcomeOK
	}
	now := c.now()
	call.Outcome = call.outcome
	call.At = call.start
	call.DurationMS = now.Sub(call.start).Milliseconds()
	call.ID = c.newID()
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), recordTimeout)
	defer cancel()
	c.log().InfoContext(ctx, "a call ended", "call", call.ID, "connection", call.Connection, "connector", call.Connector,
		"outcome", call.Outcome, "status", call.Status, "duration_ms", call.DurationMS, "bytes_in", call.BytesIn, "bytes_out", call.BytesOut)
	if call.Outcome == OutcomeDenied && !c.firstDenied(call.Subject, call.Connection, now) {
		return
	}
	if err := c.Store.Calls().Insert(ctx, call.Call); err != nil {
		c.log().WarnContext(ctx, "a call record was not written", "call", call.ID, "connection", call.Connection, "error", apierr.LogText(err))
	}
	if call.Outcome != OutcomeDenied && call.Outcome != OutcomeNotConnected {
		c.touch(ctx, call.Connection, now)
	}
}

func (c *Carrier) newID() string {
	if c.IDs != nil {
		return c.IDs.New(id.Call)
	}
	return id.New(id.Call)
}

// firstDenied reports whether a denied call is the first of its subject and
// connection in a minute on this replica.
func (c *Carrier) firstDenied(subject, connection string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := subject + "\n" + connection
	if last, ok := c.denied[key]; ok && now.Sub(last) < deniedEvery {
		return false
	}
	for k, last := range c.denied {
		if now.Sub(last) >= deniedEvery {
			delete(c.denied, k)
		}
	}
	c.denied[key] = now
	return true
}

// touch writes a connection's last use when this replica has not written it
// within the minute; the store writes it only when it is a minute behind.
func (c *Carrier) touch(ctx context.Context, connection string, now time.Time) {
	c.mu.Lock()
	last, ok := c.touched[connection]
	if ok && now.Sub(last) < store.TouchInterval {
		c.mu.Unlock()
		return
	}
	c.touched[connection] = now
	c.mu.Unlock()
	if err := c.Store.Connections().Touch(ctx, connection, now); err != nil {
		c.log().WarnContext(ctx, "a connection's last use was not written", "connection", connection, "error", apierr.LogText(err))
	}
}
