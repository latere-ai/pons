// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package carry is the carrier: it serves the addresses a caller reaches a
// connection at, adds the connection's credential, forwards the request
// through the dialer and streams the answer back (specs/008-carrying-a-call.md).
// Built here are the forwarding address and the git address of a connection
// of kind http (specs/014-http-forwarding.md), and the probe of a key for
// that kind.
//
// A request is taken in the order of spec 008: the origin, the caller and
// the places in flight, what is read from the request (its path, and for a
// push the refs it updates), the connection, the effect, one question, the
// kind, the limits of the allow, the state, the credential, the forward, the
// answer and the record. A caller who may not use a connection is answered
// 404 for every request to it, and nothing tells it the id exists.
//
// This package and internal/signin are the only callers of Sealer.Open.
package carry

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"latere.ai/x/pkg/ratelimit"

	"latere.ai/x/pons/authorizer"
	"latere.ai/x/pons/catalog"
	"latere.ai/x/pons/internal/access"
	"latere.ai/x/pons/internal/apierr"
	"latere.ai/x/pons/internal/dial"
	"latere.ai/x/pons/internal/id"
	"latere.ai/x/pons/internal/signin"
	"latere.ai/x/pons/internal/store"
)

// PerConnection is how many requests one connection has in flight in one
// process.
const PerConnection = 16

// The outcomes of a call (specs/008-carrying-a-call.md).
const (
	OutcomeOK              = "ok"
	OutcomeDenied          = "denied"
	OutcomeNotConnected    = "not_connected"
	OutcomeUpstreamError   = "upstream_error"
	OutcomeUpstreamRefused = "upstream_refused"
	OutcomeTimeout         = "timeout"
	OutcomeCanceled        = "canceled"
)

// Carrier serves the addresses of the connections of one process.
type Carrier struct {
	Store  store.Store
	Sealer store.Sealer
	Auth   access.Authenticator
	Authz  access.Authorizer
	Dial   *dial.Client
	Signin *signin.Signin
	// Resolve finds the connector a reference names: signin.ErrNoConnector
	// for one that left the catalog.
	Resolve func(ctx context.Context, ref string) (signin.Connector, error)

	// PublicURL and BasePath make a connection's addresses.
	PublicURL string
	BasePath  string
	// ReturnURLs are the addresses a browser returns to, whose origins
	// alone a request with an Origin header may come from.
	ReturnURLs []string

	// The bounds of a call.
	MaxForwardBytes       int64
	HeaderTimeout         time.Duration
	IdleTimeout           time.Duration
	MaxInflight           int
	MaxInflightPerSubject int

	Log *slog.Logger
	// Now is the clock; nil is time.Now.
	Now func() time.Time
	// IDs makes identifiers; nil is id.Default.
	IDs *id.Generator

	once   sync.Once
	places *places
	rate   *ratelimit.Buckets

	mu      sync.Mutex
	denied  map[string]time.Time // subject and connection: the last denied call recorded
	touched map[string]time.Time // connection: the last last_used_at this process wrote
}

func (c *Carrier) init() {
	c.once.Do(func() {
		c.places = &places{process: c.MaxInflight, subject: c.MaxInflightPerSubject, connection: PerConnection,
			subjects: map[string]int{}, connections: map[string]int{}}
		c.rate = ratelimit.New(ratelimit.Config{})
		c.denied, c.touched = map[string]time.Time{}, map[string]time.Time{}
	})
}

func (c *Carrier) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Carrier) log() *slog.Logger {
	if c.Log != nil {
		return c.Log
	}
	return slog.Default()
}

// Handles reports whether a request is to a forwarding or a git address,
// which the carrier serves before any router cleans its path.
func (c *Carrier) Handles(r *http.Request) bool {
	_, _, _, ok := c.split(r.URL.EscapedPath())
	return ok
}

// Pattern is the route template of a request the carrier serves, for its
// span and its metrics, holding no id.
func (c *Carrier) Pattern(r *http.Request) string {
	_, address, _, _ := c.split(r.URL.EscapedPath())
	return c.BasePath + "/connections/{id}/" + address + "/{path}"
}

// split reads an escaped path as {base}/connections/{id}/{address}{tail}.
func (c *Carrier) split(p string) (connection, address, tail string, ok bool) {
	rest, ok := strings.CutPrefix(p, c.BasePath+"/connections/")
	if !ok {
		return "", "", "", false
	}
	connection, rest, ok = strings.Cut(rest, "/")
	if !ok || connection == "" {
		return "", "", "", false
	}
	for _, a := range []string{AddressHTTP, AddressGit} {
		if rest == a || strings.HasPrefix(rest, a+"/") {
			return connection, a, rest[len(a):], true
		}
	}
	return "", "", "", false
}

// Address is where a caller reaches a connection at one of its addresses.
func (c *Carrier) Address(connection, address string) string {
	return c.PublicURL + c.BasePath + "/connections/" + connection + "/" + address
}

// ForwardedMethods are the methods the forwarding address carries, the
// ones an API is called with (specs/014-http-forwarding.md). Any other is
// refused before the connection is loaded: TRACE, which a service may
// answer with the request it received, CONNECT, and every method of
// another protocol.
var ForwardedMethods = []string{
	http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete,
}

// ServeHTTP serves one request to a forwarding or a git address.
func (c *Carrier) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.init()
	call := &call{start: c.now()}
	err := c.serve(w, r, call)
	if err != nil {
		e := apierr.Classify(err)
		call.fail(e)
		if !call.wrote {
			if apierr.Write(w, e).Code == apierr.CodeInternal {
				c.log().ErrorContext(r.Context(), "a call failed", "route", c.Pattern(r), "error", apierr.LogText(e.Cause()))
			}
		}
	}
	c.record(r, call)
}

// serve takes one request through the steps of spec 008. An error is the
// answer when nothing was written yet.
func (c *Carrier) serve(w http.ResponseWriter, r *http.Request, call *call) error {
	connection, address, tail, ok := c.split(r.URL.EscapedPath())
	if !ok {
		return apierr.Fail(apierr.CodeConnectionNotFound, "")
	}
	if !c.originAllowed(r) {
		return apierr.Fail(apierr.CodeForbidden, "origin")
	}
	caller, err := c.Auth.Authenticate(r)
	if err != nil {
		return apierr.Token(err)
	}
	release, err := c.places.caller(caller.Subject)
	if err != nil {
		return err
	}
	defer release()

	t, why := checkPath(tail)
	if why != "" {
		return apierr.Fail(apierr.CodeInvalidRequest, why)
	}
	if address == AddressHTTP && !slices.Contains(ForwardedMethods, r.Method) {
		return apierr.Fail(apierr.CodeInvalidRequest, "method")
	}
	service := ""
	if address == AddressGit {
		if service = gitService(r, t); service == "" {
			// The git address serves no web page of the git host.
			return apierr.Fail(apierr.CodeConnectionNotFound, "")
		}
	}
	if r.ContentLength > c.MaxForwardBytes {
		return apierr.Fail(apierr.CodeRequestTooLarge, "max_forward_bytes="+strconv.FormatInt(c.MaxForwardBytes, 10))
	}
	var push pushHead
	if service == ReceivePack && r.Method == http.MethodPost {
		if r.Header.Get("Content-Encoding") != "" {
			return apierr.OnField(apierr.CodeInvalidRequest, "Content-Encoding", "compressed_push")
		}
		if push, err = readCommands(r.Body); err != nil {
			return apierr.Fail(apierr.CodeInvalidRequest, "push_commands")
		}
	}

	ctx := r.Context()
	row, err := c.Store.Connections().Get(ctx, connection)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return apierr.Fail(apierr.CodeConnectionNotFound, "")
	case err != nil:
		return apierr.Internal(err)
	}
	conn, err := c.Resolve(ctx, row.Connector)
	gone := errors.Is(err, signin.ErrNoConnector) || (err == nil && (conn.Kind != row.Kind || conn.Auth.Type != row.Auth))
	if err != nil && !gone {
		return apierr.Internal(err)
	}
	if gone {
		conn = signin.Connector{}
	}
	tool, effect := service, catalog.EffectRead
	switch {
	case address == AddressHTTP:
		tool, effect = "/"+t.decoded, conn.RequestEffect(r.Method, "/"+t.decoded)
	case service == ReceivePack:
		effect = catalog.EffectWrite
	}
	refs := push.refs()
	call.found(row, caller, r.Method, tool, effect, len(refs), int64(len(push.read)))

	// One question, with what the request names.
	res := access.Connection{
		ID: row.ID, Owner: row.Owner, Connector: row.Connector, Name: row.Name, Kind: row.Kind,
		Method: r.Method, Tool: tool, Effect: effect, Refs: refs,
	}
	d, err := c.Authz.Authorize(ctx, caller, access.Ask(r, authorizer.ActionConnectionUse, res.Resource(authorizer.ActionConnectionUse)))
	switch {
	case errors.Is(err, access.ErrUnavailable):
		c.log().WarnContext(ctx, "the authorizer gave no decision", "route", c.Pattern(r), "error", apierr.LogText(err))
		return apierr.Fail(apierr.CodeAuthorizerUnavailable, "")
	case err != nil:
		return apierr.Internal(err)
	case !d.Allow:
		call.outcome = OutcomeDenied
		return apierr.Fail(apierr.CodeConnectionNotFound, "")
	}
	if row.Kind != catalog.KindHTTP || (address == AddressGit && !gone && conn.GitURL() == "") {
		call.outcome = OutcomeDenied
		return apierr.Fail(apierr.CodeWrongKind, "address_"+address)
	}
	releaseConn, err := c.hold(d.Limits, caller.Subject, row.ID, r.Method, effect, tool, refs, address == AddressHTTP)
	if err != nil {
		call.outcome = OutcomeDenied
		if e := apierr.Classify(err); e.Field == fieldRefs {
			return c.refusePush(w, r, call, push, d.Limits, err)
		}
		return err
	}
	defer releaseConn()

	o, err := c.usable(ctx, row, conn, gone)
	if err != nil {
		return err
	}
	if o, err = c.Signin.Fresh(ctx, o); err != nil {
		call.upstream(err)
		return err
	}
	return c.forward(w, r, call, o, address, service, t, push.read)
}

// fieldRefs is the member a refusal by Refs is about: a push answered in
// git's protocol, so git prints the reason.
const fieldRefs = "refs"

// hold applies the limits of an allow (specs/004-identity-and-authorization.md)
// and takes the connection's place in flight. A refusal is a 403 on the
// member it is about, or a 429.
func (c *Carrier) hold(l authorizer.Limits, subject, connection, method, effect, tool string, refs []string, forwarding bool) (func(), error) {
	if l.ReadOnly && effect == catalog.EffectWrite {
		return nil, apierr.OnField(apierr.CodeForbidden, "tool", "read_only")
	}
	if !l.AdmitsTool(tool) {
		return nil, apierr.OnField(apierr.CodeForbidden, "tool", "tools")
	}
	if forwarding && !l.AdmitsRequest(method, tool) {
		return nil, apierr.OnField(apierr.CodeForbidden, "tool", "requests")
	}
	for _, ref := range refs {
		if !l.AdmitsRef(ref) {
			return nil, apierr.OnField(apierr.CodeForbidden, fieldRefs, "refs")
		}
	}
	if l.CallsPerMinute > 0 {
		key := subject + "\n" + connection
		c.rate.SetRate(key, l.CallsPerMinute)
		if !c.rate.Allow(key).OK {
			return nil, apierr.Fail(apierr.CodeRateLimited, "calls_per_minute="+strconv.Itoa(l.CallsPerMinute))
		}
	}
	return c.places.connectionPlace(connection)
}

// usable is the credential of a connection that may be used: one
// connected, or pending for a reconnect with the credential it had and no
// reason (specs/002-objects.md). Any other answers 409 with its state. The
// credential is opened and not yet refreshed.
func (c *Carrier) usable(ctx context.Context, row store.Connection, conn signin.Connector, gone bool) (signin.Opened, error) {
	if gone {
		return signin.Opened{}, &apierr.Error{Code: apierr.CodeConnectionNotConnected, Reason: "connector_removed", Extra: map[string]any{"state": string(row.State)}}
	}
	reason := row.Reason
	switch {
	case row.State == store.StatePending && reason == "":
		reason = "not_confirmed"
	case row.State == store.StateConnected:
		reason = ""
	}
	if row.State == store.StateNeedsReconnect || (row.State == store.StatePending && row.Reason != "") {
		return signin.Opened{}, &apierr.Error{Code: apierr.CodeConnectionNotConnected, Reason: reason, Extra: map[string]any{"state": string(row.State)}}
	}
	if row.Auth == catalog.AuthNone {
		if row.State != store.StateConnected {
			return signin.Opened{}, &apierr.Error{Code: apierr.CodeConnectionNotConnected, Reason: reason, Extra: map[string]any{"state": string(row.State)}}
		}
		return signin.Opened{Connection: row, Connector: conn}, nil
	}
	o, err := signin.Open(ctx, c.Store, c.Sealer, row, conn)
	switch {
	case errors.Is(err, store.ErrNotFound):
		// A pending connection that never had a credential.
		return signin.Opened{}, &apierr.Error{Code: apierr.CodeConnectionNotConnected, Reason: reason, Extra: map[string]any{"state": string(row.State)}}
	case err != nil:
		c.log().WarnContext(ctx, "a credential did not open", "connection", row.ID, "reason", apierr.Classify(err).Reason)
		return signin.Opened{}, err
	}
	return o, nil
}

// originAllowed is the check against DNS rebinding the transport asks of a
// server: a request that carries an Origin comes from the origin of an
// address a browser returns to.
func (c *Carrier) originAllowed(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	for _, raw := range c.ReturnURLs {
		u, err := url.Parse(raw)
		if err == nil && u.Scheme+"://"+u.Host == origin {
			return true
		}
	}
	return false
}

// places are the requests in flight of one process: in all, per subject
// and per connection, each taken without waiting.
type places struct {
	mu                           sync.Mutex
	process, subject, connection int
	total                        int
	subjects                     map[string]int
	connections                  map[string]int
}

// caller takes a place for the process and one for the subject, before the
// body is read.
func (p *places) caller(subject string) (func(), error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	switch {
	case p.process > 0 && p.total >= p.process:
		return nil, apierr.Fail(apierr.CodeRateLimited, "max_inflight="+strconv.Itoa(p.process))
	case p.subject > 0 && p.subjects[subject] >= p.subject:
		return nil, apierr.Fail(apierr.CodeRateLimited, "max_inflight_per_subject="+strconv.Itoa(p.subject))
	}
	p.total++
	p.subjects[subject]++
	return func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		p.total--
		if p.subjects[subject]--; p.subjects[subject] <= 0 {
			delete(p.subjects, subject)
		}
	}, nil
}

// connectionPlace takes one of a connection's places in flight.
func (p *places) connectionPlace(connection string) (func(), error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.connections[connection] >= p.connection {
		return nil, apierr.Fail(apierr.CodeRateLimited, "connection_inflight="+strconv.Itoa(p.connection))
	}
	p.connections[connection]++
	return func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.connections[connection]--; p.connections[connection] <= 0 {
			delete(p.connections, connection)
		}
	}, nil
}
