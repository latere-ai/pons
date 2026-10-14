// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package carry

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"latere.ai/x/pons/authorizer"
	"latere.ai/x/pons/catalog"
	"latere.ai/x/pons/internal/access"
	"latere.ai/x/pons/internal/apierr"
	"latere.ai/x/pons/internal/dial"
	"latere.ai/x/pons/internal/mcp"
	"latere.ai/x/pons/internal/signin"
	"latere.ai/x/pons/internal/store"
)

// AddressMCP is the MCP address of a connection of kind mcp, a Model
// Context Protocol server over streamable HTTP toward the connector's url
// (specs/008-carrying-a-call.md).
const AddressMCP = "mcp"

// MCPMethods are the methods the MCP address carries: POST, the one method
// of the current revision, and GET and DELETE, which the revisions
// 2025-03-26 to 2025-11-25 use to open a stream and to end a session. Any
// other is refused before the connection is loaded.
var MCPMethods = []string{http.MethodPost, http.MethodGet, http.MethodDelete}

// The headers that pass toward the connector on the MCP address, beside
// every Mcp-Param- header, which mirrors an argument a server asked for.
// Everything else is removed, the caller's Authorization first.
var towardMCP = []string{
	"Accept", "Content-Type", mcp.HeaderVersion, mcp.HeaderMethod, mcp.HeaderName, mcp.HeaderSession, "Last-Event-ID",
}

// backMCP are the headers that pass back to the caller on the MCP address.
// WWW-Authenticate, Set-Cookie and Location never do: a caller that saw the
// connector's challenge would sign in at the connector around Pons.
var backMCP = []string{"Content-Type", "Cache-Control", "Retry-After", mcp.HeaderSession}

// serveMCP takes one request to the MCP address from step 3 of spec 008 on:
// the body, the connection, the effect, the question, the kind, the limits,
// the state, the credential, the forward and the answer.
func (c *Carrier) serveMCP(w http.ResponseWriter, r *http.Request, call *call, caller access.Caller, connection string) error {
	if !slices.Contains(MCPMethods, r.Method) {
		return apierr.Fail(apierr.CodeInvalidRequest, "method")
	}
	var (
		body []byte
		msg  message
	)
	method := r.Method
	if r.Method == http.MethodPost {
		var err error
		if body, err = c.readMessage(r); err != nil {
			return err
		}
		var why string
		if msg, why = parseMessage(body); why != "" {
			return apierr.Fail(apierr.CodeInvalidRequest, why)
		}
		if mirroredDiffers(r.Header, msg) {
			return apierr.Fail(apierr.CodeInvalidRequest, whyMirrored)
		}
		method = msg.method
	}

	ctx := r.Context()
	row, err := c.Store.Connections().Get(ctx, connection)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return apierr.Fail(apierr.CodeConnectionNotFound, "")
	case err != nil:
		return apierr.Internal(err)
	}
	conn, gone, err := c.connectorOf(ctx, row)
	if err != nil {
		return err
	}
	effect := ""
	if msg.method == MethodToolsCall {
		effect = conn.Tools.Effect(msg.tool)
	}
	call.found(row, caller, method, msg.tool, effect, 0, int64(len(body)))

	// One question, with the method, and the tool and its effect for a
	// tools/call.
	res := access.Connection{
		ID: row.ID, Owner: row.Owner, Connector: row.Connector, Name: row.Name, Kind: row.Kind,
		Method: method, Tool: msg.tool, Effect: effect,
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
	if row.Kind != catalog.KindMCP {
		call.outcome = OutcomeDenied
		return apierr.Fail(apierr.CodeWrongKind, "address_"+AddressMCP)
	}
	release, err := c.holdCall(d.Limits, caller.Subject, row.ID, msg, effect, conn.Tools)
	if err != nil {
		call.outcome = OutcomeDenied
		return err
	}
	defer release()

	o, err := c.usable(ctx, row, conn, gone)
	if err != nil {
		return err
	}
	if o, err = c.Signin.Fresh(ctx, o); err != nil {
		call.upstream(err)
		return err
	}
	return c.forwardMCP(w, r, call, o, body)
}

// readMessage reads a POST's body whole, up to PONS_MAX_REQUEST_BYTES: a
// Content-Length above it is refused before a byte is read, and a body
// that runs past it is refused when it does.
func (c *Carrier) readMessage(r *http.Request) ([]byte, error) {
	tooLarge := apierr.Fail(apierr.CodeRequestTooLarge, "max_request_bytes="+strconv.FormatInt(c.MaxRequestBytes, 10))
	if r.ContentLength > c.MaxRequestBytes {
		return nil, tooLarge
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, c.MaxRequestBytes+1))
	switch {
	case err != nil:
		return nil, apierr.Fail(apierr.CodeInvalidRequest, "body_unreadable")
	case int64(len(body)) > c.MaxRequestBytes:
		return nil, tooLarge
	}
	return body, nil
}

// connectorOf resolves a connection's connector. gone is a connector that
// left the catalog, or whose kind or way to give access no longer equals
// the connection's copy, which reads as empty.
func (c *Carrier) connectorOf(ctx context.Context, row store.Connection) (signin.Connector, bool, error) {
	conn, err := c.Resolve(ctx, row.Connector)
	gone := errors.Is(err, signin.ErrNoConnector) || (err == nil && (conn.Kind != row.Kind || conn.Auth.Type != row.Auth))
	if err != nil && !gone {
		return signin.Connector{}, false, apierr.Internal(err)
	}
	if gone {
		return signin.Connector{}, true, nil
	}
	return conn, false, nil
}

// holdCall applies the limits of an allow to a request to the MCP address
// (specs/004-identity-and-authorization.md). ReadOnly, Tools and the hidden
// mark bind tools/call alone, so a list of tools is carried as it is; the
// rate and the connection's places hold every request.
func (c *Carrier) holdCall(l authorizer.Limits, subject, connection string, m message, effect string, marks catalog.Marks) (func(), error) {
	if m.method == MethodToolsCall {
		switch {
		case l.ReadOnly && effect == catalog.EffectWrite:
			return nil, apierr.OnField(apierr.CodeForbidden, "tool", "read_only")
		case !l.AdmitsTool(m.tool):
			return nil, apierr.OnField(apierr.CodeForbidden, "tool", "tools")
		case marks.IsHidden(m.tool):
			return nil, apierr.OnField(apierr.CodeForbidden, "tool", "hidden")
		}
	}
	return c.admit(l, subject, connection)
}

// forwardMCP sends the request to the connector's url as the catalog writes
// it, with the credential in its place, handles a refusal of the
// credential, and streams the answer back. A POST's body is held in memory,
// so a request the connector refused can always be sent again.
func (c *Carrier) forwardMCP(w http.ResponseWriter, r *http.Request, call *call, o signin.Opened, body []byte) error {
	conn := o.Connector
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	send := func(o signin.Opened, renew bool) (*http.Response, error) {
		secrets, err := c.place(ctx, call, o, AddressMCP, renew)
		if err != nil {
			return nil, err
		}
		var rd io.Reader
		if r.Method == http.MethodPost {
			rd = bytes.NewReader(body)
		}
		out, err := http.NewRequestWithContext(ctx, r.Method, conn.URL, rd)
		if err != nil {
			return nil, apierr.Internal(err)
		}
		out.Header = headersTowardMCP(r.Header)
		resp, err := c.Dial.Do(ctx, dial.Request{HTTP: out, Secrets: secrets, Ports: conn.Ports(), HeaderTimeout: c.HeaderTimeout, Forward: true})
		if err != nil {
			return nil, c.failed(r, call, nil, err)
		}
		return resp, nil
	}

	resp, err := send(o, false)
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusUnauthorized && o.Connection.Auth != catalog.AuthNone {
		closeBody(resp)
		retry, renew, _, err := c.refused(ctx, call, o, false)
		if err != nil {
			return err
		}
		if resp, err = send(retry, renew); err != nil {
			return err
		}
		if resp.StatusCode == http.StatusUnauthorized {
			closeBody(resp)
			call.outcome = OutcomeUpstreamRefused
			reason := store.ReasonRevoked
			if o.Connection.Auth == catalog.AuthClientCredentials {
				reason = store.ReasonCredentialRefused
			}
			return signin.Refused(ctx, c.Store, o.Connection, reason)
		}
	}
	defer closeBody(resp)
	if resp.StatusCode == http.StatusForbidden && o.Connection.Auth == catalog.AuthOAuth {
		if scopes, ok := insufficientScope(resp.Header.Values("WWW-Authenticate")); ok {
			call.outcome = OutcomeUpstreamRefused
			return &apierr.Error{Code: apierr.CodeConnectionNotConnected, Reason: "scope_insufficient",
				Extra: map[string]any{"state": string(o.Connection.State), "scopes": scopes}}
		}
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		// The address a connector names is not one the catalog named, so
		// no redirect is followed and none passes.
		call.outcome, call.Status = OutcomeUpstreamError, resp.StatusCode
		return &apierr.Error{Code: apierr.CodeConnectorUnavailable, Reason: dial.RedirectRefused, Retryable: new(false)}
	}
	headersBackMCP(w.Header(), resp.Header)
	return c.stream(w, r, call, resp, cancel)
}

// headersTowardMCP copies the headers a request to the MCP address carries
// toward the connector, and asks for no content coding, so the answer
// passes as the connector wrote it.
func headersTowardMCP(in http.Header) http.Header {
	out := http.Header{}
	for name, values := range in {
		canonical := http.CanonicalHeaderKey(name)
		if containsFold(towardMCP, canonical) || strings.HasPrefix(strings.ToLower(canonical), "mcp-param-") {
			out[canonical] = append([]string(nil), values...)
		}
	}
	out.Set("Accept-Encoding", "identity")
	return out
}

// headersBackMCP copies the headers of an answer that pass back to the
// caller, and adds X-Accel-Buffering: no to an event stream, so a proxy
// between holds none of its events.
func headersBackMCP(dst, src http.Header) {
	for name, values := range src {
		canonical := http.CanonicalHeaderKey(name)
		if containsFold(backMCP, canonical) {
			dst[canonical] = append([]string(nil), values...)
		}
	}
	if strings.HasPrefix(strings.ToLower(src.Get("Content-Type")), "text/event-stream") {
		dst.Set("X-Accel-Buffering", "no")
	}
}
