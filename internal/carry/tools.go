// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package carry

import (
	"context"
	"io"
	"net/http"
	"strconv"

	"latere.ai/x/pons/catalog"
	"latere.ai/x/pons/internal/apierr"
	"latere.ai/x/pons/internal/dial"
	"latere.ai/x/pons/internal/mcp"
	"latere.ai/x/pons/internal/signin"
	"latere.ai/x/pons/internal/store"
)

// The bounds of a connection's list of tools: how much of each answer is
// read, and how many pages are followed.
const (
	maxToolsAnswer = 1 << 20
	maxToolsPages  = 10
)

// Tool is one tool a connection's server lists, with the effect its
// connector's marks give it and whether they hide it.
type Tool struct {
	Name        string
	Description string
	Effect      string
	Hidden      bool
}

// Tools lists a connection's tools through it
// (specs/016-connectors-added-for-others.md): the connector's tools/list
// with the connection's credential, its pages followed, and for a server
// of an earlier revision its handshake, a list in the session it opens,
// and the DELETE that ends it. It is held to the state of the connection
// and its connector as a call is, refreshes a credential the server
// refuses once, and records no call.
func (c *Carrier) Tools(ctx context.Context, row store.Connection) ([]Tool, error) {
	c.init()
	if row.Kind != catalog.KindMCP {
		return nil, apierr.Fail(apierr.CodeWrongKind, "address_"+AddressMCP)
	}
	conn, gone, err := c.connectorOf(ctx, row)
	if err != nil {
		return nil, err
	}
	o, err := c.usable(ctx, row, conn, gone)
	if err != nil {
		return nil, err
	}
	if o, err = c.Signin.Fresh(ctx, o); err != nil {
		return nil, err
	}
	l := lister{c: c, o: o}
	raw, status, err := l.all(ctx, false)
	if err != nil {
		return nil, err
	}
	if status == http.StatusUnauthorized && o.Connection.Auth != catalog.AuthNone {
		retry, renew, _, err := c.refused(ctx, &call{}, o, false)
		if err != nil {
			return nil, err
		}
		l.o = retry
		if raw, status, err = l.all(ctx, renew); err != nil {
			return nil, err
		}
		if status == http.StatusUnauthorized {
			reason := store.ReasonRevoked
			if o.Connection.Auth == catalog.AuthClientCredentials {
				reason = store.ReasonCredentialRefused
			}
			return nil, signin.Refused(ctx, c.Store, o.Connection, reason)
		}
	}
	if status/100 != 2 {
		return nil, apierr.Fail(apierr.CodeConnectorUnavailable, "status_"+strconv.Itoa(status))
	}
	out := make([]Tool, 0, len(raw))
	for _, t := range raw {
		out = append(out, Tool{Name: t.Name, Description: t.Description, Effect: conn.Tools.Effect(t.Name), Hidden: conn.Tools.IsHidden(t.Name)})
	}
	return out, nil
}

// lister sends the requests of one list of tools with a credential in its
// place.
type lister struct {
	c     *Carrier
	o     signin.Opened
	place []dial.Secret
}

// all lists every page of tools, and answers the status of the first
// answer that was not a page: a list is the server's answer only when each
// of its requests succeeded.
func (l *lister) all(ctx context.Context, renew bool) ([]mcp.Tool, int, error) {
	place, err := l.c.place(ctx, &call{}, l.o, AddressMCP, renew)
	if err != nil {
		return nil, 0, err
	}
	l.place = place
	url := l.o.Connector.URL
	var tools []mcp.Tool
	cursor := ""
	session, negotiated := "", ""
	for range maxToolsPages {
		status, header, body, err := l.send(ctx, func(ctx context.Context) (*http.Request, error) {
			if negotiated != "" {
				return mcp.ListToolsIn(ctx, url, session, negotiated, cursor)
			}
			return mcp.ListToolsAfter(ctx, url, cursor)
		})
		if err != nil {
			return nil, 0, err
		}
		if status == http.StatusBadRequest && negotiated == "" && cursor == "" && !mcp.ModernError(body) {
			// A server of an earlier revision.
			if session, negotiated, status, err = l.handshake(ctx); err != nil || status/100 != 2 {
				return nil, status, err
			}
			defer l.end(ctx, session, negotiated)
			continue
		}
		if status/100 != 2 {
			return nil, status, nil
		}
		page, next, err := mcp.ToolsOf(header.Get("Content-Type"), body)
		if err != nil {
			return nil, 0, apierr.Fail(apierr.CodeConnectorUnavailable, "tools_unreadable")
		}
		tools = append(tools, page...)
		if next == "" {
			return tools, status, nil
		}
		cursor = next
	}
	return tools, http.StatusOK, nil
}

// handshake opens a session of the earlier revision: initialize, then the
// notification that ends the handshake.
func (l *lister) handshake(ctx context.Context) (session, negotiated string, status int, err error) {
	url := l.o.Connector.URL
	status, header, body, err := l.send(ctx, func(ctx context.Context) (*http.Request, error) { return mcp.Initialize(ctx, url) })
	if err != nil || status/100 != 2 {
		return "", "", status, err
	}
	session, negotiated = header.Get(mcp.HeaderSession), mcp.Negotiated(body)
	status, _, _, err = l.send(ctx, func(ctx context.Context) (*http.Request, error) {
		return mcp.Initialized(ctx, url, session, negotiated)
	})
	return session, negotiated, status, err
}

// end ends a session of the earlier revision; one left open ends at the
// server's own time.
func (l *lister) end(ctx context.Context, session, negotiated string) {
	if session == "" {
		return
	}
	url := l.o.Connector.URL
	if _, _, _, err := l.send(ctx, func(ctx context.Context) (*http.Request, error) {
		return mcp.End(ctx, url, session, negotiated)
	}); err != nil {
		l.c.log().InfoContext(ctx, "a list's session was not ended", "connection", l.o.Connection.ID, "reason", apierr.Classify(err).Reason)
	}
}

// send makes one request of the list through the dialer, the credential in
// its place, and reads its answer up to its bound.
func (l *lister) send(ctx context.Context, build func(context.Context) (*http.Request, error)) (int, http.Header, []byte, error) {
	req, err := build(ctx)
	if err != nil {
		return 0, nil, nil, apierr.Fail(apierr.CodeConnectorUnavailable, dial.SchemeNotHTTPS)
	}
	resp, err := l.c.Dial.Do(ctx, dial.Request{HTTP: req, Secrets: l.place, Ports: l.o.Connector.Ports(), Timeout: probeTimeout, Forward: true})
	if err != nil {
		name, _, _ := dial.ReasonOf(err)
		return 0, nil, nil, apierr.Fail(apierr.CodeConnectorUnavailable, name)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxToolsAnswer))
	closeBody(resp)
	if err != nil {
		name, _, _ := dial.ReasonOf(err)
		return 0, nil, nil, apierr.Fail(apierr.CodeConnectorUnavailable, name)
	}
	return resp.StatusCode, resp.Header, body, nil
}
