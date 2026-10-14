// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package carry

import (
	"context"
	"io"
	"net/http"
	"strconv"
	"time"

	"latere.ai/x/pons/catalog"
	"latere.ai/x/pons/internal/apierr"
	"latere.ai/x/pons/internal/dial"
	"latere.ai/x/pons/internal/mcp"
	"latere.ai/x/pons/internal/signin"
	"latere.ai/x/pons/internal/store"
)

// probeTimeout bounds the probe of a key, whole.
const probeTimeout = 15 * time.Second

// maxProbeAnswer bounds what the probe reads of an answer: enough to tell a
// JSON-RPC error of the current revision, or the version an initialize
// negotiated.
const maxProbeAnswer = 64 << 10

// Probe tries a key against a connector before it is stored. For kind http
// (specs/014-http-forwarding.md) it is one GET of the connector's url; for
// kind mcp (specs/008-carrying-a-call.md) a tools/list of the current
// revision, and for a connector of an earlier revision that revision's
// handshake, a tools/list in the session it opens, and the DELETE that ends
// it. Each has the key in its place. A 401 or a 403 refuses the key, 422
// credential_refused; no answer is 422 connector_unreachable. Any other
// answer of kind http accepts the key, since the service answered without
// refusing it; of kind mcp only a 2xx does, and anything else is a
// connector that cannot be reached. No answer reaches a caller or is kept.
func (c *Carrier) Probe(ctx context.Context, conn signin.Connector, secrets store.Secrets, meta store.Meta) error {
	o := signin.Opened{Connection: store.Connection{Auth: catalog.AuthToken}, Connector: conn, Secrets: secrets, Meta: meta}
	address := AddressHTTP
	if conn.Kind == catalog.KindMCP {
		address = AddressMCP
	}
	place, err := c.place(ctx, &call{}, o, address, false)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	p := prober{c: c, conn: conn, place: place}
	if conn.Kind == catalog.KindMCP {
		return p.mcp(ctx)
	}
	status, err := p.send(ctx, false, func(ctx context.Context) (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, conn.URL, nil)
		if err == nil {
			req.Header.Set("Accept", "application/json")
		}
		return req, err
	})
	if err != nil {
		return err
	}
	return refusedBy(status)
}

// refusedBy is the outcome of a probe's status: a 401 or a 403 refuses the
// key.
func refusedBy(status int) error {
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		return apierr.Fail(apierr.CodeCredentialRefused, "status_"+strconv.Itoa(status))
	}
	return nil
}

// prober sends the probe's requests to one connector with the key in its
// place.
type prober struct {
	c     *Carrier
	conn  signin.Connector
	place []dial.Secret
	// header and body are of the last answer, its body read up to
	// maxProbeAnswer.
	header http.Header
	body   []byte
}

// mcp is the probe of kind mcp.
func (p *prober) mcp(ctx context.Context) error {
	url := p.conn.URL
	status, err := p.send(ctx, false, func(ctx context.Context) (*http.Request, error) { return mcp.ListTools(ctx, url) })
	if err != nil {
		return err
	}
	if status == http.StatusBadRequest && !mcp.ModernError(p.body) {
		// A connector of an earlier revision, as the transport's backward
		// compatibility describes.
		if status, err = p.earlier(ctx); err != nil {
			return err
		}
	}
	if err := refusedBy(status); err != nil {
		return err
	}
	if status/100 != 2 {
		return apierr.Fail(apierr.CodeConnectorUnreachable, "status_"+strconv.Itoa(status))
	}
	return nil
}

// earlier is the probe of a connector of an earlier revision: initialize,
// then, in the session it opened, the notification that ends the
// handshake and a tools/list, whose status it answers; the session is ended
// with DELETE whatever the list answered.
func (p *prober) earlier(ctx context.Context) (int, error) {
	url := p.conn.URL
	status, err := p.send(ctx, true, func(ctx context.Context) (*http.Request, error) { return mcp.Initialize(ctx, url) })
	if err != nil || status/100 != 2 {
		return status, err
	}
	session, negotiated := p.header.Get(mcp.HeaderSession), mcp.Negotiated(p.body)
	if status, err = p.send(ctx, false, func(ctx context.Context) (*http.Request, error) {
		return mcp.Initialized(ctx, url, session, negotiated)
	}); err != nil || status/100 != 2 {
		return status, err
	}
	status, err = p.send(ctx, false, func(ctx context.Context) (*http.Request, error) {
		return mcp.ListToolsIn(ctx, url, session, negotiated)
	})
	if session != "" {
		// A session left open ends at the connector's own time; the key's
		// outcome is the list's.
		if _, endErr := p.send(ctx, false, func(ctx context.Context) (*http.Request, error) {
			return mcp.End(ctx, url, session, negotiated)
		}); endErr != nil {
			p.c.log().InfoContext(ctx, "the probe's session was not ended", "connector", p.conn.Name, "reason", apierr.Classify(endErr).Reason)
		}
	}
	return status, err
}

// send makes one request of the probe through the dialer and answers its
// status, keeping its headers and, when read is set or the status is 400,
// the start of its body; a body that is not read is closed unread, so an
// answer that streams does not hold the probe. No answer is 422
// connector_unreachable, naming the dialer's rule.
func (p *prober) send(ctx context.Context, read bool, build func(context.Context) (*http.Request, error)) (int, error) {
	req, err := build(ctx)
	if err != nil {
		return 0, apierr.Fail(apierr.CodeConnectorUnreachable, dial.SchemeNotHTTPS)
	}
	resp, err := p.c.Dial.Do(ctx, dial.Request{HTTP: req, Secrets: p.place, Ports: p.conn.Ports(), Timeout: probeTimeout, Forward: true})
	if err != nil {
		name, _, _ := dial.ReasonOf(err)
		return 0, apierr.Fail(apierr.CodeConnectorUnreachable, name)
	}
	p.header, p.body = resp.Header, nil
	if read || resp.StatusCode == http.StatusBadRequest {
		p.body, err = io.ReadAll(io.LimitReader(resp.Body, maxProbeAnswer))
	}
	closeBody(resp)
	if err != nil {
		name, _, _ := dial.ReasonOf(err)
		return 0, apierr.Fail(apierr.CodeConnectorUnreachable, name)
	}
	return resp.StatusCode, nil
}
