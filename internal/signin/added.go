// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package signin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"latere.ai/x/pons/catalog"
	"latere.ai/x/pons/internal/apierr"
	"latere.ai/x/pons/internal/dial"
	"latere.ai/x/pons/internal/mcp"
)

// The ways an added connector's sign-in identifies Pons at its
// authorization server (specs/016-connectors-added-for-others.md), in the
// order they are chosen.
const (
	// ClientOwn is the client an administrator registered at the server
	// and gave with a vouched-for connector.
	ClientOwn = "own"
	// ClientByDocument is the connector's client metadata document.
	ClientByDocument = "document"
	// ClientRegistered is a dynamic registration, kept per issuer and
	// redirect address and reused by every connector at that issuer.
	ClientRegistered = "registered"
)

// Found is what an add found of how an added server signs people in: the
// authorization server, its token endpoint, whether it says its answer
// carries iss, and how Pons identifies itself there. It is stored with the
// connector, so its view, its client metadata document and the binding of
// its client's secret need no request.
type Found struct {
	Issuer        string `json:"issuer,omitempty"`
	TokenEndpoint string `json:"token_endpoint,omitempty"`
	Iss           bool   `json:"iss,omitempty"`
	Client        string `json:"client,omitempty"`
}

// Way is how the server at an added connector's address asks to be
// connected: auth.type none, oauth or token, and for oauth what the add
// found.
type Way struct {
	Type  string
	Found Found
}

// keyDigits is how many hex digits of the issuer's SHA-256 name its
// callback.
const keyDigits = 16

// IssuerKey names an issuer's own callback: the first 16 hex digits of the
// SHA-256 of the issuer.
func IssuerKey(issuer string) string {
	sum := sha256.Sum256([]byte(issuer))
	return hex.EncodeToString(sum[:])[:keyDigits]
}

// CallbackFor is the redirect address of an issuer's own: the callback
// with the issuer's key.
func (s *Signin) CallbackFor(issuer string) string {
	return s.RedirectURI() + "/" + IssuerKey(issuer)
}

// redirectFor is the redirect address a sign-in at an issuer uses: the
// shared callback, or, for an added server whose authorization server does
// not say its answer carries iss, a callback of the issuer's own, the
// other defense RFC 9700, section 4.4 names against a mix-up.
func (s *Signin) redirectFor(conn Connector, issuer string, iss bool) string {
	if conn.AddedURL != "" && !iss {
		return s.CallbackFor(issuer)
	}
	return s.RedirectURI()
}

// RedirectOf is the redirect address an added server's sign-ins use, as
// its add found it: the address its client metadata document names, and
// the one an administrator registers a vouched-for connector's client
// with.
func (s *Signin) RedirectOf(f Found) string {
	if f.Issuer != "" && !f.Iss {
		return s.CallbackFor(f.Issuer)
	}
	return s.RedirectURI()
}

// clientWay is how Pons identifies itself at a server whose metadata is
// md, in the protocol's order after a client of its own: a client metadata
// document, then dynamic registration, or "" for none.
func (s *Signin) clientWay(md metadataDocument) string {
	switch {
	case md.ClientIDMetadataDocumentSupported && strings.HasPrefix(s.PublicURL, "https://"):
		return ClientByDocument
	case md.RegistrationEndpoint != "":
		return ClientRegistered
	}
	return ""
}

// maxAskAnswer bounds what the add reads of the server's answer: enough to
// tell a JSON-RPC error of the current revision.
const maxAskAnswer = 64 << 10

// noAnswer is a server that did not answer as one that can be connected,
// with the status or the dialer's rule as the reason, never the address.
func noAnswer(reason string) *apierr.Error {
	return apierr.Fail(apierr.CodeServerUnreachable, reason)
}

// Ask asks the server at an added connector's address how to sign in
// (specs/016-connectors-added-for-others.md), with no credential: the
// request discovery makes first, a tools/list of the current revision,
// and for a server of an earlier revision its initialize. A success is
// none; a 401 whose protected resource metadata (RFC 9728) is found, in
// its challenge or at the well-known address, is oauth, checked through
// the authorization server's metadata as a sign-in checks it; a 401 or a
// 403 with no metadata is token; anything else is 422 server_unreachable.
// own is an add that carries a client of its own, registered at the
// server. Every request goes through the dialer.
func (s *Signin) Ask(ctx context.Context, conn Connector, own bool) (Way, error) {
	status, header, err := s.first(ctx, conn)
	if err != nil {
		return Way{}, err
	}
	switch {
	case status/100 == 2:
		return Way{Type: catalog.AuthNone}, nil
	case status == http.StatusForbidden:
		return Way{Type: catalog.AuthToken}, nil
	case status != http.StatusUnauthorized:
		return Way{}, noAnswer("status_" + strconv.Itoa(status))
	}
	challenge := ""
	for _, ch := range header.Values("WWW-Authenticate") {
		if strings.Contains(ch, "resource_metadata=") {
			challenge = ch
		}
	}
	doc, _, err := s.resourceAt(ctx, conn, challenge)
	if apierr.Classify(err).Reason == "no_resource_metadata" {
		return Way{Type: catalog.AuthToken}, nil
	}
	if err != nil {
		return Way{}, err
	}
	var last error = unsupported("no_authorization_server")
	for _, issuer := range doc.AuthorizationServers {
		md, err := s.metadata(ctx, conn, issuer)
		if err != nil {
			last = err
			continue
		}
		f := Found{Issuer: md.Issuer, TokenEndpoint: md.TokenEndpoint, Iss: md.IssParameterSupported, Client: ClientOwn}
		if !own {
			f.Client = s.clientWay(md)
		}
		if f.Client == "" {
			last = unsupported("no_client")
			continue
		}
		return Way{Type: catalog.AuthOAuth, Found: f}, nil
	}
	return Way{}, last
}

// first makes the add's first request and answers its status and headers:
// a tools/list of the current revision, and the earlier revision's
// initialize when the server answers the list 400 with no JSON-RPC error
// of the current revision. A session the initialize opens is ended.
func (s *Signin) first(ctx context.Context, conn Connector) (int, http.Header, error) {
	status, header, body, err := s.send(ctx, conn, func(ctx context.Context) (*http.Request, error) { return mcp.ListTools(ctx, conn.URL) })
	if err != nil || status != http.StatusBadRequest || mcp.ModernError(body) {
		return status, header, err
	}
	status, header, body, err = s.send(ctx, conn, func(ctx context.Context) (*http.Request, error) { return mcp.Initialize(ctx, conn.URL) })
	if err != nil {
		return 0, nil, err
	}
	if session := header.Get(mcp.HeaderSession); session != "" && status/100 == 2 {
		negotiated := mcp.Negotiated(body)
		if _, _, _, endErr := s.send(ctx, conn, func(ctx context.Context) (*http.Request, error) {
			return mcp.End(ctx, conn.URL, session, negotiated)
		}); endErr != nil {
			s.log().InfoContext(ctx, "the add's session was not ended", "reason", apierr.Classify(endErr).Reason)
		}
	}
	return status, header, nil
}

// send makes one request of the add through the dialer and answers its
// status, its headers and the start of its body.
func (s *Signin) send(ctx context.Context, conn Connector, build func(context.Context) (*http.Request, error)) (int, http.Header, []byte, error) {
	req, err := build(ctx)
	if err != nil {
		return 0, nil, nil, noAnswer(dial.SchemeNotHTTPS)
	}
	resp, err := s.Dial.Do(ctx, dial.Request{HTTP: req, Ports: conn.Ports(), Timeout: tokenTimeout, MaxBody: maxTokenAnswer})
	if err != nil {
		return 0, nil, nil, noAnswer(ruleOf(err))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxAskAnswer))
	if cerr := resp.Body.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return 0, nil, nil, noAnswer(ruleOf(err))
	}
	return resp.StatusCode, resp.Header, body, nil
}

// ruleOf is the dialer's rule an error names, or fetch_failed.
func ruleOf(err error) string {
	if name, _, ok := dial.ReasonOf(err); ok {
		return name
	}
	var e *apierr.Error
	if errors.As(err, &e) && e.Reason != "" {
		return e.Reason
	}
	return "fetch_failed"
}
