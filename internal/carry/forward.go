// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package carry

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"latere.ai/x/pons/catalog"
	"latere.ai/x/pons/internal/apierr"
	"latere.ai/x/pons/internal/dial"
	"latere.ai/x/pons/internal/signin"
	"latere.ai/x/pons/internal/store"
)

// forward sends the request to the connector with the credential in its
// place, handles a refusal of the credential, and streams the answer back.
func (c *Carrier) forward(w http.ResponseWriter, r *http.Request, call *call, o signin.Opened, address, service string, t target, prefix []byte) error {
	conn := o.Connector
	base := conn.URL
	if address == AddressGit {
		base = conn.GitURL()
	}
	dest, err := join(base, t, r.URL.RawQuery)
	if err != nil {
		return apierr.Internal(err)
	}
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	hasBody := r.Body != nil && r.Body != http.NoBody && r.ContentLength != 0
	var body *bounded
	if hasBody {
		body = &bounded{r: io.MultiReader(bytes.NewReader(prefix), r.Body), left: c.MaxForwardBytes}
	}
	send := func(o signin.Opened, renew bool) (*http.Response, error) {
		secrets, err := c.place(ctx, call, o, address, renew)
		if err != nil {
			return nil, err
		}
		var rd io.Reader
		if body != nil {
			rd = body
		}
		out, err := http.NewRequestWithContext(ctx, r.Method, dest.String(), rd)
		if err != nil {
			return nil, apierr.Internal(err)
		}
		out.Header = toward(r.Header, conn.Connector, address, service)
		out.ContentLength = r.ContentLength
		if body == nil {
			out.ContentLength = 0
		}
		resp, err := c.Dial.Do(ctx, dial.Request{HTTP: out, Secrets: secrets, Ports: conn.Ports(), HeaderTimeout: c.HeaderTimeout, Forward: true})
		if err != nil {
			return nil, c.failed(r, call, body, err)
		}
		return resp, nil
	}

	resp, err := send(o, false)
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusUnauthorized && o.Connection.Auth != catalog.AuthNone {
		retry, renew, pass, err := c.refused(ctx, call, o, hasBody)
		if err != nil {
			closeBody(resp)
			return err
		}
		// A request with a body is not sent again (pass): the 401 the
		// connector gave is answered, and the next request uses the
		// refreshed credential.
		if !pass {
			closeBody(resp)
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
	}
	defer closeBody(resp)
	if resp.StatusCode == http.StatusForbidden && o.Connection.Auth == catalog.AuthOAuth {
		if scopes, ok := insufficientScope(resp.Header.Values("WWW-Authenticate")); ok {
			call.outcome = OutcomeUpstreamRefused
			return &apierr.Error{Code: apierr.CodeConnectionNotConnected, Reason: "scope_insufficient",
				Extra: map[string]any{"state": string(o.Connection.State), "scopes": scopes}}
		}
	}
	addr := c.Address(o.Connection.ID, address)
	if resp.StatusCode >= 300 && resp.StatusCode < 400 && resp.Header.Get("Location") != "" {
		loc, ok := location(resp.Header.Get("Location"), dest, base, addr)
		if !ok {
			call.outcome, call.Status = OutcomeUpstreamError, resp.StatusCode
			return &apierr.Error{Code: apierr.CodeConnectorUnavailable, Reason: "redirect_elsewhere", Retryable: new(false)}
		}
		w.Header().Set("Location", loc)
	}
	backward(w.Header(), resp.Header, conn.Connector)
	if links := resp.Header.Values("Link"); len(links) > 0 {
		if kept := rewriteLinks(links, base, addr); kept != "" {
			w.Header().Set("Link", kept)
		}
	}
	err = c.stream(w, r, call, resp, cancel)
	if body != nil {
		call.BytesIn = body.read
	}
	return err
}

// place is the credential's place on one request, handed to the dialer
// bound to the connector's hosts: a bearer for oauth and a minted token, the
// connector's inject for a key, and on the git address git.inject when the
// entry gives it. renew mints a client's token anew.
func (c *Carrier) place(ctx context.Context, call *call, o signin.Opened, address string, renew bool) ([]dial.Secret, error) {
	hosts := catalog.Matcher(o.Connector.HostPatterns())
	var token string
	switch o.Connection.Auth {
	case catalog.AuthNone:
		return nil, nil
	case catalog.AuthOAuth:
		token = o.Secrets.AccessToken
	case catalog.AuthClientCredentials:
		t, err := c.Signin.Mint(ctx, o, renew)
		if err != nil {
			call.upstream(err)
			return nil, err
		}
		token = t
	case catalog.AuthToken:
		gitInject := o.Connector.Git != nil && o.Connector.Git.Inject != nil
		if address != AddressGit || !gitInject {
			header, format := o.Meta.Header, o.Meta.Format
			if header == "" {
				header, format = catalog.DefaultInjectHeader, catalog.DefaultInjectFormat
			}
			return []dial.Secret{{Value: o.Secrets.Value, Header: header, Format: format, Hosts: hosts}}, nil
		}
		token = o.Secrets.Value
	default:
		return nil, apierr.Internal(errors.New("carry: a connection of an unknown auth"))
	}
	if address == AddressGit {
		if in := o.Connector.GitInjectOrDefault(); in.Scheme == catalog.GitBasic {
			basic := base64.StdEncoding.EncodeToString([]byte(in.Username + ":" + token))
			return []dial.Secret{{Value: basic, Header: "Authorization", Format: "Basic {value}", Hosts: hosts}}, nil
		}
	}
	return []dial.Secret{{Value: token, Header: "Authorization", Format: "Bearer {value}", Hosts: hosts}}, nil
}

// refused handles a 401 from the connector (specs/008-carrying-a-call.md,
// specs/014-http-forwarding.md). A key moves its connection at once; an
// oauth credential is refreshed and a client's token minted anew, and a
// request with no body is sent once more with it, while one with a body is
// answered the 401 as it came. It answers the credential to send again,
// whether to mint anew, or pass for the 401 to be answered.
func (c *Carrier) refused(ctx context.Context, call *call, o signin.Opened, hasBody bool) (signin.Opened, bool, bool, error) {
	switch o.Connection.Auth {
	case catalog.AuthToken:
		call.outcome = OutcomeUpstreamRefused
		return o, false, false, signin.Refused(ctx, c.Store, o.Connection, store.ReasonCredentialRefused)
	case catalog.AuthClientCredentials:
		if hasBody {
			if _, err := c.Signin.Mint(ctx, o, true); err != nil {
				call.upstream(err)
				return o, false, false, err
			}
			return o, false, true, nil
		}
		return o, true, false, nil
	}
	if o.Secrets.RefreshToken == "" {
		call.outcome = OutcomeUpstreamRefused
		return o, false, false, signin.Refused(ctx, c.Store, o.Connection, store.ReasonRevoked)
	}
	next, err := c.Signin.Refresh(ctx, o)
	if err != nil {
		call.upstream(err)
		return o, false, false, err
	}
	return next, false, hasBody, nil
}

// scopeChallenge reads the scope of an insufficient_scope challenge.
var scopeChallenge = regexp.MustCompile(`scope="([^"]*)"`)

// insufficientScope reads a challenge of RFC 6750, section 3.1: the scopes a
// connector asks for, and whether it is that challenge.
func insufficientScope(challenges []string) ([]string, bool) {
	for _, ch := range challenges {
		if !strings.Contains(ch, `error="insufficient_scope"`) {
			continue
		}
		scopes := []string{}
		if m := scopeChallenge.FindStringSubmatch(ch); m != nil {
			scopes = strings.Fields(m[1])
		}
		return scopes, true
	}
	return nil, false
}

// failed is the error of a request the dialer did not carry: a caller that
// went away, a body past its bound, a timeout, or a refusal of the dialer.
func (c *Carrier) failed(r *http.Request, call *call, body *bounded, err error) error {
	switch {
	case body != nil && body.over.Load():
		call.outcome = OutcomeDenied
		return apierr.Fail(apierr.CodeRequestTooLarge, "max_forward_bytes="+strconv.FormatInt(c.MaxForwardBytes, 10))
	case r.Context().Err() != nil || errors.Is(err, context.Canceled):
		call.outcome = OutcomeCanceled
		call.wrote = true // there is nobody to answer
		return err
	}
	name, _, ok := dial.ReasonOf(err)
	switch {
	case ok && name == dial.Timeout:
		call.outcome = OutcomeTimeout
		return apierr.Fail(apierr.CodeConnectorTimeout, name)
	case ok:
		call.outcome = OutcomeUpstreamError
		return apierr.Fail(apierr.CodeConnectorUnavailable, name)
	}
	return apierr.Internal(err)
}

// stream writes the answer as it is read, each read flushed at once, and
// ends a body that is idle past its bound.
func (c *Carrier) stream(w http.ResponseWriter, r *http.Request, call *call, resp *http.Response, cancel context.CancelFunc) error {
	call.Status = resp.StatusCode
	call.wrote = true
	w.WriteHeader(resp.StatusCode)
	rc := http.NewResponseController(w)
	if err := rc.Flush(); err != nil && !errors.Is(err, http.ErrNotSupported) {
		call.outcome = OutcomeCanceled
		return nil
	}
	var idle atomic.Bool
	timer := time.AfterFunc(c.IdleTimeout, func() { idle.Store(true); cancel() })
	defer timer.Stop()
	buf := make([]byte, 32<<10)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			timer.Reset(c.IdleTimeout)
			if _, werr := w.Write(buf[:n]); werr != nil {
				call.outcome = OutcomeCanceled
				return nil
			}
			call.BytesOut += int64(n)
			if ferr := rc.Flush(); ferr != nil && !errors.Is(ferr, http.ErrNotSupported) {
				call.outcome = OutcomeCanceled
				return nil
			}
		}
		// A cancelled read can end as the end of the body, so the two
		// cancellations are asked first: the idle bound's, and the caller's
		// going away. A caller that waits for the answer closes only after
		// this handler has returned, so a body that truly ended is still ok.
		switch {
		case err == nil:
			continue
		case idle.Load():
			call.outcome = OutcomeTimeout
		case r.Context().Err() != nil:
			call.outcome = OutcomeCanceled
		case errors.Is(err, io.EOF):
			call.outcome = OutcomeOK
		default:
			call.outcome = OutcomeUpstreamError
		}
		return nil
	}
}

// bounded is a request body that ends with an error past its bound, so a
// body over PONS_MAX_FORWARD_BYTES is never sent whole.
type bounded struct {
	r    io.Reader
	left int64
	read int64
	over atomic.Bool
}

// errTooLarge ends a body past its bound.
var errTooLarge = errors.New("carry: the body is over its bound")

func (b *bounded) Read(p []byte) (int, error) {
	if b.left <= 0 {
		// One byte more is read to tell a body that ends at the bound from
		// one that runs past it.
		var one [1]byte
		n, err := b.r.Read(one[:])
		if n > 0 {
			b.over.Store(true)
			return 0, errTooLarge
		}
		return 0, err
	}
	if int64(len(p)) > b.left {
		p = p[:b.left]
	}
	n, err := b.r.Read(p)
	b.left -= int64(n)
	b.read += int64(n)
	return n, err
}

// closeBody closes an answer's body that is read no more. A failure to
// close it changes nothing: the answer is already decided.
func closeBody(resp *http.Response) {
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
}
