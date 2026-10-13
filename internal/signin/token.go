// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package signin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"latere.ai/x/pons/catalog"
	"latere.ai/x/pons/internal/dial"
)

// maxTokenAnswer bounds what a token endpoint's answer may hold.
const maxTokenAnswer = 1 << 20

// answer is what a token endpoint answered: new tokens.
type answer struct {
	AccessToken      string
	TokenType        string
	ExpiresIn        int64 // seconds; 0 when the answer gave none
	RefreshToken     string
	RefreshExpiresIn int64 // seconds; 0 when the answer gave none
	Scope            string
}

// tokenError is an answer that is an error: the OAuth error code, with the
// words some services use in its place read as the standard's
// (specs/013-github-connector.md). Its text is the code alone.
type tokenError struct{ Code string }

func (e *tokenError) Error() string { return "signin: the token endpoint answered " + e.Code }

// The OAuth error codes the sign-in branches on.
const (
	errInvalidGrant  = "invalid_grant"
	errInvalidClient = "invalid_client"
)

// standard reads a service's own word for an error as the standard's: a
// bad refresh token and a bad code are a grant the server refuses, and bad
// client credentials a client it refuses.
func standard(code string) string {
	switch code {
	case "bad_refresh_token", "bad_verification_code":
		return errInvalidGrant
	case "incorrect_client_credentials":
		return errInvalidClient
	}
	return code
}

// isCode reports whether err is a token endpoint's error of the code.
func isCode(err error, code string) bool {
	var te *tokenError
	return errors.As(err, &te) && te.Code == code
}

// client is how Pons identifies itself at a token endpoint: a client with a
// secret authenticates with HTTP Basic, and one without sends client_id in
// the body.
type client struct {
	ID     string
	Secret string
}

// hostOf is the matcher of one URL's host, what a secret bound to that
// endpoint may be sent to.
func hostOf(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" {
		return "", errors.New("signin: an endpoint that is not a URL")
	}
	return catalog.Normalize(u.Hostname()), nil
}

// post sends one form to an endpoint the sign-in recorded, with the secrets
// written in by the dialer as form members, and the client by Basic or in
// the body. It asks for JSON, follows no redirect, and ends within 15
// seconds; its answer's body is read whole, up to 1 MiB.
func (s *Signin) post(ctx context.Context, endpoint string, ports []int, form url.Values, secrets map[string]string, c client) (int, []byte, error) {
	host, err := hostOf(endpoint)
	if err != nil {
		return 0, nil, err
	}
	bound := catalog.Matcher([]string{host})
	var place []dial.Secret
	for field, value := range secrets {
		place = append(place, dial.Secret{Value: value, FormField: field, Hosts: bound})
	}
	body := url.Values{}
	maps.Copy(body, form)
	switch {
	case c.Secret != "":
		basic := base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(c.ID) + ":" + url.QueryEscape(c.Secret)))
		place = append(place, dial.Secret{Value: basic, Header: "Authorization", Format: "Basic {value}", Hosts: bound})
	case c.ID != "":
		body.Set("client_id", c.ID)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(body.Encode()))
	if err != nil {
		return 0, nil, errors.New("signin: an endpoint that is not a URL")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := s.Dial.Do(ctx, dial.Request{HTTP: req, Secrets: place, Ports: ports, Timeout: tokenTimeout, MaxBody: maxTokenAnswer})
	if err != nil {
		return 0, nil, err
	}
	raw, err := io.ReadAll(resp.Body)
	if cerr := resp.Body.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, raw, nil
}

// token asks a token endpoint for tokens and reads its answer. An answer
// whose body has an error member is an error whatever its status, since
// some services answer an error with 200; one in form encoding is read as
// well as one in JSON.
func (s *Signin) token(ctx context.Context, endpoint string, ports []int, form url.Values, secrets map[string]string, c client) (answer, error) {
	status, raw, err := s.post(ctx, endpoint, ports, form, secrets, c)
	if err != nil {
		return answer{}, err
	}
	m, err := members(raw)
	if err != nil {
		return answer{}, &tokenError{Code: "unreadable"}
	}
	if code := text(m["error"]); code != "" {
		return answer{}, &tokenError{Code: standard(code)}
	}
	if status < 200 || status > 299 {
		return answer{}, &tokenError{Code: "status_" + strconv.Itoa(status)}
	}
	a := answer{
		AccessToken: text(m["access_token"]), TokenType: text(m["token_type"]),
		ExpiresIn: number(m["expires_in"]), RefreshToken: text(m["refresh_token"]),
		RefreshExpiresIn: number(m["refresh_token_expires_in"]), Scope: text(m["scope"]),
	}
	if a.AccessToken == "" {
		return answer{}, &tokenError{Code: "no_access_token"}
	}
	if !strings.EqualFold(a.TokenType, "bearer") {
		return answer{}, &tokenError{Code: "token_type"}
	}
	return a, nil
}

// members reads an answer as a JSON object, or as form encoding when it is
// not JSON.
func members(raw []byte) (map[string]any, error) {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err == nil {
		return m, nil
	}
	values, err := url.ParseQuery(string(raw))
	if err != nil || len(values) == 0 {
		return nil, errors.New("signin: an answer that is neither JSON nor a form")
	}
	m = map[string]any{}
	for k := range values {
		m[k] = values.Get(k)
	}
	return m, nil
}

// text is a member that is a string, and "" otherwise.
func text(v any) string {
	s, _ := v.(string)
	return s
}

// number is a member that is a whole number of seconds, written as a JSON
// number or as text, and 0 otherwise.
func number(v any) int64 {
	switch n := v.(type) {
	case float64:
		if n > 0 {
			return int64(n)
		}
	case string:
		if i, err := strconv.ParseInt(n, 10, 64); err == nil && i > 0 {
			return i
		}
	}
	return 0
}

// reasonOf names what failed at an endpoint in one word: a refusal of the
// dialer by its rule's name, an error the endpoint answered by its code.
func reasonOf(err error) string {
	if name, _, ok := dial.ReasonOf(err); ok {
		return name
	}
	var te *tokenError
	if errors.As(err, &te) {
		return te.Code
	}
	return "failed"
}
