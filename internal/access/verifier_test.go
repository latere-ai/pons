// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package access_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"latere.ai/x/pkg/authkit"
	"latere.ai/x/pkg/authkit/conformance"
	"latere.ai/x/pkg/authkit/issuertest"
	"latere.ai/x/pkg/authz"

	"latere.ai/x/pons/internal/access"
	"latere.ai/x/pons/internal/config"
	"latere.ai/x/pons/internal/dial"
	"latere.ai/x/pons/test/stubs"
)

// audience is the audience the gate's identity block declares, and the
// default of PONS_OIDC_AUDIENCE.
const audience = "pons"

// operator is the operator client, trusting the stubs' authority.
func operator(t testing.TB) *http.Client {
	t.Helper()
	roots, err := stubs.Roots()
	if err != nil {
		t.Fatal(err)
	}
	return dial.Operator(dial.OperatorOptions{Roots: roots})
}

// verifying builds the verifier ponsd runs, over the issuers.
func verifying(t testing.TB, audiences []string, issuers ...string) *access.Verifier {
	t.Helper()
	v, err := access.NewVerifier(access.VerifierOptions{Issuers: issuers, Audiences: audiences, HTTP: operator(t)})
	if err != nil {
		t.Fatalf("the verifier would not build: %v", err)
	}
	return v
}

// bearing is a request that carries the token as its bearer.
func bearing(t testing.TB, token string) *http.Request {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v1/connections", nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	return r
}

// The verifier passes the shared conformance suite, built as ponsd builds
// it.
func TestVerifierConformance(t *testing.T) {
	conformance.Run(t, conformance.Service{
		Audience: audience,
		New: func(tb testing.TB, issuerURL, _ string) authkit.Authenticator {
			tb.Helper()
			return verifying(tb, []string{audience}, issuerURL).Authenticator()
		},
	})
}

// A verified token becomes a caller whose subject is <iss>|<sub> and whose
// claims are the token's, verbatim, and two issuers that agree on a sub are
// two subjects.
func TestAVerifiedTokenBecomesACaller(t *testing.T) {
	one, two := stubs.NewIssuer(t), stubs.NewIssuer(t)
	v := verifying(t, []string{audience}, one.URL()+"/", two.URL())
	if got := v.Issuers(); !slices.Equal(got, []string{one.URL(), two.URL()}) {
		t.Fatalf("issuers %v", got)
	}
	c, err := v.Authenticate(bearing(t, one.Token("alice", map[string]any{"tenant": "acme", "session": map[string]any{"id": "ses_1"}})))
	if err != nil {
		t.Fatal(err)
	}
	if c.Subject != one.URL()+"|alice" || c.Subject != authz.Subject(one.URL(), "alice") || c.Issuer != one.URL() || c.Sub != "alice" {
		t.Fatalf("caller %+v", c)
	}
	if c.Claims["tenant"] != "acme" || c.Claims["session"].(map[string]any)["id"] != "ses_1" {
		t.Fatalf("claims %v", c.Claims)
	}
	other, err := v.Verify(two.Token("alice", nil))
	if err != nil {
		t.Fatal(err)
	}
	if other.Subject == c.Subject {
		t.Fatal("two issuers that agree on a sub are one subject")
	}
}

// A token for another audience, of an unlisted issuer, expired or not yet
// valid past the skew, or with a bad signature is invalid_token with the
// reason, and the error never repeats the token.
func TestWhatTheVerifierRefuses(t *testing.T) {
	iss, other := stubs.NewIssuer(t), stubs.NewIssuer(t)
	v := verifying(t, []string{audience}, iss.URL())
	now := time.Now()
	good := iss.Token("alice", nil)
	at := strings.LastIndexByte(good, '.') + 1
	forged := good[:at] + map[bool]string{true: "A", false: "B"}[good[at] != 'A'] + good[at+1:]
	cases := []struct{ name, token, reason string }{
		{"another audience", iss.Mint(issuertest.Claims{Sub: "alice", Aud: issuertest.StringList{"other"}}), "audience"},
		{"expired past the skew", iss.Mint(issuertest.Claims{Sub: "alice", Exp: now.Add(-5 * time.Minute).Unix()}), "expired"},
		{"not valid yet past the skew", iss.Mint(issuertest.Claims{Sub: "alice", Nbf: now.Add(5 * time.Minute).Unix()}), "nbf"},
		{"an unlisted issuer", other.Token("alice", nil), "issuer"},
		{"a bad signature", forged, "signature"},
		{"not a token", "not-a-token", "malformed"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := v.Authenticate(bearing(t, c.token))
			var te *access.TokenError
			if !errors.As(err, &te) || te.Reason != c.reason || te.Retryable {
				t.Fatalf("got %v, want the reason %q", err, c.reason)
			}
			if strings.Contains(err.Error(), c.token) || te.Unwrap() == nil {
				t.Errorf("the error repeats the token or hides its cause: %v", err)
			}
		})
	}
	basic := bearing(t, "")
	basic.Header.Set("Authorization", "Basic YWxpY2U6c2VjcmV0")
	for _, r := range []*http.Request{bearing(t, ""), basic} {
		if _, err := v.Authenticate(r); !errors.Is(err, access.ErrMissingToken) {
			t.Errorf("no bearer: %v", err)
		}
	}
	// An issuer that does not answer is a refusal a caller may retry.
	roots, err := stubs.Roots()
	if err != nil {
		t.Fatal(err)
	}
	down, err := access.NewVerifier(access.VerifierOptions{
		Issuers: []string{iss.URL()}, Audiences: []string{audience},
		HTTP: dial.Operator(dial.OperatorOptions{Roots: roots, Timeout: 300 * time.Millisecond}),
	})
	if err != nil {
		t.Fatal(err)
	}
	iss.Hang()
	_, err = down.Verify(iss.Token("alice", nil))
	var te *access.TokenError
	iss.Resume()
	if !errors.As(err, &te) || te.Reason != "issuer_unavailable" || !te.Retryable {
		t.Fatalf("an issuer that does not answer: %v", err)
	}
}

// exp and nbf are read with 30 seconds of skew.
func TestTheSkewOnExpAndNbf(t *testing.T) {
	iss := stubs.NewIssuer(t)
	v := verifying(t, []string{audience}, iss.URL())
	now := time.Now()
	within := access.ClockSkew / 3
	for name, claims := range map[string]issuertest.Claims{
		"expired within the skew":       {Sub: "alice", Exp: now.Add(-within).Unix()},
		"not valid yet within the skew": {Sub: "alice", Nbf: now.Add(within).Unix()},
	} {
		if _, err := v.Verify(iss.Mint(claims)); err != nil {
			t.Errorf("%s: refused: %v", name, err)
		}
	}
}

func TestWarmReadsEachIssuersKeys(t *testing.T) {
	iss := stubs.NewIssuer(t)
	v := verifying(t, []string{audience}, iss.URL())
	if err := v.Warm(t.Context()); err != nil {
		t.Fatal(err)
	}
	gone := httptest.NewServer(http.NotFoundHandler())
	gone.Close()
	if err := verifying(t, []string{audience}, gone.URL).Warm(t.Context()); err == nil {
		t.Error("warming an issuer that does not answer reports nothing")
	}
}

// A server that lists no issuer, names no audience or has no client is
// refused, naming the variable.
func TestAVerifierNeedsAnIssuerAndAnAudience(t *testing.T) {
	for name, o := range map[string]access.VerifierOptions{
		"no issuer":         {Audiences: []string{audience}, HTTP: http.DefaultClient},
		"no audience":       {Issuers: []string{"https://issuer.example.com"}, HTTP: http.DefaultClient},
		"an empty audience": {Issuers: []string{"https://issuer.example.com"}, Audiences: []string{""}, HTTP: http.DefaultClient},
		"no client":         {Issuers: []string{"https://issuer.example.com"}, Audiences: []string{audience}},
	} {
		if _, err := access.NewVerifier(o); err == nil {
			t.Errorf("%s: built", name)
		}
	}
	if _, err := access.New(config.Settings{OIDCAudiences: []string{audience}}, access.Options{}); err == nil || !strings.Contains(err.Error(), "PONS_OIDC_ISSUERS") {
		t.Errorf("no issuer: %v", err)
	}
}
