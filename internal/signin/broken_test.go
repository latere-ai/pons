// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package signin

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"latere.ai/x/pons/catalog"
	"latere.ai/x/pons/internal/apierr"
	"latere.ai/x/pons/internal/store"
	"latere.ai/x/pons/test/stubs"
)

// serve starts a server of the test's own under a name of the stubs'
// domain, on the stubs' authority, and points the rig's dialer at it.
func (r *rig) serve(name string, h http.HandlerFunc) string {
	r.t.Helper()
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{stubs.Certificate(name, "127.0.0.1")}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	r.t.Cleanup(srv.Close)
	port, err := strconv.Atoi(srv.URL[strings.LastIndexByte(srv.URL, ':')+1:])
	if err != nil {
		r.t.Fatal(err)
	}
	r.s.Dial = r.dialTo(port)
	return "https://" + name + ":" + strconv.Itoa(port)
}

// Documents that are read and cannot be used are sign_in_unsupported,
// naming the step; a server that answers nothing useful is the next
// address or no document.
func TestDocumentsThatCannotBeUsed(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	var base string
	answers := map[string]string{}
	base = r.serve("broken.example.com", func(w http.ResponseWriter, req *http.Request) {
		body, ok := answers[req.URL.Path]
		if !ok {
			http.NotFound(w, req)
			return
		}
		if body == "401" {
			w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+base+`/meta", scope="a b"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(strings.ReplaceAll(body, "BASE", base)))
	})
	found := r.conns["found"]
	found.URL = base
	found.Hosts = []string{"broken.example.com"}
	issued := r.conns["issued"]
	issued.Auth.Issuer = base
	cases := []struct {
		name    string
		answers map[string]string
		conn    Connector
		reason  string
	}{
		{"resource metadata that is not JSON", map[string]string{"/": "401", "/meta": "{"}, found, "resource_metadata"},
		{"an authorization server that is not https", map[string]string{"/": "401", "/meta": `{"resource":"BASE","authorization_servers":["http://x.example.com"]}`}, found, "scheme_not_https"},
		{"an authorization server at an address", map[string]string{"/": "401", "/meta": `{"resource":"BASE","authorization_servers":["https://127.0.0.1"]}`}, found, "host_not_a_name"},
		{"no authorization server", map[string]string{"/": "401", "/meta": `{"resource":"BASE","authorization_servers":[]}`}, found, "no_authorization_server"},
		{"metadata that is not JSON", map[string]string{"/.well-known/oauth-authorization-server": "{"}, issued, "metadata"},
		{"metadata with no endpoints", map[string]string{"/.well-known/oauth-authorization-server": `{"issuer":"BASE"}`}, issued, "endpoints"},
		{"metadata nowhere", map[string]string{}, issued, "no_metadata"},
		{"a registration that is refused", map[string]string{
			"/": "401", "/meta": `{"resource":"BASE","authorization_servers":["BASE"]}`,
			"/.well-known/oauth-authorization-server": `{"issuer":"BASE","authorization_endpoint":"BASE/a","token_endpoint":"BASE/t","registration_endpoint":"BASE/r","code_challenge_methods_supported":["S256"]}`,
		}, found, "registration"},
		{"an endpoint inside", map[string]string{
			"/.well-known/oauth-authorization-server": `{"issuer":"BASE","authorization_endpoint":"https://10.0.0.1/a","token_endpoint":"BASE/t","code_challenge_methods_supported":["S256"]}`,
		}, issued, "host_not_a_name"},
	}
	for _, tc := range cases {
		answers = tc.answers
		_, err := r.s.Discover(ctx, tc.conn, nil)
		if e := apierr.Classify(err); e.Reason != tc.reason {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
	// The challenge names the scopes the base takes.
	answers = map[string]string{
		"/": "401", "/meta": `{"resource":"BASE","authorization_servers":["` + r.auth.Issuer() + `"]}`,
	}
	r.s.Dial = r.dialTo(r.portOf(base))
	if p, err := r.s.Discover(ctx, found, nil); err != nil || strings.Join(p.Scopes, " ") != "a b offline_access" {
		t.Fatalf("the challenge's scopes: %+v %v", p, err)
	}
	// A url that does not parse.
	bad := found
	bad.URL = "::"
	if _, err := r.s.Discover(ctx, bad, nil); err == nil {
		t.Fatal("a connector url that is no URL")
	}
	if _, _, err := r.s.challenge(ctx, bad); err == nil {
		t.Fatal("a challenge of no URL")
	}
	// A registration whose secret cannot be sealed.
	empty, err := store.NewSealer()
	if err != nil {
		t.Fatal(err)
	}
	r.s.Sealer = empty
	r.s.Dial = r.dialTo()
	r.api.Protect(nil, r.auth.Issuer())
	r.auth.Set(func(sw *stubs.AuthSwitches) { sw.IssueSecret = true })
	if err := r.st.Registrations().Delete(ctx, r.auth.Issuer(), r.s.RedirectURI()); err != nil {
		t.Fatal(err)
	}
	if _, err := r.s.Discover(ctx, r.conns["found"], nil); apierr.Classify(err).Code != apierr.CodeSealingUnavailable {
		t.Fatalf("a secret with no key to seal it: %v", err)
	}
	_ = catalog.KindHTTP
}

// portOf is the port of an address.
func (r *rig) portOf(base string) int {
	p, err := strconv.Atoi(base[strings.LastIndexByte(base, ':')+1:])
	if err != nil {
		r.t.Fatal(err)
	}
	return p
}
