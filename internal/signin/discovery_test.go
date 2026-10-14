// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package signin

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"latere.ai/x/pons/catalog"
	"latere.ai/x/pons/internal/apierr"
	"latere.ai/x/pons/internal/dial"
	"latere.ai/x/pons/internal/store"
	"latere.ai/x/pons/test/stubs"
)

// The paths a test's stub API was asked for, in order.
func (r *rig) apiPaths() []string {
	var out []string
	for _, q := range r.api.Requests() {
		out = append(out, q.Path)
	}
	return out
}

// Discovery takes resource_metadata from the challenge, else the two
// well-known addresses in order, and refuses a document about another
// resource.
func TestProtectedResourceDiscovery(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.api.Protect([]string{"repo", "user"}, r.auth.Issuer())
	p, err := r.s.Discover(ctx, r.conns["found"], nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.Issuer != r.auth.Issuer() || p.Resource != r.api.URL() || p.TokenEndpoint != r.auth.TokenURL() {
		t.Fatalf("the plan %+v", p)
	}
	if got := r.apiPaths(); !slices.Equal(got, []string{"/", "/.well-known/oauth-protected-resource"}) {
		t.Fatalf("asked %v", got)
	}
	// With no challenge, the well-known address with the url's path, then
	// at the root.
	found := r.conns["found"]
	found.URL = r.api.URL() + "/v3"
	r.conns["found"] = found
	before := len(r.api.Requests())
	r.api.Protect(nil)
	if _, err := r.s.Discover(ctx, found, nil); apierr.Classify(err).Reason != "no_resource_metadata" {
		t.Fatalf("no metadata anywhere: %v", err)
	}
	if got := r.apiPaths()[before:]; !slices.Equal(got, []string{"/v3", "/.well-known/oauth-protected-resource/v3", "/.well-known/oauth-protected-resource"}) {
		t.Fatalf("asked %v", got)
	}
	r.api.Protect([]string{"repo"}, r.auth.Issuer())
	if _, err := r.s.Discover(ctx, found, nil); err != nil {
		t.Fatalf("a resource whose path is a prefix: %v", err)
	}
	// A document about another resource is refused.
	other := found
	other.URL = strings.Replace(r.api.URL(), "api.example.com", "other.example.com", 1)
	if _, err := r.s.Discover(ctx, other, nil); err == nil {
		t.Fatal("a document about another resource")
	}
	for resource, ok := range map[string]bool{
		"https://api.example.com":      true,
		"https://api.example.com/v3":   true,
		"https://api.example.com/v":    false,
		"https://api.example.com/v3/x": false,
		"http://api.example.com/v3":    false,
		"https://api.example.com:8/v3": false,
		"%zz":                          false,
	} {
		if sameResource(resource, &url.URL{Scheme: "https", Host: "api.example.com", Path: "/v3/repos"}) != ok {
			t.Errorf("%s", resource)
		}
	}
	// An authorization server the document names that is not https.
	r.api.Protect([]string{"repo"}, "http://auth.example.com")
	if _, err := r.s.Discover(ctx, r.conns["found"], nil); apierr.Classify(err).Reason != "authorization_servers" {
		t.Fatalf("an http authorization server: %v", err)
	}
	// A connector that cannot be reached.
	gone := r.conns["found"]
	gone.URL = "https://nothing.example.org"
	if _, err := r.s.Discover(ctx, gone, nil); apierr.Classify(err).Code != apierr.CodeConnectorUnreachable {
		t.Fatalf("an unreachable connector: %v", err)
	}
}

// Authorization server metadata is fetched in priority order for an issuer
// with and without a path, and a different issuer, an http endpoint or no
// S256 is sign_in_unsupported; an endpoint inside is unreachable.
func TestAuthorizationServerMetadata(t *testing.T) {
	ctx := context.Background()
	for _, path := range []string{"", "/tenant1"} {
		for _, at := range []stubs.MetadataAt{stubs.MetadataOAuth, stubs.MetadataOIDCInserted, stubs.MetadataOIDCAppended} {
			if path == "" && at == stubs.MetadataOIDCAppended {
				continue
			}
			var opts []stubs.AuthOption
			if path != "" {
				opts = append(opts, stubs.WithIssuerPath(path))
			}
			r := newRig(t, opts...)
			r.auth.Set(func(sw *stubs.AuthSwitches) { sw.MetadataAt = at })
			p, err := r.s.Discover(ctx, r.conns["issued"], nil)
			if err != nil || p.Issuer != r.auth.Issuer() || !p.IssParameterSupported {
				t.Fatalf("%q at %d: %+v %v", path, at, p, err)
			}
		}
	}
	addresses, err := metadataAddresses("https://auth.example.com/tenant1/")
	if err != nil || !slices.Equal(addresses, []string{
		"https://auth.example.com/.well-known/oauth-authorization-server/tenant1",
		"https://auth.example.com/.well-known/openid-configuration/tenant1",
		"https://auth.example.com/tenant1/.well-known/openid-configuration",
	}) {
		t.Fatalf("%v %v", addresses, err)
	}
	if _, err := metadataAddresses("::"); err == nil {
		t.Fatal("an issuer that is no URL")
	}
	r := newRig(t)
	for name, change := range map[string]func(*stubs.AuthSwitches){
		"issuer_mismatch": func(sw *stubs.AuthSwitches) { sw.WrongIssuer = true },
		"no_s256":         func(sw *stubs.AuthSwitches) { sw.NoS256 = true },
	} {
		r.auth.Set(func(sw *stubs.AuthSwitches) {
			*sw = stubs.AuthSwitches{IssSupported: true, TokenType: "Bearer", ExpiresIn: 3600, TokenPrefix: "stub-"}
		})
		r.auth.Set(change)
		_, err := r.s.Discover(ctx, r.conns["issued"], nil)
		if e := apierr.Classify(err); e.Code != apierr.CodeSignInUnsupported || e.Reason != name {
			t.Errorf("%s: %v", name, err)
		}
	}
	r.auth.Set(func(sw *stubs.AuthSwitches) {
		*sw = stubs.AuthSwitches{IssSupported: true, TokenType: "Bearer", InsideEndpoint: true}
	})
	if _, err := r.s.Discover(ctx, r.conns["issued"], nil); apierr.Classify(err).Code != apierr.CodeConnectorUnreachable {
		t.Fatalf("an endpoint inside: %v", err)
	}
	for raw, want := range map[string]string{
		"http://auth.example.com/t": "scheme_not_https", "https://u@auth.example.com/t": "scheme_not_https",
		"https://10.0.0.1/t": "host_not_a_name", "https://auth.example.com/t": "",
	} {
		if got := checkEndpoint(raw); got != want {
			t.Errorf("%s: %q", raw, got)
		}
	}
	issued := r.conns["issued"]
	issued.Auth.Issuer = "http://auth.example.com"
	if _, err := r.s.Discover(ctx, issued, nil); apierr.Classify(err).Code != apierr.CodeConnectorUnreachable {
		t.Fatalf("an issuer that is not https: %v", err)
	}
}

// Pons identifies itself in order: the catalog's client, a client metadata
// document, dynamic registration, else sign_in_unsupported; a catalog
// client is never used at another issuer, and an added connector is named
// by its own document alone.
func TestClientSelection(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	r.api.Protect([]string{"repo"}, r.auth.Issuer())
	if p, err := r.s.Discover(ctx, r.conns["named"], nil); err != nil || p.ClientID != "pons-client" {
		t.Fatalf("the catalog's client: %+v %v", p, err)
	}
	other := r.conns["issued"]
	other.Auth.Issuer = "https://elsewhere.example.com"
	if _, err := r.s.planAt(ctx, other, metadataDocument{Issuer: r.auth.Issuer()}); apierr.Classify(err).Reason != "client_at_another_issuer" {
		t.Fatalf("a client at another issuer: %v", err)
	}
	r.auth.Set(func(sw *stubs.AuthSwitches) { sw.CIMD = true })
	if p, err := r.s.Discover(ctx, r.conns["found"], nil); err != nil || p.ClientID != "https://pons.example.com/v1/client" {
		t.Fatalf("a client metadata document: %+v %v", p, err)
	}
	added := r.conns["found"]
	added.Ref, added.AddedURL = "ctr_01", added.URL
	if p, err := r.s.Discover(ctx, added, nil); err != nil || p.ClientID != "https://pons.example.com/v1/client/ctr_01" {
		t.Fatalf("an added connector's own document: %+v %v", p, err)
	}
	r.auth.Set(func(sw *stubs.AuthSwitches) { sw.CIMD = false })
	if _, err := r.s.Discover(ctx, added, nil); apierr.Classify(err).Reason != "no_client" {
		t.Fatalf("an added connector is never registered: %v", err)
	}
	if p, err := r.s.Discover(ctx, r.conns["found"], nil); err != nil || !strings.HasPrefix(p.ClientID, "reg-") {
		t.Fatalf("a registration: %+v %v", p, err)
	}
	r.st.Registrations().Delete(ctx, r.auth.Issuer(), r.s.RedirectURI())
	r.auth.Set(func(sw *stubs.AuthSwitches) { sw.NoRegistration = true })
	if _, err := r.s.Discover(ctx, r.conns["found"], nil); apierr.Classify(err).Reason != "no_client" {
		t.Fatalf("no way to identify: %v", err)
	}
	// A client metadata document needs an https public address.
	r.auth.Set(func(sw *stubs.AuthSwitches) { sw.CIMD = true })
	r.s.PublicURL = "http://127.0.0.1:8080"
	if _, err := r.s.Discover(ctx, r.conns["found"], nil); apierr.Classify(err).Reason != "no_client" {
		t.Fatalf("a document on plain http: %v", err)
	}
	doc := r.s.ClientDocument("ctr_01", "Team wiki")
	if doc.ClientName != "Pons for Team wiki" || doc.TokenEndpointAuthMethod != "none" || len(doc.RedirectURIs) != 1 {
		t.Fatalf("a document %+v", doc)
	}
}

// A registration is kept per issuer and reused; its secret is sealed; one
// the server refuses is deleted and registered again.
func TestRegistrationIsKeptPerIssuer(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	r.api.Protect([]string{"repo"}, r.auth.Issuer())
	r.auth.Set(func(sw *stubs.AuthSwitches) { sw.IssueSecret = true })
	first, err := r.s.Discover(ctx, r.conns["found"], nil)
	if err != nil {
		t.Fatal(err)
	}
	again, err := r.s.Discover(ctx, r.conns["found"], nil)
	if err != nil || again.ClientID != first.ClientID || r.auth.Registrations() != 1 {
		t.Fatalf("a second sign-in registered again: %+v %v %d", again, err, r.auth.Registrations())
	}
	reg, err := r.st.Registrations().Get(ctx, r.auth.Issuer(), r.s.RedirectURI())
	if err != nil || reg.Secret.Zero() {
		t.Fatalf("the registration %+v %v", reg, err)
	}
	body := registered(r)
	for _, want := range []string{`"application_type":"web"`, `"redirect_uris":["https://pons.example.com/v1/callback"]`, `"token_endpoint_auth_method":"none"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("registered %s", body)
		}
	}
	// A sign-in through it: the code exchange authenticates with the
	// registered secret.
	c := r.signIn("alice", "found")
	if c.State != store.StateConnected {
		t.Fatalf("%+v", c)
	}
	// A server that refuses the client: the registration is forgotten.
	_, address, _ := r.pending("bob", "found", nil)
	q := browser(t, address)
	r.auth.Set(func(sw *stubs.AuthSwitches) { sw.RefuseClient = true })
	if dest, err := r.s.Callback(ctx, q); err != nil || !strings.Contains(dest, "error=sign_in_failed") {
		t.Fatalf("a refused client: %s %v", dest, err)
	}
	if _, err := r.st.Registrations().Get(ctx, r.auth.Issuer(), r.s.RedirectURI()); err == nil {
		t.Fatal("a refused registration was kept")
	}
	r.auth.Set(func(sw *stubs.AuthSwitches) { sw.RefuseClient = false })
	if _, err := r.s.Discover(ctx, r.conns["found"], nil); err != nil || r.auth.Registrations() != 2 {
		t.Fatalf("registered again: %v %d", err, r.auth.Registrations())
	}
	// On loopback Pons registers as a native client.
	r.st.Registrations().Delete(ctx, r.auth.Issuer(), r.s.RedirectURI())
	r.s.PublicURL = "http://127.0.0.1:8080"
	if _, err := r.s.Discover(ctx, r.conns["found"], nil); err != nil {
		t.Fatal(err)
	}
	if body := registered(r); !strings.Contains(body, `"application_type":"native"`) {
		t.Fatalf("on loopback: %s", body)
	}
}

// The scopes asked are the base, the entry's, else the challenge's, else
// the document's, with the scopes the request names and offline_access
// when the server lists it.
func TestScopeSelection(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	r.api.Protect([]string{"repo", "user"}, r.auth.Issuer())
	p, err := r.s.Discover(ctx, r.conns["found"], []string{"gist", "repo"})
	if err != nil || !slices.Equal(p.Scopes, []string{"repo", "user", "gist", "offline_access"}) {
		t.Fatalf("the challenge's: %v %v", p.Scopes, err)
	}
	if p, err := r.s.Discover(ctx, r.conns["issued"], nil); err != nil || !slices.Equal(p.Scopes, []string{"read", "offline_access"}) {
		t.Fatalf("the entry's: %v %v", p.Scopes, err)
	}
	r.auth.Set(func(sw *stubs.AuthSwitches) { sw.Scopes = []string{"read"} })
	if p, err := r.s.Discover(ctx, r.conns["issued"], []string{"write"}); err != nil || !slices.Equal(p.Scopes, []string{"read", "write"}) {
		t.Fatalf("no offline_access listed: %v %v", p.Scopes, err)
	}
	if p, err := r.s.Discover(ctx, r.conns["code"], []string{"repo"}); err != nil || !slices.Equal(p.Scopes, []string{"repo"}) || p.Resource != "" {
		t.Fatalf("an entry that names its endpoints: %+v %v", p, err)
	}
	if got := union(nil, nil); len(got) != 0 {
		t.Fatalf("%v", got)
	}
}

// registered is the body of the stub's last registration.
func registered(r *rig) string {
	body := ""
	for _, q := range r.auth.Requests() {
		if q.Path == "/register" {
			body = string(q.Body)
		}
	}
	return body
}

// Discovery of a connector of kind mcp begins with the probe's tools/list,
// with no credential: a POST of the current revision whose challenge names
// the resource metadata, and the plan is found through it.
func TestAnMCPConnectorIsFoundThroughItsProbe(t *testing.T) {
	r := newRig(t)
	stub := stubs.NewConnector(t)
	stub.Set(func(sw *stubs.ConnectorSwitches) {
		sw.Servers, sw.Scopes = []string{r.auth.Issuer()}, []string{"notes"}
	})
	r.s.Dial = dial.New(dial.Options{Resolver: stubs.Resolver(), Roots: stubs.Roots(), Permit: stubs.Permit(r.auth.Port(), stub.Port())})
	conn := Connector{
		Name: "notes", Title: "Notes", Kind: catalog.KindMCP, URL: stub.URL(),
		Auth: catalog.Auth{Type: catalog.AuthOAuth, Discovery: catalog.DiscoveryResource, Resource: new(true)}, Ref: "notes"}
	p, err := r.s.Discover(t.Context(), conn, nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.Issuer != r.auth.Issuer() || p.Resource != stub.URL() || !slices.Contains(p.Scopes, "notes") {
		t.Fatalf("the plan %+v", p)
	}
	got := stub.Requests()
	if len(got) != 2 || got[0].Method != http.MethodPost || got[0].RPC != "tools/list" || got[0].Credential != "" ||
		got[0].Header.Get("MCP-Protocol-Version") != "2026-07-28" || got[0].Header.Get("Mcp-Method") != "tools/list" {
		t.Fatalf("the first request %+v", got)
	}
}
