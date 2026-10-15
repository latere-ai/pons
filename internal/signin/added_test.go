// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package signin

import (
	"context"
	"encoding/json"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"latere.ai/x/pons/catalog"
	"latere.ai/x/pons/internal/apierr"
	"latere.ai/x/pons/internal/store"
	"latere.ai/x/pons/test/stubs"
)

// added is a server the rig's tests add by its address: a stub connector
// that is a protected resource at the rig's authorization server, which the
// rig's dialer reaches.
func (r *rig) added() *stubs.Connector {
	r.t.Helper()
	server := stubs.NewConnector(r.t)
	server.Set(func(sw *stubs.ConnectorSwitches) { sw.Servers = []string{r.auth.Issuer()} })
	r.s.Dial = r.dialTo(server.Port())
	return server
}

// addedConnector is a connector added at the server's address, as the add
// stores it, with what the add found.
func (r *rig) addedConnector(server *stubs.Connector, ref string, way Way) Connector {
	c := Connector{
		Name: "wiki", Title: "Wiki", Kind: catalog.KindMCP, URL: server.URL(), Auth: catalog.Auth{Type: way.Type},
		Ref: ref, AddedURL: server.URL(), Found: way.Found,
	}
	r.conns[ref] = c
	return c
}

// withClient is a vouched-for connector's own client, its secret sealed to
// the connector and the token endpoint its add found.
func (r *rig) withClient(c Connector, id, secret string) Connector {
	r.t.Helper()
	sealed, err := r.sealer.Seal([]byte(secret), store.ConnectorClientBinding(c.Ref, c.Found.TokenEndpoint))
	if err != nil {
		r.t.Fatal(err)
	}
	c.Auth.Client, c.Auth.Issuer, c.ClientSecret = &catalog.Client{ID: id}, c.Found.Issuer, sealed
	r.conns[c.Ref] = c
	return c
}

// connect makes a pending connection of an added connector and starts its
// sign-in.
func (r *rig) connect(owner string, c Connector) (store.Connection, string, store.Flow) {
	r.t.Helper()
	row := store.Connection{
		ID: "con_" + owner + strings.Repeat("0", 26-len(owner)), Owner: subject(owner), Name: "wiki", Connector: c.Ref,
		Kind: catalog.KindMCP, Auth: catalog.AuthOAuth, State: store.StatePending, CreatedBy: subject(owner),
	}
	if err := r.st.Connections().Create(context.Background(), row, 0); err != nil {
		r.t.Fatal(err)
	}
	plan, err := r.s.Discover(context.Background(), c, nil)
	if err != nil {
		r.t.Fatalf("discover %s: %v", c.Ref, err)
	}
	address, f, err := r.s.Begin(row, plan, "https://app.example.com/back")
	if err != nil {
		r.t.Fatal(err)
	}
	if err := r.st.Flows().Put(context.Background(), f); err != nil {
		r.t.Fatal(err)
	}
	return row, address, f
}

// ask is the add's question to the server, which must answer oauth.
func (r *rig) ask(server *stubs.Connector, own bool) Way {
	r.t.Helper()
	way, err := r.s.Ask(context.Background(), Connector{Kind: catalog.KindMCP, URL: server.URL(), AddedURL: server.URL()}, own)
	if err != nil || way.Type != catalog.AuthOAuth {
		r.t.Fatalf("the add's question: %+v %v", way, err)
	}
	return way
}

// An added oauth connector identifies itself by a registered client of a
// vouched-for connector, else its client metadata document, else a
// registration the installation keeps per issuer and reuses, else not at
// all; a registered client's secret is sent to the token endpoint its add
// found and no other.
func TestAnAddedConnectorIdentifiesItself(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	server := r.added()
	r.auth.Set(func(sw *stubs.AuthSwitches) { sw.CIMD = true })

	// A registered client comes first, whatever else the server offers.
	way := r.ask(server, true)
	if way.Found != (Found{Issuer: r.auth.Issuer(), TokenEndpoint: r.auth.TokenURL(), Iss: true, Client: ClientOwn}) {
		t.Fatalf("the add found %+v", way.Found)
	}
	const secret = "the-wiki-client-secret"
	r.auth.AddClient("wiki-client", secret)
	own := r.withClient(r.addedConnector(server, "ctr_own", way), "wiki-client", secret)
	c, address, f := r.connect("alice", own)
	if f.ClientID != "wiki-client" || f.RedirectURI != r.s.RedirectURI() {
		t.Fatalf("a registered client's flow %+v", f)
	}
	dest, err := r.s.Callback(ctx, browser(t, address))
	if err != nil || !strings.Contains(dest, "code=") {
		t.Fatalf("a registered client's sign-in: %s %v", dest, err)
	}
	var exchange stubs.AuthRequest
	for _, q := range r.auth.Requests() {
		if q.Path == "/token" {
			exchange = q
		}
	}
	if exchange.ClientID != "wiki-client" || !exchange.Basic {
		t.Fatalf("the code was exchanged as %+v", exchange)
	}
	u, err := url.Parse(dest)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.s.Confirm(ctx, r.state(c), u.Query().Get("code")); err != nil {
		t.Fatal(err)
	}
	// The secret opens for its own connector and token endpoint alone.
	copied := own
	copied.Ref = "ctr_copied"
	if _, err := r.s.clientAt(ctx, copied, r.auth.Issuer(), "wiki-client", r.auth.TokenURL()); apierr.Classify(err).Code != apierr.CodeSealingUnavailable {
		t.Fatalf("a secret copied to another connector: %v", err)
	}
	if _, err := r.s.clientAt(ctx, own, r.auth.Issuer(), "wiki-client", "https://elsewhere.example.net/token"); apierr.Classify(err).Code != apierr.CodeSealingUnavailable {
		t.Fatalf("a secret asked for at another token endpoint: %v", err)
	}
	moved := own
	moved.Found.TokenEndpoint = "https://elsewhere.example.net/token"
	if _, err := r.s.Discover(ctx, moved, nil); apierr.Classify(err).Reason != "token_endpoint_changed" {
		t.Fatalf("a server whose token endpoint moved: %v", err)
	}
	public := r.addedConnector(server, "ctr_public", way)
	public.Auth.Client, public.Auth.Issuer = &catalog.Client{ID: "public-client"}, r.auth.Issuer()
	if got, err := r.s.clientAt(ctx, public, r.auth.Issuer(), "public-client", r.auth.TokenURL()); err != nil || got.Secret != "" {
		t.Fatalf("a registered client with no secret: %+v %v", got, err)
	}

	// Then the connector's own client metadata document.
	way = r.ask(server, false)
	if way.Found.Client != ClientByDocument {
		t.Fatalf("the add found %+v", way.Found)
	}
	if p, err := r.s.Discover(ctx, r.addedConnector(server, "ctr_doc", way), nil); err != nil || p.ClientID != "https://pons.example.com/v1/client/ctr_doc" {
		t.Fatalf("a client metadata document: %+v %v", p, err)
	}

	// Then a registration, kept by issuer and redirect address and reused
	// by a second connector at that issuer.
	r.auth.Set(func(sw *stubs.AuthSwitches) { sw.CIMD = false; sw.IssueSecret = true })
	way = r.ask(server, false)
	if way.Found.Client != ClientRegistered {
		t.Fatalf("the add found %+v", way.Found)
	}
	first, err := r.s.Discover(ctx, r.addedConnector(server, "ctr_reg", way), nil)
	if err != nil || !strings.HasPrefix(first.ClientID, "reg-") {
		t.Fatalf("a registration: %+v %v", first, err)
	}
	second, err := r.s.Discover(ctx, r.addedConnector(server, "ctr_reg2", way), nil)
	if err != nil || second.ClientID != first.ClientID || r.auth.Registrations() != 1 {
		t.Fatalf("a second connector registered again: %+v %v %d", second, err, r.auth.Registrations())
	}
	reg, err := r.st.Registrations().Get(ctx, r.auth.Issuer(), r.s.RedirectURI())
	if err != nil || reg.Secret.Zero() {
		t.Fatalf("the registration %+v %v", reg, err)
	}

	// And none is sign_in_unsupported, at the add and at a connect.
	r.auth.Set(func(sw *stubs.AuthSwitches) { sw.NoRegistration = true })
	if _, err := r.s.Ask(ctx, r.conns["ctr_reg"], false); apierr.Classify(err).Code != apierr.CodeSignInUnsupported || apierr.Classify(err).Reason != "no_client" {
		t.Fatalf("no way to identify at the add: %v", err)
	}
	if way, err := r.s.Ask(ctx, r.conns["ctr_reg"], true); err != nil || way.Found.Client != ClientOwn {
		t.Fatalf("a registered client needs no other way: %+v %v", way, err)
	}
	r.st.Registrations().Delete(ctx, r.auth.Issuer(), r.s.RedirectURI())
	if _, err := r.s.Discover(ctx, r.conns["ctr_reg"], nil); apierr.Classify(err).Reason != "no_client" {
		t.Fatalf("no way to identify at a connect: %v", err)
	}
}

// An added server whose authorization server does not say it sends iss,
// vouched for or not, signs in at a callback of its issuer's own, which its
// client metadata document and its registration name; an answer at the
// shared callback or at another issuer's is refused before the code goes
// anywhere; a server that sends iss keeps the shared callback.
func TestACallbackOfItsOwnPerIssuer(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	server := r.added()
	r.auth.Set(func(sw *stubs.AuthSwitches) { sw.IssSupported = false; sw.CIMD = true })
	key := IssuerKey(r.auth.Issuer())
	if !regexp.MustCompile(`^[0-9a-f]{16}$`).MatchString(key) {
		t.Fatalf("the key %q is not 16 hex digits", key)
	}
	own := "https://pons.example.com/v1/callback/" + key
	if r.s.CallbackFor(r.auth.Issuer()) != own {
		t.Fatalf("the callback of the issuer's own is %s", r.s.CallbackFor(r.auth.Issuer()))
	}
	const secret = "the-vouched-client-secret"
	r.auth.AddClient("vouched-client", secret)
	for _, vouched := range []bool{false, true} {
		way := r.ask(server, vouched)
		conn := r.addedConnector(server, "ctr_plain", way)
		if vouched {
			conn = r.withClient(r.addedConnector(server, "ctr_vouched", way), "vouched-client", secret)
		}
		if way.Found.Iss || r.s.RedirectOf(way.Found) != own {
			t.Fatalf("vouched %v: the add found %+v", vouched, way.Found)
		}
		if doc := r.s.ClientDocument(conn.Ref, conn.Title, r.s.RedirectOf(conn.Found)); len(doc.RedirectURIs) != 1 || doc.RedirectURIs[0] != own {
			t.Fatalf("vouched %v: the document names %v", vouched, doc.RedirectURIs)
		}
		for i, at := range []string{"", IssuerKey("https://elsewhere.example.net")} {
			_, address, f := r.connect("refused"+string(rune('a'+i))+map[bool]string{true: "v"}[vouched], conn)
			if f.RedirectURI != own {
				t.Fatalf("vouched %v: the flow's redirect address is %s", vouched, f.RedirectURI)
			}
			landed := follow(t, address)
			if landed.String() != own+"?"+landed.RawQuery || landed.Query().Has("iss") {
				t.Fatalf("vouched %v: the answer came back to %s", vouched, landed)
			}
			before := r.tokenCalls()
			var dest string
			var err error
			if at == "" {
				dest, err = r.s.Callback(ctx, landed.Query())
			} else {
				dest, err = r.s.CallbackAt(ctx, at, landed.Query())
			}
			if err != nil || !strings.Contains(dest, "error=sign_in_failed") || r.tokenCalls() != before {
				t.Fatalf("vouched %v: an answer at %q: %s %v, token requests %d to %d", vouched, at, dest, err, before, r.tokenCalls())
			}
		}
		c, address, _ := r.connect("accepted"+map[bool]string{true: "v"}[vouched], conn)
		landed := follow(t, address)
		dest, err := r.s.CallbackAt(ctx, key, landed.Query())
		if err != nil || !strings.Contains(dest, "code=") {
			t.Fatalf("vouched %v: an answer at its own callback: %s %v", vouched, dest, err)
		}
		u, err := url.Parse(dest)
		if err != nil {
			t.Fatal(err)
		}
		if err := r.s.Confirm(ctx, r.state(c), u.Query().Get("code")); err != nil {
			t.Fatalf("vouched %v: the confirm: %v", vouched, err)
		}
	}

	// A registration names the issuer's own callback and is kept under it.
	r.auth.Set(func(sw *stubs.AuthSwitches) { sw.CIMD = false })
	way := r.ask(server, false)
	if _, err := r.s.Discover(ctx, r.addedConnector(server, "ctr_reg", way), nil); err != nil {
		t.Fatal(err)
	}
	var body struct {
		RedirectURIs []string `json:"redirect_uris"`
	}
	for _, q := range r.auth.Requests() {
		if q.Path == "/register" {
			if err := json.Unmarshal(q.Body, &body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if len(body.RedirectURIs) != 1 || body.RedirectURIs[0] != own {
		t.Fatalf("the registration names %v", body.RedirectURIs)
	}
	if _, err := r.st.Registrations().Get(ctx, r.auth.Issuer(), own); err != nil {
		t.Fatalf("the registration is not kept under the issuer's callback: %v", err)
	}

	// A server that sends iss keeps the shared callback, and an answer for
	// it at an issuer's own is refused.
	r.auth.Set(func(sw *stubs.AuthSwitches) { sw.IssSupported = true; sw.CIMD = true })
	way = r.ask(server, false)
	if !way.Found.Iss || r.s.RedirectOf(way.Found) != r.s.RedirectURI() {
		t.Fatalf("a server that sends iss: %+v", way.Found)
	}
	_, address, f := r.connect("shared", r.addedConnector(server, "ctr_iss", way))
	if f.RedirectURI != r.s.RedirectURI() {
		t.Fatalf("a server that sends iss signs in at %s", f.RedirectURI)
	}
	if dest, err := r.s.CallbackAt(ctx, key, browser(t, address)); err != nil || !strings.Contains(dest, "error=sign_in_failed") {
		t.Fatalf("an answer of the shared callback at an issuer's own: %s %v", dest, err)
	}
}

// The add reads a server's first answer: a success is none, a 403 or a 401
// with no metadata is token, a 401 whose metadata names no usable server
// is refused, any other status and no answer at all are
// server_unreachable, and a server of an earlier revision is asked by its
// handshake.
func TestTheAddReadsTheFirstAnswer(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	server := r.added()
	conn := Connector{Kind: catalog.KindMCP, URL: server.URL(), AddedURL: server.URL()}
	cases := []struct {
		name   string
		set    func(*stubs.ConnectorSwitches)
		url    string
		way    string
		code   string
		reason string
	}{
		{"open", func(*stubs.ConnectorSwitches) {}, "", catalog.AuthNone, "", ""},
		{"an earlier revision", func(sw *stubs.ConnectorSwitches) { sw.Legacy = true }, "", catalog.AuthNone, "", ""},
		{"a key", func(sw *stubs.ConnectorSwitches) { sw.KeyOnly = true }, "", catalog.AuthToken, "", ""},
		{"a 403", func(sw *stubs.ConnectorSwitches) { sw.Insufficient = []string{"x"} }, "", catalog.AuthToken, "", ""},
		{"another address", func(*stubs.ConnectorSwitches) {}, strings.TrimSuffix(server.URL(), "/mcp") + "/nothing", "", apierr.CodeServerUnreachable, "status_404"},
		{"a redirect", func(sw *stubs.ConnectorSwitches) { sw.Redirect = true }, "", "", apierr.CodeServerUnreachable, "redirect_refused"},
		{"no answer", func(*stubs.ConnectorSwitches) {}, "https://nobody.example.com/mcp", "", apierr.CodeServerUnreachable, "address_not_public"},
		{"an authorization server that is not one", func(sw *stubs.ConnectorSwitches) {
			sw.Servers = []string{"https://nothing.example.com"}
		}, "", "", apierr.CodeConnectorUnreachable, ""},
	}
	for _, tc := range cases {
		server.Set(func(sw *stubs.ConnectorSwitches) { *sw = stubs.ConnectorSwitches{} })
		server.Set(tc.set)
		c := conn
		if tc.url != "" {
			c.URL = tc.url
		}
		way, err := r.s.Ask(ctx, c, false)
		e := apierr.Classify(err)
		switch {
		case tc.code == "" && (err != nil || way.Type != tc.way):
			t.Errorf("%s: %+v %v", tc.name, way, err)
		case tc.code != "" && (e.Code != tc.code || (tc.reason != "" && e.Reason != tc.reason)):
			t.Errorf("%s: %+v %v", tc.name, way, err)
		case tc.code != "" && strings.Contains(err.Error(), "example.com"):
			t.Errorf("%s: the error names the address: %v", tc.name, err)
		}
	}
	if server.Sessions() != 0 {
		t.Errorf("the add left %d sessions open", server.Sessions())
	}
	if _, err := r.s.Ask(ctx, Connector{Kind: catalog.KindMCP, URL: "https://bad host/"}, false); apierr.Classify(err).Code != apierr.CodeServerUnreachable {
		t.Errorf("an address that does not build a request: %v", err)
	}
	if got := ruleOf(&apierr.Error{Code: apierr.CodeInternal}); got != "fetch_failed" {
		t.Errorf("an error with no rule: %s", got)
	}
	if got := ruleOf(apierr.Fail(apierr.CodeConnectorUnreachable, "status_500")); got != "status_500" {
		t.Errorf("an error with a reason: %s", got)
	}
}
