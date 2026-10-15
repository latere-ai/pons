// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"latere.ai/x/pkg/authz"

	"latere.ai/x/pons/authorizer"
	"latere.ai/x/pons/internal/access"
	"latere.ai/x/pons/internal/apierr"
	"latere.ai/x/pons/test/stubs"
)

// orgOwner is the owner an authorizer gives an organization's servers.
const orgOwner = "org:acme"

// orgPolicy is an authorizer of one organization: admin adds the
// organization's servers, vouched for, and changes them; alice is a member,
// who sees and connects them; bob is neither. Every other question is the
// owner policy's.
func orgPolicy(c access.Caller, q access.Question) (access.Decision, error) {
	owner := q.Resource.String(authorizer.FieldOwner)
	member := c.Sub == "alice" || c.Sub == "admin"
	deny := access.Decision{Reason: "not_a_member"}
	switch q.Action {
	case authorizer.ActionConnectorCreate:
		if c.Sub == "admin" {
			return access.Decision{Allow: true, Limits: authorizer.Limits{Owner: orgOwner, Vouched: true}}, nil
		}
	case authorizer.ActionConnectorList:
		if member {
			return access.Decision{Allow: true, Filter: &authz.Filter{Owners: []string{c.Subject, orgOwner}}}, nil
		}
	case authorizer.ActionConnectorRead:
		if owner == orgOwner {
			if member {
				return access.Decision{Allow: true}, nil
			}
			return deny, nil
		}
	case authorizer.ActionConnectorUpdate, authorizer.ActionConnectorDelete:
		if owner == orgOwner {
			if c.Sub == "admin" {
				return access.Decision{Allow: true}, nil
			}
			return deny, nil
		}
	}
	return access.NewAuthorizer(access.OwnerPolicy{}).Authorize(context.Background(), c, q)
}

// add adds a connector at the stub connector's address as the bearer, with
// the auth given, or none for the server's own answer.
func (h *harness) add(bearer, name string, auth map[string]any) answer {
	h.t.Helper()
	body := map[string]any{"name": name, "title": "Wiki", "kind": "mcp", "url": addedURL}
	if auth != nil {
		body["auth"] = auth
	}
	return h.do(http.MethodPost, "/v1/connectors", bearer, body)
}

// asked are the questions of one action since a count of questions.
func (h *harness) asked(since int, action string) []access.Question {
	var out []access.Question
	for _, q := range h.authz.questions()[since:] {
		if q.Action == action {
			out = append(out, q)
		}
	}
	return out
}

// ids are the ids of a list's items.
func ids(t testing.TB, a answer) []string {
	t.Helper()
	var out []string
	for _, item := range a.json(t)["items"].([]any) {
		if id, ok := item.(map[string]any)["id"].(string); ok {
			out = append(out, id)
		}
	}
	return out
}

// itemOf is the item of a list with the id.
func itemOf(t testing.TB, a answer, id string) map[string]any {
	t.Helper()
	for _, item := range a.json(t)["items"].([]any) {
		if m := item.(map[string]any); m["id"] == id {
			return m
		}
	}
	t.Fatalf("%s is not listed: %s", id, a.body)
	return nil
}

// An add whose allow names another owner stores that owner, and the list
// shows the connector to every caller whose filter names that owner and to
// no other, each owner's beside the others in one answer.
func TestAnAddedConnectorListsToTheOwnersTheFilterNames(t *testing.T) {
	h := newHarness(t)
	h.authz.set(orgPolicy)
	before := len(h.authz.questions())
	org := h.add("admin", "wiki", nil)
	if org.status != http.StatusCreated || org.json(t)["owner"] != orgOwner || org.json(t)["vouched"] != true {
		t.Fatalf("the organization's add: %d %s", org.status, org.body)
	}
	if q := h.asked(before, authorizer.ActionConnectorCreate); len(q) != 1 || q[0].Resource.String(authorizer.FieldOwner) != "" {
		t.Fatalf("the add asked %+v", q)
	}
	wiki := idOf(t, org)
	mine := idOf(t, h.add("alice", "mine", nil))
	if a := h.add("bob", "bobs", nil); a.status != http.StatusCreated || a.json(t)["owner"] != subject("bob") || a.json(t)["vouched"] != false {
		t.Fatalf("a person's add: %d %s", a.status, a.body)
	}
	if got := ids(t, h.do(http.MethodGet, "/v1/connectors", "alice", nil)); !slices.Contains(got, wiki) || !slices.Contains(got, mine) || len(got) != 2 {
		t.Fatalf("alice lists %v", got)
	}
	if got := ids(t, h.do(http.MethodGet, "/v1/connectors", "admin", nil)); !slices.Equal(got, []string{wiki}) {
		t.Fatalf("admin lists %v", got)
	}
	if got := ids(t, h.do(http.MethodGet, "/v1/connectors", "bob", nil)); slices.Contains(got, wiki) || slices.Contains(got, mine) || len(got) != 1 {
		t.Fatalf("bob lists %v", got)
	}
	if a := h.do(http.MethodGet, "/v1/connectors/"+wiki, "alice", nil); a.status != http.StatusOK || a.json(t)["owner"] != orgOwner {
		t.Fatalf("alice reads the organization's: %d %s", a.status, a.body)
	}
	if a := h.do(http.MethodGet, "/v1/connectors/"+wiki, "bob", nil); a.status != http.StatusNotFound || a.code() != apierr.CodeConnectorNotFound {
		t.Fatalf("bob reads the organization's: %d %s", a.status, a.body)
	}
}

// An owner's add past PONS_MAX_ADDED_CONNECTORS is 409 connector_limit,
// and another owner's add still succeeds.
func TestAnOwnerHoldsAtMostItsLimitOfConnectors(t *testing.T) {
	h := newHarness(t, func(s *Server) { s.MaxAddedConnectors = 2 })
	h.authz.set(orgPolicy)
	for _, name := range []string{"one", "two"} {
		if a := h.add("alice", name, nil); a.status != http.StatusCreated {
			t.Fatalf("%s: %d %s", name, a.status, a.body)
		}
	}
	asked := len(h.up.mcp.Requests())
	a := h.add("alice", "three", nil)
	if a.status != http.StatusConflict || a.code() != apierr.CodeConnectorLimit || a.detail("field") != "owner" || a.detail("reason") != "max_added_connectors=2" {
		t.Fatalf("past the limit: %d %s", a.status, a.body)
	}
	if len(h.up.mcp.Requests()) == asked {
		t.Fatal("the add past the limit did not ask the server, which the limit follows")
	}
	if a := h.add("bob", "one", nil); a.status != http.StatusCreated {
		t.Fatalf("another person's add: %d %s", a.status, a.body)
	}
	for _, name := range []string{"one", "two"} {
		if a := h.add("admin", name, nil); a.status != http.StatusCreated {
			t.Fatalf("the organization's %s: %d %s", name, a.status, a.body)
		}
	}
	if a := h.add("admin", "three", nil); a.code() != apierr.CodeConnectorLimit {
		t.Fatalf("the organization past its limit: %d %s", a.status, a.body)
	}
	if got := ids(t, h.do(http.MethodGet, "/v1/connectors", "alice", nil)); len(got) != 4 {
		t.Fatalf("alice lists %d of her own and the organization's", len(got))
	}
}

// A connect to another owner's connector asks connector.read of it first:
// an allow connects, under the caller's own owner, and connection.create
// carries connector_owner; a deny is 404 and asks nothing more, as it is
// under the owner policy; an outage is 503.
func TestAConnectionToAnotherOwnersConnector(t *testing.T) {
	h := newHarness(t)
	h.authz.set(orgPolicy)
	wiki := idOf(t, h.add("admin", "wiki", map[string]any{"type": "token"}))
	before := len(h.authz.questions())
	a := h.connect("alice", wiki, "", "the-key-of-alice")
	if a.status != http.StatusCreated || a.json(t)["owner"] != subject("alice") || a.json(t)["connector"] != wiki || a.json(t)["state"] != "connected" {
		t.Fatalf("alice connects the organization's: %d %s", a.status, a.body)
	}
	asked := h.authz.questions()[before:]
	if len(asked) != 2 || asked[0].Action != authorizer.ActionConnectorRead || asked[0].Resource.ID != wiki ||
		asked[0].Resource.String(authorizer.FieldOwner) != orgOwner {
		t.Fatalf("the connect asked %+v", asked)
	}
	if create := asked[1]; create.Action != authorizer.ActionConnectionCreate || create.Resource.String(authorizer.FieldConnectorOwner) != orgOwner ||
		create.Resource.String(authorizer.FieldConnector) != wiki {
		t.Fatalf("the connect's create %+v", create)
	}
	// A catalog connector has no owner, and its connect asks one question.
	before = len(h.authz.questions())
	if a := h.connect("alice", "weather", "", ""); a.status != http.StatusCreated {
		t.Fatalf("a catalog connector: %d %s", a.status, a.body)
	}
	if asked := h.authz.questions()[before:]; len(asked) != 1 || asked[0].Resource.String(authorizer.FieldConnectorOwner) != "" {
		t.Fatalf("a catalog connector's connect asked %+v", asked)
	}
	before = len(h.authz.questions())
	if a := h.connect("bob", wiki, "", "the-key-of-bob-0"); a.status != http.StatusNotFound || a.code() != apierr.CodeConnectorNotFound || a.detail("field") != "connector" {
		t.Fatalf("bob connects the organization's: %d %s", a.status, a.body)
	}
	if q := h.asked(before, authorizer.ActionConnectionCreate); len(q) != 0 {
		t.Fatalf("a deny of the read asked a create: %+v", q)
	}
	// The owner policy, as an authorizer that knows nothing of
	// organizations, lets nobody read another's connector.
	h.authz.set(nil)
	if a := h.connect("carol", wiki, "", "the-key-of-carol"); a.status != http.StatusNotFound {
		t.Fatalf("under the owner policy: %d %s", a.status, a.body)
	}
	h.authz.set(func(c access.Caller, q access.Question) (access.Decision, error) {
		if q.Action == authorizer.ActionConnectorRead {
			return access.Decision{}, fmt.Errorf("%w: the endpoint hung", access.ErrUnavailable)
		}
		return orgPolicy(c, q)
	})
	if a := h.connect("alice", wiki, "again", "the-key-of-alice"); a.status != http.StatusServiceUnavailable || a.code() != apierr.CodeAuthorizerUnavailable {
		t.Fatalf("an outage: %d %s", a.status, a.body)
	}
	// The connection is alice's, and its key is used for her.
	h.authz.set(orgPolicy)
	conns := ids(t, h.do(http.MethodGet, "/v1/connections", "alice", nil))
	if len(conns) != 2 {
		t.Fatalf("alice holds %v", conns)
	}
	var con string
	for _, id := range conns {
		if h.do(http.MethodGet, "/v1/connections/"+id, "alice", nil).json(t)["connector"] == wiki {
			con = id
		}
	}
	if a := h.callTool("alice", con, "get_note"); a.status != http.StatusOK {
		t.Fatalf("alice's call: %d %s", a.status, a.body)
	}
	if got := h.up.mcp.Credentials(); got[len(got)-1] != "Bearer the-key-of-alice" {
		t.Fatalf("the call carried %q", got[len(got)-1])
	}
	// Who may change the connector sees how many connections use it.
	if a := h.do(http.MethodGet, "/v1/connectors/"+wiki, "admin", nil).json(t); a["connections"] != float64(1) {
		t.Fatalf("admin reads %v", a)
	}
	if a := h.do(http.MethodGet, "/v1/connectors/"+wiki, "alice", nil).json(t); a["connections"] != nil {
		t.Fatalf("alice reads a count: %v", a)
	}
	if item := itemOf(t, h.do(http.MethodGet, "/v1/connectors", "admin", nil), wiki); item["connections"] != float64(1) {
		t.Fatalf("admin lists %v", item)
	}
	if item := itemOf(t, h.do(http.MethodGet, "/v1/connectors", "alice", nil), wiki); item["connections"] != nil {
		t.Fatalf("alice lists a count: %v", item)
	}
}

// callTool calls one tool through a connection's MCP address.
func (h *harness) callTool(bearer, con, tool string) answer {
	h.t.Helper()
	body := map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{
		"name": tool, "arguments": map[string]any{},
		"_meta": map[string]any{"io.modelcontextprotocol/protocolVersion": stubs.MCPRevision},
	}}
	return h.do(http.MethodPost, "/v1/connections/"+con+"/mcp", bearer, body,
		"MCP-Protocol-Version", stubs.MCPRevision, "Mcp-Method", "tools/call", "Mcp-Name", tool, "Accept", "application/json, text/event-stream")
}

// browser follows a sign-in as a person's browser does: the authorization
// request at the stub, then the answer at the address the stub sent it
// back to, on the harness. It answers that address and where the harness
// sent the browser on.
func (h *harness) browser(t testing.TB, authorizationURL string) (landed, back *url.URL) {
	t.Helper()
	landed = authorize(t, authorizationURL)
	return landed, h.callback(t, landed)
}

// authorize follows an authorization request at the stub, reached by its
// name on loopback, and answers the address it sends the browser back to.
func authorize(t testing.TB, authorizationURL string) *url.URL {
	t.Helper()
	dialer := &net.Dialer{}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: stubs.Roots(), MinVersion: tls.VersionTLS12},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				_, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				return dialer.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", port))
			},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, authorizationURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatal(err)
	}
	landed, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || resp.StatusCode != http.StatusFound {
		t.Fatalf("the authorization request answered %d %v", resp.StatusCode, err)
	}
	return landed
}

// callback brings the answer at an address of the harness's callback to
// it, and answers where the harness sent the browser on.
func (h *harness) callback(t testing.TB, landed *url.URL) *url.URL {
	t.Helper()
	client := *h.http.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, h.http.URL+landed.Path+"?"+landed.RawQuery, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("the callback at %s answered %d", landed.Path, resp.StatusCode)
	}
	back, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return back
}

// signIn connects a connector whose people sign in, follows the sign-in,
// and answers the connection's id, where the callback was, and where the
// browser was sent on.
func (h *harness) signIn(t testing.TB, bearer, connector string) (string, *url.URL, *url.URL) {
	t.Helper()
	a := h.do(http.MethodPost, "/v1/connections", bearer, map[string]any{"connector": connector, "return_to": "https://app.example.com/done"})
	if a.status != http.StatusCreated {
		t.Fatalf("a connect by signing in: %d %s", a.status, a.body)
	}
	started := a.json(t)
	con := started["connection"].(map[string]any)["id"].(string)
	landed, back := h.browser(t, started["authorization_url"].(string))
	return con, landed, back
}

// confirm makes a signed-in connection usable with the code the browser
// brought back.
func (h *harness) confirm(t testing.TB, bearer, con string, back *url.URL) answer {
	t.Helper()
	return h.do(http.MethodPost, "/v1/connections/"+con+"/confirm", bearer, map[string]any{"code": back.Query().Get("code")})
}

// Who may change an added connector, as the authorizer answers
// connector.update, sees how many connections of every owner use it, on a
// read, in a list and in an edit's answer; a reader does not, and an
// authorizer that gives no decision about it hides the count and fails
// nothing.
func TestWhoMayChangeAConnectorSeesItsConnections(t *testing.T) {
	h := newHarness(t)
	h.authz.set(orgPolicy)
	wiki := idOf(t, h.add("admin", "wiki", map[string]any{"type": "token"}))
	mine := idOf(t, h.add("alice", "mine", map[string]any{"type": "token"}))
	for _, who := range []string{"alice", "admin"} {
		if a := h.connect(who, wiki, "", "the-key-of-"+who+"-0"); a.status != http.StatusCreated {
			t.Fatalf("%s connects: %d %s", who, a.status, a.body)
		}
	}
	if a := h.connect("alice", mine, "", "the-key-of-alice-1"); a.status != http.StatusCreated {
		t.Fatal(a.status)
	}
	before := len(h.authz.questions())
	list := h.do(http.MethodGet, "/v1/connectors", "alice", nil)
	if item := itemOf(t, list, wiki); item["connections"] != nil {
		t.Fatalf("a member reads the organization's count: %v", item)
	}
	if item := itemOf(t, list, mine); item["connections"] != float64(1) {
		t.Fatalf("alice's own: %v", item)
	}
	if q := h.asked(before, authorizer.ActionConnectorUpdate); len(q) != 2 || q[0].Resource.ID != "" || q[1].Resource.ID != "" {
		t.Fatalf("the list asked %+v, want one question per owner on its page", q)
	}
	if item := itemOf(t, h.do(http.MethodGet, "/v1/connectors", "admin", nil), wiki); item["connections"] != float64(2) {
		t.Fatalf("admin lists %v", item)
	}
	if a := h.do(http.MethodPatch, "/v1/connectors/"+wiki, "admin", map[string]any{"description": "Notes."}).json(t); a["connections"] != float64(2) {
		t.Fatalf("an edit answers %v", a)
	}
	h.authz.set(func(c access.Caller, q access.Question) (access.Decision, error) {
		if q.Action == authorizer.ActionConnectorUpdate {
			return access.Decision{}, fmt.Errorf("%w: the endpoint hung", access.ErrUnavailable)
		}
		return orgPolicy(c, q)
	})
	if a := h.do(http.MethodGet, "/v1/connectors/"+wiki, "admin", nil); a.status != http.StatusOK || a.json(t)["connections"] != nil {
		t.Fatalf("a read when the count has no decision: %d %s", a.status, a.body)
	}
	if a := h.do(http.MethodGet, "/v1/connectors", "admin", nil); a.status != http.StatusOK || itemOf(t, a, wiki)["connections"] != nil {
		t.Fatalf("a list when the count has no decision: %d %s", a.status, a.body)
	}
	if !strings.Contains(h.logText(), "the count of a connector's connections is not shown") {
		t.Fatal("a count with no decision was not logged")
	}
}

// An added connector's view carries what a client draws it with: its
// owner, url, presentation and tool marks, how a person gives access and,
// for a server that signs people in, how Pons identifies itself there,
// whether it is turned off and vouched for, and for a vouched-for client
// the address to register it with; never the client's id or secret.
func TestAnAddedConnectorsView(t *testing.T) {
	h := newHarness(t)
	h.authz.set(orgPolicy)
	h.signsIn()
	a := h.do(http.MethodPost, "/v1/connectors", "admin", map[string]any{
		"name": "wiki", "title": "Team wiki", "description": "The team's notes.", "icon": "https://mcp.example.com/icon.svg",
		"kind": "mcp", "url": addedURL, "tools": map[string]any{"read_only": []string{"get_*"}},
		"auth": map[string]any{"type": "oauth", "scopes": []string{"notes:read"}, "client": map[string]any{"id": "wiki-client", "secret": "the-wiki-client-secret"}},
	})
	if a.status != http.StatusCreated {
		t.Fatalf("%d %s", a.status, a.body)
	}
	id := idOf(t, a)
	want := `{"name":"wiki","id":"` + id + `","owner":"` + orgOwner + `","title":"Team wiki","description":"The team's notes.",` +
		`"icon":"https://mcp.example.com/icon.svg","kind":"mcp","url":"` + addedURL + `","hosts":["mcp.example.com"],` +
		`"auth":{"type":"oauth","scopes":["notes:read"],"client":"own","redirect_uri":"https://pons.example.com/v1/callback"},` +
		`"tools":{"read_only":["get_*"],"hidden":[]},"disabled":false,"vouched":true,"connections":0}`
	if got := strings.TrimSpace(string(h.do(http.MethodGet, "/v1/connectors/"+id, "admin", nil).body)); got != want {
		t.Fatalf("the view\n got %s\nwant %s", got, want)
	}
	h.up.mcp.Set(func(sw *stubs.ConnectorSwitches) { *sw = stubs.ConnectorSwitches{KeyOnly: true} })
	key := h.add("alice", "keyed", nil)
	want = `{"name":"keyed","id":"` + idOf(t, key) + `","owner":"` + subject("alice") + `","title":"Wiki","kind":"mcp","url":"` + addedURL + `",` +
		`"hosts":["mcp.example.com"],"auth":{"type":"token","inject":{"header":"Authorization","format":"Bearer {value}"},"hint":"API key"},` +
		`"tools":{"read_only":[],"hidden":[]},"disabled":false,"vouched":false}`
	if got := strings.TrimSpace(string(key.body)); got != want {
		t.Fatalf("a key's view\n got %s\nwant %s", got, want)
	}
	if got := itemOf(t, h.do(http.MethodGet, "/v1/connectors", "alice", nil), id); got["connections"] != nil || got["auth"].(map[string]any)["client"] != "own" {
		t.Fatalf("a member lists %v", got)
	}
}
