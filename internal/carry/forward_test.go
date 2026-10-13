// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package carry

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"latere.ai/x/pons/authorizer"
	"latere.ai/x/pons/catalog"
	"latere.ai/x/pons/internal/store"
	"latere.ai/x/pons/test/stubs"
)

// A path with a dot segment, an empty segment, an encoded slash, backslash
// or dot, a control character, or over 2048 bytes is refused before the
// connection is loaded, and no request leaves for another host.
func TestAForwardedPathStaysOnItsConnector(t *testing.T) {
	r := newRig(t, false)
	c := r.keyed()
	for _, bad := range []string{
		"/a/../b", "/a/./b", "/..", "/a//b", "/a/", "/a%2Fb", "/a%2fb", "/a%5Cb", `/a\b`, "/%2e%2e/b", "/.%2E/b",
		"/a%00b", "/a%1Fb", "/a%7Fb", "/" + strings.Repeat("a", MaxPathBytes+1),
	} {
		for _, id := range []string{c.ID, "con_nothing"} {
			a := r.send(http.MethodGet, "/v1/connections/"+id+"/http"+bad, "alice", nil)
			if a.status != http.StatusBadRequest || a.code() != "invalid_request" {
				t.Errorf("%s on %s: %d %s", bad, id, a.status, a.body)
			}
		}
	}
	if got := r.api.Requests(); len(got) != 0 {
		t.Fatalf("a refused path reached the connector: %+v", got)
	}
	if got := r.az.questions(); len(got) != 0 {
		t.Fatalf("a refused path asked a question: %+v", got)
	}
	// A path that names a host is a path below the connector's url.
	if a := r.send(http.MethodGet, address(c, "http")+"/https:/elsewhere.example.net/user?x=1", "alice", nil); a.status != http.StatusNotFound {
		t.Fatalf("a host-like path: %d %s", a.status, a.body)
	}
	if a := r.send(http.MethodGet, address(c, "http")+"/repos/acme/app/issues?page=2&state=open", "alice", nil); a.status != http.StatusOK {
		t.Fatalf("a good path: %d %s", a.status, a.body)
	}
	if a := r.send(http.MethodGet, address(c, "http"), "alice", nil); a.status != http.StatusOK {
		t.Fatalf("the address itself is the url: %d %s", a.status, a.body)
	}
	got := r.api.Requests()
	if len(got) != 3 || got[0].Path != "/https:/elsewhere.example.net/user" || got[1].Path != "/repos/acme/app/issues" ||
		got[1].Query != "page=2&state=open" || got[2].Path != "/" {
		t.Fatalf("forwarded %+v", got)
	}
	if a := r.send(http.MethodGet, "/v1/connections/"+c.ID+"/http/user", "", nil); a.status != http.StatusUnauthorized || a.code() != "missing_token" {
		t.Fatalf("no bearer: %d %s", a.status, a.body)
	}
	if a := r.send(http.MethodGet, "/v1/connections/"+c.ID+"/http/user", "expired", nil); a.status != http.StatusUnauthorized || a.code() != "invalid_token" {
		t.Fatalf("a refused bearer: %d %s", a.status, a.body)
	}
	if r.c.Handles(httpRequest(t, "/v1/connections/"+c.ID+"/mcp")) || r.c.Handles(httpRequest(t, "/v1/connections/")) {
		t.Fatal("the carrier takes an address it does not serve")
	}
}

// The forwarding address carries the methods of an API alone: TRACE,
// CONNECT and a method of another protocol are refused before the
// connection is loaded, reach no connector and ask no question, and each of
// ForwardedMethods is forwarded.
func TestOnlyAnAPIsMethodsAreForwarded(t *testing.T) {
	r := newRig(t, false)
	c := r.keyed()
	for _, m := range []string{http.MethodTrace, "PROPFIND", "get", "QUERY"} {
		if a := r.send(m, address(c, "http")+"/user", "alice", nil); a.status != http.StatusBadRequest || a.code() != "invalid_request" {
			t.Errorf("%s: %d %s", m, a.status, a.body)
		}
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodConnect, "http://pons.example.com"+address(c, "http")+"/user", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer alice")
	w := httptest.NewRecorder()
	r.c.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "invalid_request") {
		t.Errorf("CONNECT: %d %s", w.Code, w.Body)
	}
	if got := r.api.Requests(); len(got) != 0 {
		t.Fatalf("a refused method reached the connector: %+v", got)
	}
	if got := r.az.questions(); len(got) != 0 {
		t.Fatalf("a refused method asked a question: %+v", got)
	}
	for _, m := range ForwardedMethods {
		if a := r.send(m, address(c, "http")+"/user", "alice", nil); a.status == http.StatusBadRequest {
			t.Errorf("%s was refused: %s", m, a.body)
		}
	}
	if got := r.api.Requests(); len(got) != len(ForwardedMethods) {
		t.Fatalf("forwarded %d of %d methods: %+v", len(got), len(ForwardedMethods), got)
	}
}

// Under an allow whose limits give Requests, a request to the forwarding
// address that no entry names is 403 forbidden on tool with the reason
// requests, so the caller learns that the connection is there and the
// request is not allowed; nothing reaches the connector, and the call is
// recorded denied. A request an entry names is forwarded, and the git
// address is held by refs alone.
func TestARequestOutsideRequestsIsForbidden(t *testing.T) {
	r := newRig(t, true)
	c := r.keyed()
	r.az.set(authorizer.Limits{Requests: []string{"GET /**", "POST /repos/*/*/issues"}})
	for _, ok := range []struct{ method, path string }{
		{http.MethodGet, "/repos/acme/app/issues"},
		{http.MethodPost, "/repos/acme/app/issues"},
	} {
		if a := r.send(ok.method, address(c, "http")+ok.path, "alice", strings.NewReader("{}")); a.status != http.StatusOK && a.status != http.StatusCreated {
			t.Errorf("%s %s: %d %s", ok.method, ok.path, a.status, a.body)
		}
	}
	before := len(r.api.Requests())
	for _, bad := range []struct{ method, path string }{
		{http.MethodPut, "/repos/acme/app/pulls/7/merge"},
		{http.MethodPost, "/repos/acme/app/issues/1/comments"},
		{http.MethodDelete, "/repos/acme/app"},
	} {
		a := r.send(bad.method, address(c, "http")+bad.path, "alice", strings.NewReader("{}"))
		if a.status != http.StatusForbidden || a.code() != "forbidden" || a.detail("field") != "tool" || a.detail("reason") != "requests" {
			t.Errorf("%s %s: %d %s", bad.method, bad.path, a.status, a.body)
		}
	}
	if got := r.api.Requests(); len(got) != before {
		t.Fatalf("a refused request reached the connector: %+v", got[before:])
	}
	calls := r.calls(c)
	if last := calls[len(calls)-1]; last.Outcome != OutcomeDenied || last.Method != http.MethodPut {
		t.Fatalf("the refused request was recorded %+v", last)
	}
	if a := r.send(http.MethodGet, address(c, "git")+"/acme/app.git/info/refs?service=git-upload-pack", "alice", nil); a.status != http.StatusOK {
		t.Fatalf("a clone under requests: %d %s", a.status, a.body)
	}
}

func httpRequest(t *testing.T, path string) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://pons.example.com"+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

// GET, HEAD, OPTIONS and an http.read_only match read, every other method
// writes, and ReadOnly refuses a write.
func TestTheEffectOfAForwardedRequest(t *testing.T) {
	r := newRig(t, false)
	c := r.keyed()
	cases := []struct{ method, path, want string }{
		{http.MethodGet, "/user", catalog.EffectRead},
		{http.MethodHead, "/user", catalog.EffectRead},
		{http.MethodOptions, "/user", catalog.EffectRead},
		{http.MethodPost, "/search/issues", catalog.EffectRead},
		{http.MethodPost, "/repos/acme/app/issues", catalog.EffectWrite},
		{http.MethodPut, "/upload", catalog.EffectWrite},
		{http.MethodPatch, "/repos/acme/app", catalog.EffectWrite},
		{http.MethodDelete, "/repos/acme/app", catalog.EffectWrite},
	}
	for _, tc := range cases {
		r.send(tc.method, address(c, "http")+tc.path, "alice", strings.NewReader("{}"))
		asked := r.az.questions()
		q := asked[len(asked)-1]
		if q.Action != authorizer.ActionConnectionUse || q.Resource.Fields["effect"] != tc.want || q.Resource.Fields["tool"] != tc.path || q.Resource.Fields["method"] != tc.method {
			t.Errorf("%s %s asked %+v", tc.method, tc.path, q.Resource)
		}
	}
	r.az.set(authorizer.Limits{ReadOnly: true})
	before := len(r.api.Requests())
	for _, tc := range cases {
		a := r.send(tc.method, address(c, "http")+tc.path, "alice", strings.NewReader("{}"))
		refused := a.status == http.StatusForbidden && a.detail("field") == "tool" && a.detail("reason") == "read_only"
		if refused != (tc.want == catalog.EffectWrite) {
			t.Errorf("under read_only, %s %s: %d %s", tc.method, tc.path, a.status, a.body)
		}
	}
	if got := len(r.api.Requests()) - before; got != 4 {
		t.Fatalf("under read_only %d requests reached the connector, want the 4 that read", got)
	}
}

// A body streams without being buffered, and one past
// PONS_MAX_FORWARD_BYTES ends with 413.
func TestAForwardedBodyStreams(t *testing.T) {
	r := newRig(t, false)
	c := r.keyed()
	pr, pw := io.Pipe()
	done := make(chan answer, 1)
	go func() { done <- r.send(http.MethodPut, address(c, "http")+"/upload", "alice", pr) }()
	first := bytes.Repeat([]byte("a"), 8<<10)
	if _, err := pw.Write(first); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for r.api.Received() < int64(len(first)) {
		if time.Now().After(deadline) {
			t.Fatal("the first part did not reach the connector before the rest was sent")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := pw.Write(bytes.Repeat([]byte("b"), 8<<10)); err != nil {
		t.Fatal(err)
	}
	if err := pw.Close(); err != nil {
		t.Fatal(err)
	}
	if a := <-done; a.status != http.StatusOK || !bytes.Contains(a.body, []byte(`"bytes":16384`)) {
		t.Fatalf("the stream: %d %s", a.status, a.body)
	}

	r.serving.Wait()
	r.c.MaxForwardBytes = 4 << 10
	before := len(r.api.Requests())
	if a := r.send(http.MethodPost, address(c, "http")+"/repos/acme/app/issues", "alice", bytes.NewReader(make([]byte, 5<<10))); a.status != http.StatusRequestEntityTooLarge || a.code() != "request_too_large" {
		t.Fatalf("a length past the bound: %d %s", a.status, a.body)
	}
	if len(r.api.Requests()) != before {
		t.Fatal("a length past the bound reached the connector")
	}
	pr, pw = io.Pipe()
	go func() {
		_, err := pw.Write(make([]byte, 5<<10))
		pw.CloseWithError(err)
	}()
	if a := r.send(http.MethodPut, address(c, "http")+"/upload", "alice", pr); a.status != http.StatusRequestEntityTooLarge {
		t.Fatalf("a stream past the bound: %d %s", a.status, a.body)
	}
	r.serving.Wait()
	if uploads := countPath(r.api.Requests(), "/upload"); uploads > 1 && r.api.Received() > 4<<10 {
		t.Fatalf("%d bytes of a body past the bound reached the connector", r.api.Received())
	}
}

// A Link header's URLs under the connector's url come back under the
// forwarding address and others are dropped; a body's URLs are unchanged.
func TestLinksComeBackToTheAddress(t *testing.T) {
	r := newRig(t, false)
	c := r.keyed()
	a := r.send(http.MethodGet, address(c, "http")+"/repos/acme/app/issues", "alice", nil)
	at := r.c.Address(c.ID, AddressHTTP)
	want := `<` + at + `/repos/acme/app/issues?page=2>; rel="next", <` + at + `/repos/acme/app/issues?page=3>; rel="last"`
	if got := a.header.Get("Link"); got != want {
		t.Fatalf("Link %q, want %q", got, want)
	}
	if !bytes.Contains(a.body, []byte(r.api.URL()+"/repos/acme/app/issues/1")) {
		t.Fatalf("the body was changed: %s", a.body)
	}
	if got := rewriteLinks([]string{`<https://elsewhere.example.net/x>; rel="help"`, `<` + r.api.URL() + `.evil.example.net/y>; rel="x"`}, r.api.URL(), at); got != "" {
		t.Fatalf("links elsewhere kept: %q", got)
	}
	if got := rewriteLinks([]string{`<` + r.api.URL() + `/a,b>; title="x, y"; rel="next", bare`}, r.api.URL(), at); got != `<`+at+`/a,b>; title="x, y"; rel="next"` {
		t.Fatalf("a link with commas: %q", got)
	}
}

// A 3xx within the connector comes back rewritten, and one elsewhere is 502
// with redirect_elsewhere.
func TestARedirectStaysOnItsConnector(t *testing.T) {
	r := newRig(t, false)
	c := r.keyed()
	a := r.send(http.MethodGet, address(c, "http")+"/redirect/within", "alice", nil)
	if a.status != http.StatusFound || a.header.Get("Location") != r.c.Address(c.ID, AddressHTTP)+"/user" {
		t.Fatalf("within: %d %v", a.status, a.header)
	}
	a = r.send(http.MethodGet, address(c, "http")+"/redirect/elsewhere", "alice", nil)
	if a.status != http.StatusBadGateway || a.code() != "connector_unavailable" || a.detail("reason") != "redirect_elsewhere" || a.header.Get("Location") != "" {
		t.Fatalf("elsewhere: %d %s", a.status, a.body)
	}
	for _, rq := range r.api.Requests() {
		if rq.Path == "/user" {
			t.Fatal("a redirect was followed")
		}
	}
	if loc, ok := location("/user?x=1", mustURL(t, r.api.URL()+"/a/b"), r.api.URL(), "https://pons.example.com/v1/connections/c/http"); !ok || loc != "https://pons.example.com/v1/connections/c/http/user?x=1" {
		t.Fatalf("a relative location: %q", loc)
	}
	if _, ok := location("%zz", mustURL(t, r.api.URL()), r.api.URL(), "x"); ok {
		t.Fatal("a location that does not parse is kept")
	}
}

// Only the listed headers pass each way, and Set-Cookie and
// WWW-Authenticate never do.
func TestForwardedHeaders(t *testing.T) {
	r := newRig(t, false)
	c := r.keyed()
	a := r.send(http.MethodGet, address(c, "http")+"/headers", "alice", nil,
		"Accept", "application/vnd.example+json", "If-None-Match", `"v0"`, "Range", "bytes=0-10", "X-Api-Version", "2026-10-01",
		"Cookie", "session=caller", "X-Forwarded-For", "10.0.0.1", "Via", "1.1 proxy", "X-Real-Ip", "10.0.0.2",
		"Connection", "X-Hop", "X-Hop", "1", "User-Agent", "caller/1.0", "X-Other", "2", "Proxy-Authorization", "Basic x")
	got := r.api.Requests()[0]
	for name, want := range map[string]string{
		"Accept": "application/vnd.example+json", "If-None-Match": `"v0"`, "Range": "bytes=0-10", "X-Api-Version": "2026-10-01",
		"Authorization": "Bearer the-key-of-alice-0001", "Accept-Encoding": "identity",
	} {
		if got.Header.Get(name) != want {
			t.Errorf("toward the connector %s is %q, want %q", name, got.Header.Get(name), want)
		}
	}
	for _, name := range []string{"Cookie", "X-Forwarded-For", "Via", "X-Real-Ip", "X-Hop", "X-Other", "Proxy-Authorization"} {
		if got.Header.Get(name) != "" {
			t.Errorf("%s reached the connector", name)
		}
	}
	if !strings.HasPrefix(got.Header.Get("User-Agent"), "pons/") {
		t.Errorf("the user agent %q", got.Header.Get("User-Agent"))
	}
	for _, name := range []string{"Etag", "Cache-Control", "Last-Modified", "Retry-After", "X-Ratelimit-Remaining", "Content-Type"} {
		if a.header.Get(name) == "" {
			t.Errorf("%s did not pass back", name)
		}
	}
	for _, name := range []string{"Set-Cookie", "Www-Authenticate", "X-Stub-Private"} {
		if a.header.Get(name) != "" {
			t.Errorf("%s passed back", name)
		}
	}
	// The caller's own encoding is asked of the connector and passes back
	// unread.
	r.send(http.MethodGet, address(c, "http")+"/user", "alice", nil, "Accept-Encoding", "gzip")
	if got := r.api.Requests()[1].Header.Get("Accept-Encoding"); got != "gzip" {
		t.Fatalf("the caller's encoding %q", got)
	}
	if a := r.send(http.MethodGet, address(c, "http")+"/user", "alice", nil, "Origin", "https://elsewhere.example.net"); a.status != http.StatusForbidden || a.detail("reason") != "origin" {
		t.Fatalf("a foreign origin: %d %s", a.status, a.body)
	}
	if a := r.send(http.MethodGet, address(c, "http")+"/user", "alice", nil, "Origin", "https://app.example.com"); a.status != http.StatusOK {
		t.Fatalf("the origin of a return address: %d %s", a.status, a.body)
	}
}

// A 401 to a request with no body is retried once after a refresh, and one
// to a request with a body is answered as it came.
func TestARefusedForwardedRequest(t *testing.T) {
	r := newRig(t, false)
	c, old := r.signedIn(time.Now().Add(time.Hour))
	r.api.Refuse("Bearer " + old)
	if a := r.send(http.MethodGet, address(c, "http")+"/user", "alice", nil); a.status != http.StatusOK {
		t.Fatalf("a refused token, refreshed: %d %s", a.status, a.body)
	}
	creds := r.api.Credentials()
	if len(creds) != 2 || creds[0] != "Bearer "+old || creds[1] == creds[0] {
		t.Fatalf("the connector saw %v", creds)
	}
	fresh := creds[1]
	r.api.Refuse(fresh)
	a := r.send(http.MethodPost, address(c, "http")+"/repos/acme/app/issues", "alice", strings.NewReader(`{"title":"x"}`))
	if a.status != http.StatusUnauthorized || a.header.Get("WWW-Authenticate") != "" || !bytes.Contains(a.body, []byte("Bad credentials")) {
		t.Fatalf("a refused request with a body: %d %v %s", a.status, a.header, a.body)
	}
	if a := r.send(http.MethodGet, address(c, "http")+"/user", "alice", nil); a.status != http.StatusOK {
		t.Fatalf("the next request after a refresh: %d %s", a.status, a.body)
	}
	creds = r.api.Credentials()
	if creds[len(creds)-1] == fresh || len(creds) != 4 {
		t.Fatalf("the next request did not use the refreshed credential: %v", creds)
	}
	r.api.Refuse()
	a = r.send(http.MethodGet, address(c, "http")+"/user", "alice", nil)
	if a.status != http.StatusConflict || a.detail("reason") != store.ReasonRevoked || a.detail("state") != string(store.StateNeedsReconnect) {
		t.Fatalf("a second refusal: %d %s", a.status, a.body)
	}
	if row, err := r.st.Connections().Get(t.Context(), c.ID); err != nil || row.State != store.StateNeedsReconnect || row.Reason != store.ReasonRevoked {
		t.Fatalf("the connection %+v %v", row, err)
	}
	r.api.Accept()

	// A key is moved at once.
	k := r.keyed()
	r.api.Refuse("Bearer the-key-of-alice-0001")
	a = r.send(http.MethodGet, address(k, "http")+"/user", "alice", nil)
	if a.status != http.StatusConflict || a.detail("reason") != store.ReasonCredentialRefused {
		t.Fatalf("a refused key: %d %s", a.status, a.body)
	}
	if a := r.send(http.MethodGet, address(k, "http")+"/user", "alice", nil); a.status != http.StatusConflict || a.detail("state") != string(store.StateNeedsReconnect) {
		t.Fatalf("a connection that needs a reconnect: %d %s", a.status, a.body)
	}
	r.api.Accept()

	// An oauth credential with no refresh token moves with revoked.
	norefresh := r.connect("bob", "signed", store.Secrets{AccessToken: "an-access-token-of-bob"}, store.Meta{TokenEndpoint: r.auth.TokenURL(), ClientID: "pons-client"})
	r.api.Refuse("Bearer an-access-token-of-bob")
	if a := r.send(http.MethodGet, address(norefresh, "http")+"/user", "bob", nil); a.status != http.StatusConflict || a.detail("reason") != store.ReasonRevoked {
		t.Fatalf("no refresh token: %d %s", a.status, a.body)
	}
	r.api.Accept()

	// A client's token is minted anew once, and a second refusal moves it.
	r.auth.AddClient("wh-client", "the-client-secret-01")
	m := r.connect("carol", "minted", store.Secrets{ClientSecret: "the-client-secret-01"}, store.Meta{ClientID: "wh-client", TokenEndpoint: r.auth.TokenURL(), Scopes: []string{"read"}})
	if a := r.send(http.MethodGet, address(m, "http")+"/user", "carol", nil); a.status != http.StatusOK {
		t.Fatalf("a minted token: %d %s", a.status, a.body)
	}
	first := r.api.Credentials()[len(r.api.Credentials())-1]
	r.api.Refuse(first)
	if a := r.send(http.MethodGet, address(m, "http")+"/user", "carol", nil); a.status != http.StatusOK {
		t.Fatalf("a token minted anew: %d %s", a.status, a.body)
	}
	if a := r.send(http.MethodPut, address(m, "http")+"/upload", "carol", strings.NewReader("x")); a.status != http.StatusOK {
		t.Fatalf("a request with a body and a kept token: %d %s", a.status, a.body)
	}
	r.api.Refuse()
	if a := r.send(http.MethodPost, address(m, "http")+"/repos/acme/app/issues", "carol", strings.NewReader("x")); a.status != http.StatusUnauthorized {
		t.Fatalf("a refused request of a client with a body: %d %s", a.status, a.body)
	}
	if a := r.send(http.MethodGet, address(m, "http")+"/user", "carol", nil); a.status != http.StatusConflict || a.detail("reason") != store.ReasonCredentialRefused {
		t.Fatalf("a client refused twice: %d %s", a.status, a.body)
	}
	r.api.Accept()

	// No credential: the 401 passes, less its challenge.
	open := r.connect("dave", "open", store.Secrets{}, store.Meta{})
	r.api.Refuse("")
	if a := r.send(http.MethodGet, address(open, "http")+"/user", "dave", nil); a.status != http.StatusUnauthorized || a.header.Get("WWW-Authenticate") != "" {
		t.Fatalf("a connector with no credential: %d %v", a.status, a.header)
	}
}

// Each forwarded request leaves one record with its method, its path or
// git service, and a push its count of refs.
func TestForwardedRequestsAreRecorded(t *testing.T) {
	r := newRig(t, false)
	c := r.keyed()
	r.send(http.MethodGet, address(c, "http")+"/repos/acme/app/issues?token=never-kept", "agent", nil)
	r.send(http.MethodPost, address(c, "http")+"/repos/acme/app/issues", "alice", strings.NewReader(`{"title":"argument never kept"}`))
	r.az.set(authorizer.Limits{ReadOnly: true})
	r.send(http.MethodDelete, address(c, "http")+"/repos/acme/app", "alice", nil)
	r.send(http.MethodDelete, address(c, "http")+"/repos/acme/app", "alice", nil)
	r.az.set(authorizer.Limits{})
	r.send(http.MethodGet, address(c, "http")+"/redirect/elsewhere", "alice", nil)
	r.send(http.MethodGet, address(c, "http")+"/user", "bob", nil)
	got := r.calls(c)
	if len(got) != 5 {
		t.Fatalf("%d records: %+v", len(got), got)
	}
	want := []struct{ method, tool, effect, outcome string }{
		{http.MethodGet, "/repos/acme/app/issues", "read", OutcomeOK},
		{http.MethodPost, "/repos/acme/app/issues", "write", OutcomeOK},
		{http.MethodDelete, "/repos/acme/app", "write", OutcomeDenied},
		{http.MethodGet, "/redirect/elsewhere", "read", OutcomeUpstreamError},
		{http.MethodGet, "/user", "read", OutcomeDenied},
	}
	for i, w := range want {
		g := got[i]
		if g.Method != w.method || g.Tool != w.tool || g.Effect != w.effect || g.Outcome != w.outcome || g.Connector != "api" || g.Owner != subject("alice") {
			t.Errorf("record %d: %+v, want %+v", i, g, w)
		}
	}
	if got[0].Session != "ses_01" || got[0].Subject != subject("agent") || got[0].Status != http.StatusOK || got[0].BytesOut == 0 {
		t.Errorf("the first record %+v", got[0])
	}
	if got[1].BytesIn != int64(len(`{"title":"argument never kept"}`)) || got[1].Status != http.StatusCreated {
		t.Errorf("the write's record %+v", got[1])
	}
	if got[4].Subject != subject("bob") {
		t.Errorf("a deny of another subject %+v", got[4])
	}
	dump := string(r.st.Dump())
	for _, never := range []string{"never-kept", "argument never kept", "the-key-of-alice-0001"} {
		if strings.Contains(dump, never) {
			t.Fatalf("%q is at rest", never)
		}
	}
	if row, err := r.st.Connections().Get(t.Context(), c.ID); err != nil || row.LastUsedAt.IsZero() {
		t.Fatalf("the last use was not written: %+v %v", row, err)
	}
	// A request that names no connection, and a failure of Pons's own,
	// leave none.
	r.send(http.MethodGet, "/v1/connections/con_nothing/http/user", "alice", nil)
	r.az.out(true)
	if a := r.send(http.MethodGet, address(c, "http")+"/user", "alice", nil); a.status != http.StatusServiceUnavailable {
		t.Fatalf("an outage: %d", a.status)
	}
	r.az.out(false)
	if n := len(r.calls(c)); n != 5 {
		t.Fatalf("%d records after an unknown id and an outage", n)
	}
	if !slices.ContainsFunc(strings.Split(r.logs.String(), "\n"), func(l string) bool { return strings.Contains(l, `"msg":"a call ended"`) }) {
		t.Fatal("no line for a call that ended")
	}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// countPath counts the requests to one path.
func countPath(requests []stubs.APIRequest, path string) int {
	n := 0
	for _, q := range requests {
		if q.Path == path {
			n++
		}
	}
	return n
}
