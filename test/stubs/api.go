// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package stubs

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// API is the stub API: a small JSON API in a code host's manner, behind a
// connector of kind http (specs/014-http-forwarding.md). It serves a root
// document, a user, a list of issues paged with a Link header, a write that
// records its body, a redirect within and one elsewhere, an answer with
// headers of every kind, an upload that counts what arrived, and a large
// answer. It records every request with the credential it carried.
//
// Its switches: Refuse answers 401 to the credentials named, Slow delays the
// headers of every answer, and Protect makes it a protected resource that
// challenges a request with no credential and serves its metadata.
type API struct {
	url  string
	port int

	mu        sync.Mutex
	requests  []APIRequest
	refused   map[string]bool
	refuseAll bool
	slow      time.Duration
	login     string
	servers   []string // the authorization servers of Protect; nil when off
	scopes    []string
	received  int64
	needs     []string // the scopes of an insufficient_scope challenge; nil when off
}

// APIRequest is one request the stub API served.
type APIRequest struct {
	Method string
	Path   string
	Query  string
	Header http.Header
	// Credential is the Authorization header the request carried.
	Credential string
	// Body is the body of a write, at most 64 KiB of it; Size is its whole
	// size.
	Body []byte
	Size int64
}

// APIOption configures the stub API.
type APIOption func(*apiConfig)

type apiConfig struct{ name string }

// WithAPIName is the name the stub answers under, api.example.com by
// default.
func WithAPIName(name string) APIOption { return func(c *apiConfig) { c.name = name } }

// NewAPI starts a stub API for the test.
func NewAPI(t TB, opts ...APIOption) *API {
	t.Helper()
	cfg := apiConfig{name: "api." + Domain}
	for _, o := range opts {
		o(&cfg)
	}
	a := &API{refused: map[string]bool{}, login: "octo-person"}
	srv := serveTLS(t, http.HandlerFunc(a.serve), cfg.name)
	a.port = portOf(srv.URL)
	a.url = named(cfg.name, a.port)
	return a
}

// URL is the API's base, by its name: the value of a catalog entry's url.
func (a *API) URL() string { return a.url }

// Port is the port the stub listens on.
func (a *API) Port() int { return a.port }

// SetLogin sets the login GET /user answers, octo-person by default.
func (a *API) SetLogin(login string) {
	a.mu.Lock()
	a.login = login
	a.mu.Unlock()
}

// Refuse answers 401 to every request that carries one of the
// credentials, the whole Authorization header; with none named it refuses
// every request.
func (a *API) Refuse(credentials ...string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(credentials) == 0 {
		a.refuseAll = true
	}
	for _, c := range credentials {
		a.refused[c] = true
	}
}

// Accept ends every refusal.
func (a *API) Accept() {
	a.mu.Lock()
	a.refuseAll, a.refused = false, map[string]bool{}
	a.mu.Unlock()
}

// Slow delays the headers of every answer by d.
func (a *API) Slow(d time.Duration) {
	a.mu.Lock()
	a.slow = d
	a.mu.Unlock()
}

// Protect makes the API a protected resource (RFC 9728): a request with no
// credential is answered 401 with a challenge naming the metadata and the
// scopes, and the metadata names the authorization servers.
func (a *API) Protect(scopes []string, servers ...string) {
	a.mu.Lock()
	a.servers, a.scopes = servers, scopes
	a.mu.Unlock()
}

// Insufficient answers every request 403 with a challenge for more scopes
// (RFC 6750, section 3.1), while scopes is not nil.
func (a *API) Insufficient(scopes []string) {
	a.mu.Lock()
	a.needs = scopes
	a.mu.Unlock()
}

// Requests is every request served, in order.
func (a *API) Requests() []APIRequest {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]APIRequest(nil), a.requests...)
}

// Credentials is the credential every request carried, in order.
func (a *API) Credentials() []string {
	var out []string
	for _, r := range a.Requests() {
		out = append(out, r.Credential)
	}
	return out
}

// Received is how many bytes of an upload's body have arrived so far.
func (a *API) Received() int64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.received
}

// maxRecordedBody bounds what of a write's body is kept.
const maxRecordedBody = 64 << 10

func (a *API) serve(w http.ResponseWriter, r *http.Request) {
	rec := APIRequest{
		Method: r.Method, Path: r.URL.EscapedPath(), Query: r.URL.RawQuery,
		Header: r.Header.Clone(), Credential: r.Header.Get("Authorization"),
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead && r.URL.Path != "/upload" {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "the body did not read", http.StatusBadRequest)
			return
		}
		rec.Size = int64(len(body))
		rec.Body = body[:min(len(body), maxRecordedBody)]
	}
	a.mu.Lock()
	a.requests = append(a.requests, rec)
	refused := a.refuseAll || a.refused[rec.Credential]
	slow, login, servers, scopes, needs := a.slow, a.login, a.servers, a.scopes, a.needs
	a.mu.Unlock()
	if slow > 0 {
		select {
		case <-time.After(slow):
		case <-r.Context().Done():
			return
		}
	}
	if r.URL.Path == "/.well-known/oauth-protected-resource" && servers != nil {
		writeStubJSON(w, http.StatusOK, map[string]any{
			"resource": a.url, "authorization_servers": servers, "scopes_supported": scopes,
		})
		return
	}
	switch {
	case servers != nil && rec.Credential == "":
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata=%q, scope=%q`,
			a.url+"/.well-known/oauth-protected-resource", strings.Join(scopes, " ")))
		writeStubJSON(w, http.StatusUnauthorized, map[string]any{"message": "Requires authentication"})
		return
	case refused:
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		writeStubJSON(w, http.StatusUnauthorized, map[string]any{"message": "Bad credentials"})
		return
	case needs != nil:
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer error="insufficient_scope", scope=%q`, strings.Join(needs, " ")))
		writeStubJSON(w, http.StatusForbidden, map[string]any{"message": "Insufficient scope"})
		return
	}
	a.route(w, r, rec, login)
}

// route answers a request the stub accepted.
func (a *API) route(w http.ResponseWriter, r *http.Request, rec APIRequest, login string) {
	path := r.URL.Path
	switch {
	case path == "/" && r.Method == http.MethodGet:
		writeStubJSON(w, http.StatusOK, map[string]any{"current_user_url": a.url + "/user"})
	case path == "/user":
		writeStubJSON(w, http.StatusOK, map[string]any{"login": login, "id": 1})
	case strings.HasPrefix(path, "/repos/") && strings.HasSuffix(path, "/issues"):
		a.issues(w, r, rec)
	case path == "/redirect/within":
		w.Header().Set("Location", a.url+"/user")
		w.WriteHeader(http.StatusFound)
	case path == "/redirect/elsewhere":
		w.Header().Set("Location", "https://elsewhere.example.net/user")
		w.WriteHeader(http.StatusFound)
	case path == "/headers":
		h := w.Header()
		h.Set("Set-Cookie", "session=stub; Secure")
		h.Set("WWW-Authenticate", `Bearer realm="stub"`)
		h.Set("ETag", `"v1"`)
		h.Set("Cache-Control", "private, max-age=60")
		h.Set("Last-Modified", "Mon, 12 Oct 2026 10:00:00 GMT")
		h.Set("Retry-After", "7")
		h.Set("X-RateLimit-Remaining", "4999")
		h.Set("X-Stub-Private", "kept")
		writeStubJSON(w, http.StatusOK, map[string]any{"ok": true})
	case path == "/upload":
		a.upload(w, r)
	case path == "/stream":
		a.stream(w, r)
	case path == "/large":
		n, err := strconv.Atoi(r.URL.Query().Get("bytes"))
		if err != nil || n < 0 {
			http.Error(w, "bytes is not a count", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(n))
		chunk := make([]byte, 32<<10)
		for n > 0 {
			k := min(n, len(chunk))
			if _, err := w.Write(chunk[:k]); err != nil {
				return
			}
			n -= k
		}
	default:
		writeStubJSON(w, http.StatusNotFound, map[string]any{"message": "Not Found"})
	}
}

// issues lists a repository's issues, paged with a Link header whose next
// and last pages are on the API and whose help is elsewhere, or files one.
func (a *API) issues(w http.ResponseWriter, r *http.Request, rec APIRequest) {
	base := a.url + r.URL.Path
	if r.Method == http.MethodPost {
		writeStubJSON(w, http.StatusCreated, map[string]any{"number": 2, "url": base + "/2", "bytes": rec.Size})
		return
	}
	page := r.URL.Query().Get("page")
	if page == "" {
		page = "1"
	}
	w.Header().Set("Link", fmt.Sprintf(`<%s?page=2>; rel="next", <%s?page=3>; rel="last", <https://elsewhere.example.net/help>; rel="help"`, base, base))
	writeStubJSON(w, http.StatusOK, []map[string]any{{"number": 1, "page": page, "url": base + "/1"}})
}

// stream writes chunks of a stream, each flushed, with a gap between two:
// a stream a test makes go silent.
func (a *API) stream(w http.ResponseWriter, r *http.Request) {
	chunks, err := strconv.Atoi(r.URL.Query().Get("chunks"))
	if err != nil {
		http.Error(w, "chunks is not a count", http.StatusBadRequest)
		return
	}
	gap, err := time.ParseDuration(r.URL.Query().Get("gap"))
	if err != nil {
		http.Error(w, "gap is not a duration", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	rc := http.NewResponseController(w)
	for i := range chunks {
		if i > 0 {
			select {
			case <-time.After(gap):
			case <-r.Context().Done():
				return
			}
		}
		if _, err := fmt.Fprintf(w, "data: %d\n\n", i); err != nil {
			return
		}
		if err := rc.Flush(); err != nil {
			return
		}
	}
}

// upload reads the body in pieces, counting each as it arrives, so a test
// sees a body reach the stub before its sender has finished.
func (a *API) upload(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	a.received = 0
	a.mu.Unlock()
	buf := make([]byte, 4<<10)
	var total int64
	for {
		n, err := r.Body.Read(buf)
		total += int64(n)
		a.mu.Lock()
		a.received = total
		a.mu.Unlock()
		if err == io.EOF {
			break
		}
		if err != nil {
			return
		}
	}
	writeStubJSON(w, http.StatusOK, map[string]any{"bytes": total})
}

// writeStubJSON answers a JSON value. The headers are out before the body
// is encoded, so a write that fails is a client that went away, and no
// answer is left to tell it.
func writeStubJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
