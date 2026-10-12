// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package httpapi serves the contract of specs/003-api.md: the catalog,
// connections, their records, the probes and the contract itself. Every
// route below the base path but the public documents authenticates, builds
// the resource from the request and the stored object, asks one question,
// and acts within the decision (specs/004-identity-and-authorization.md).
// An error has one code, one fixed sentence for a person, and the developer
// detail apart.
package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"latere.ai/x/pkg/authz"
	"latere.ai/x/pkg/health"
	"latere.ai/x/pkg/httpjson"
	"latere.ai/x/pkg/otel"
	"latere.ai/x/pkg/ratelimit"

	"latere.ai/x/pons/api"
	"latere.ai/x/pons/catalog"
	"latere.ai/x/pons/internal/access"
	"latere.ai/x/pons/internal/id"
	"latere.ai/x/pons/internal/store"
	"latere.ai/x/pons/internal/version"
)

// maxBodyBytes bounds a request body of the API's own routes. A body of a
// call to a connection's address is the carrier's to bound.
const maxBodyBytes = 64 << 10

// Server is the API of one process.
type Server struct {
	Store   store.Store
	Sealer  store.Sealer
	Catalog catalog.Catalog
	// Auth verifies a caller and Authz answers its questions.
	Auth  access.Authenticator
	Authz access.Authorizer

	// PublicURL is where other services and browsers reach Pons, and
	// BasePath the prefix of every route; an address Pons hands out is the
	// two joined with the route.
	PublicURL string
	BasePath  string

	// MaxConnectionsPerOwner and CreatesPerMinute are the installation's
	// limits, which hold whatever the authorizer answers.
	MaxConnectionsPerOwner int
	CreatesPerMinute       int

	// Ready are the readiness checks of /readyz beside the store's:
	// sealing and the catalog, named.
	Ready []health.Check
	// AllowPrivate says the dialer treats every address as public, which
	// /readyz carries.
	AllowPrivate bool

	Log *slog.Logger
	// IDs makes identifiers. Nil takes id.Default.
	IDs *id.Generator

	creates *ratelimit.Buckets
}

func (s *Server) newID(prefix string) string {
	if s.IDs != nil {
		return s.IDs.New(prefix)
	}
	return id.New(prefix)
}

func (s *Server) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

// route is one route of the contract this server serves, below the base
// path, with the handler that serves it for a verified caller.
type route struct {
	method, path string
	handle       func(*Server, http.ResponseWriter, *http.Request, access.Caller) error
}

// routes are the routes of specs/003-api.md built so far, in the
// contract's order. GET /openapi.yaml is served beside them and takes no
// token.
var routes = []route{
	{http.MethodGet, "/connectors", (*Server).listConnectors},
	{http.MethodGet, "/connectors/{ref}", (*Server).readConnector},
	{http.MethodPost, "/connectors", (*Server).addConnector},
	{http.MethodDelete, "/connectors/{id}", (*Server).removeConnector},
	{http.MethodPost, "/connections", (*Server).createConnection},
	{http.MethodGet, "/connections", (*Server).listConnections},
	{http.MethodGet, "/connections/{id}", (*Server).readConnection},
	{http.MethodPatch, "/connections/{id}", (*Server).renameConnection},
	{http.MethodPut, "/connections/{id}/credential", (*Server).replaceCredential},
	{http.MethodDelete, "/connections/{id}", (*Server).deleteConnection},
	{http.MethodGet, "/connections/{id}/calls", (*Server).listCalls},
}

// Route is one route the server serves, as the contract spells it below
// the base path.
type Route struct{ Method, Path string }

// Routes lists every route the server serves below the base path, the
// contract itself included.
func Routes() []Route {
	out := make([]Route, 0, len(routes)+1)
	for _, rt := range routes {
		out = append(out, Route{rt.method, rt.path})
	}
	return append(out, Route{http.MethodGet, "/openapi.yaml"})
}

// Handler is the whole surface: the probes at the root and the API below
// the base path.
func (s *Server) Handler() http.Handler {
	s.creates = ratelimit.New(ratelimit.Config{PerMinute: s.CreatesPerMinute})
	mux := http.NewServeMux()
	probes := s.probes()
	for _, p := range []string{"GET /livez", "GET /readyz", "GET /version"} {
		mux.Handle(p, probes)
	}
	b := s.BasePath
	for _, rt := range routes {
		handle := rt.handle
		mux.Handle(rt.method+" "+b+rt.path, s.authenticated(func(w http.ResponseWriter, r *http.Request, c access.Caller) error {
			return handle(s, w, r, c)
		}))
	}
	mux.HandleFunc("GET "+b+"/openapi.yaml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/yaml")
		if _, err := w.Write(api.OpenAPI); err != nil {
			s.log().WarnContext(r.Context(), "the contract was not written whole", "error", err.Error())
		}
	})
	return otel.Handler(mux, "ponsd",
		otel.WithRouteTemplate(func(r *http.Request) string { return r.Pattern }),
		otel.WithSkip(func(r *http.Request) bool { return !strings.HasPrefix(r.URL.Path, b+"/") }))
}

// authenticated runs a route for a verified caller and answers its error.
func (s *Server) authenticated(h func(http.ResponseWriter, *http.Request, access.Caller) error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := s.Auth.Authenticate(r)
		if err != nil {
			s.answer(w, r, tokenError(err))
			return
		}
		if err := h(w, r, c); err != nil {
			s.answer(w, r, err)
		}
	})
}

// tokenError is the route error of a refused bearer.
func tokenError(err error) error {
	var te *access.TokenError
	switch {
	case errors.Is(err, access.ErrMissingToken):
		return fail(CodeMissingToken, "")
	case errors.As(err, &te):
		e := fail(CodeInvalidToken, te.Reason)
		e.Retryable = &te.Retryable
		return e
	}
	return internal(err)
}

// answer writes an error. An error nobody classified is logged with its
// text, any URL in it cut to its scheme, host and path, and answered as
// internal with no detail.
func (s *Server) answer(w http.ResponseWriter, r *http.Request, err error) {
	e := classify(err)
	status, body := e.envelope()
	if body.Code == CodeInternal {
		cause := e.cause
		if cause == nil {
			cause = err
		}
		s.log().ErrorContext(r.Context(), "a request failed", "route", r.Pattern, "error", logText(cause))
	}
	if body.Code == CodeRateLimited {
		w.Header().Set("Retry-After", "1")
	}
	httpjson.WriteError(w, status, body)
}

// ask asks one question and turns its failure into the route's error.
func (s *Server) ask(r *http.Request, c access.Caller, action string, res authz.Resource) (access.Decision, error) {
	d, err := s.Authz.Authorize(r.Context(), c, access.Ask(r, action, res))
	switch {
	case errors.Is(err, access.ErrUnavailable):
		s.log().WarnContext(r.Context(), "the authorizer gave no decision", "route", r.Pattern, "error", logText(err))
		return access.Decision{}, fail(CodeAuthorizerUnavailable, "")
	case err != nil:
		return access.Decision{}, internal(err)
	}
	return d, nil
}

// forbidden is the refusal of a deny of a create or a list, with the
// authorizer's reason as the detail.
func forbidden(d access.Decision) error { return fail(CodeForbidden, d.Reason) }

// limited holds a subject to the creates it may make in a minute: an add, a
// connect and a reconnect each fetch discovery documents.
func (s *Server) limited(c access.Caller) error {
	if a := s.creates.Allow(c.Subject); !a.OK {
		return fail(CodeRateLimited, "creates_per_minute="+strconv.Itoa(s.CreatesPerMinute))
	}
	return nil
}

// probes serve /livez, /readyz and /version. /readyz is ready when the
// store answers and every other check holds, and carries a line saying so
// while the dialer treats every address as public.
func (s *Server) probes() http.Handler {
	checks := append([]health.Check{{Name: "store", Run: s.storeReady}}, s.Ready...)
	inner := health.Handler(health.Options{
		Ready: health.Checks(checks...), Timeout: time.Second,
		Version: version.Version, Commit: version.Commit, BuildTime: version.Date,
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/readyz" || !s.AllowPrivate {
			inner.ServeHTTP(w, r)
			return
		}
		rec := &status{ResponseWriter: w}
		inner.ServeHTTP(rec, r)
		if rec.code == http.StatusOK {
			if _, err := w.Write([]byte("dial: private addresses allowed\n")); err != nil {
				s.log().WarnContext(r.Context(), "the readiness line was not written", "error", err.Error())
			}
		}
	})
}

// storeReady is the store's check, which names no address: a driver's
// error can hold one, so it is logged and not answered.
func (s *Server) storeReady(ctx context.Context) error {
	if err := s.Store.Ready(ctx); err != nil {
		s.log().WarnContext(ctx, "the store is not ready", "error", logText(err))
		return errors.New("the store does not answer")
	}
	return nil
}

// status records the status a handler wrote.
type status struct {
	http.ResponseWriter
	code int
}

func (s *status) WriteHeader(code int) {
	s.code = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *status) Write(b []byte) (int, error) {
	if s.code == 0 {
		s.code = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}
