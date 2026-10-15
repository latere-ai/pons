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

	"latere.ai/x/pons/internal/apierr"

	"latere.ai/x/pkg/authz"
	"latere.ai/x/pkg/health"
	"latere.ai/x/pkg/otel"
	"latere.ai/x/pkg/ratelimit"

	"latere.ai/x/pons/api"
	"latere.ai/x/pons/catalog"
	"latere.ai/x/pons/internal/access"
	"latere.ai/x/pons/internal/carry"
	"latere.ai/x/pons/internal/id"
	"latere.ai/x/pons/internal/signin"
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

	// MaxConnectionsPerOwner, MaxAddedConnectors and CreatesPerMinute are
	// the installation's limits, which hold whatever the authorizer
	// answers.
	MaxConnectionsPerOwner int
	MaxAddedConnectors     int
	CreatesPerMinute       int

	// Ready are the readiness checks of /readyz beside the store's:
	// sealing and the catalog, named.
	Ready []health.Check
	// AllowPrivate says the dialer treats every address as public, which
	// /readyz carries.
	AllowPrivate bool

	// Carrier serves the MCP, forwarding and git addresses of connections,
	// and probes a key. Signin signs people in at the other service.
	Carrier *carry.Carrier
	Signin  *signin.Signin

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
	{http.MethodPatch, "/connectors/{id}", (*Server).editConnector},
	{http.MethodDelete, "/connectors/{id}", (*Server).removeConnector},
	{http.MethodPost, "/connections", (*Server).createConnection},
	{http.MethodGet, "/connections", (*Server).listConnections},
	{http.MethodGet, "/connections/{id}", (*Server).readConnection},
	{http.MethodPatch, "/connections/{id}", (*Server).renameConnection},
	{http.MethodPost, "/connections/{id}/confirm", (*Server).confirm},
	{http.MethodPost, "/connections/{id}/reconnect", (*Server).reconnect},
	{http.MethodPut, "/connections/{id}/credential", (*Server).replaceCredential},
	{http.MethodDelete, "/connections/{id}", (*Server).deleteConnection},
	{http.MethodGet, "/connections/{id}/calls", (*Server).listCalls},
	{http.MethodGet, "/connections/{id}/tools", (*Server).listTools},
}

// Route is one route the server serves, as the contract spells it below
// the base path.
type Route struct{ Method, Path string }

// carried are the routes of the carrier: the MCP address takes POST, and
// GET and DELETE for a connector of an earlier protocol revision
// (specs/008-carrying-a-call.md); the forwarding address takes every method
// OpenAPI names but TRACE, and the git address git's smart HTTP alone
// (specs/014-http-forwarding.md).
var carried = []Route{
	{http.MethodPost, "/connections/{id}/mcp"},
	{http.MethodGet, "/connections/{id}/mcp"},
	{http.MethodDelete, "/connections/{id}/mcp"},
	{http.MethodGet, "/connections/{id}/http/{path}"},
	{http.MethodPut, "/connections/{id}/http/{path}"},
	{http.MethodPost, "/connections/{id}/http/{path}"},
	{http.MethodDelete, "/connections/{id}/http/{path}"},
	{http.MethodOptions, "/connections/{id}/http/{path}"},
	{http.MethodHead, "/connections/{id}/http/{path}"},
	{http.MethodPatch, "/connections/{id}/http/{path}"},
	{http.MethodGet, "/connections/{id}/git/{path}"},
	{http.MethodPost, "/connections/{id}/git/{path}"},
}

// Routes lists every route the server serves below the base path, the
// carrier's and the contract itself included.
func Routes() []Route {
	out := make([]Route, 0, len(routes)+len(carried)+len(public))
	for _, rt := range routes {
		out = append(out, Route{rt.method, rt.path})
	}
	out = append(out, carried...)
	return append(out, public...)
}

// public are the routes that take no token: where the other service returns
// a person's browser, the documents that name Pons to an authorization
// server, and the contract.
var public = []Route{
	{http.MethodGet, "/callback"},
	{http.MethodGet, "/callback/{key}"},
	{http.MethodGet, "/client"},
	{http.MethodGet, "/client/{id}"},
	{http.MethodGet, "/openapi.yaml"},
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
	mux.HandleFunc("GET "+b+"/callback", s.callback)
	mux.HandleFunc("GET "+b+"/callback/{key}", s.callback)
	mux.HandleFunc("GET "+b+"/client", s.clientDocument)
	mux.HandleFunc("GET "+b+"/client/{id}", s.clientDocument)
	mux.HandleFunc("GET "+b+"/openapi.yaml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/yaml")
		if _, err := w.Write(api.OpenAPI); err != nil {
			s.log().WarnContext(r.Context(), "the contract was not written whole", "error", err.Error())
		}
	})
	// The carrier's addresses are served before the router, which would
	// clean a path's dot segments and repeated slashes and decode its
	// escapes before the carrier could refuse them.
	front := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.Carrier != nil && s.Carrier.Handles(r) {
			r.Pattern = s.Carrier.Pattern(r)
			s.Carrier.ServeHTTP(w, r)
			return
		}
		mux.ServeHTTP(w, r)
	})
	return otel.Handler(front, "ponsd",
		otel.WithRouteTemplate(func(r *http.Request) string { return r.Pattern }),
		otel.WithSkip(func(r *http.Request) bool { return !strings.HasPrefix(r.URL.Path, b+"/") }))
}

// authenticated runs a route for a verified caller and answers its error.
func (s *Server) authenticated(h func(http.ResponseWriter, *http.Request, access.Caller) error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := s.Auth.Authenticate(r)
		if err != nil {
			s.answer(w, r, apierr.Token(err))
			return
		}
		if err := h(w, r, c); err != nil {
			s.answer(w, r, err)
		}
	})
}

// answer writes an error. An error nobody classified is logged with its
// text, any URL in it cut to its scheme, host and path, and answered as
// internal with no detail.
func (s *Server) answer(w http.ResponseWriter, r *http.Request, err error) {
	if e := apierr.Write(w, err); e.Code == apierr.CodeInternal {
		s.log().ErrorContext(r.Context(), "a request failed", "route", r.Pattern, "error", apierr.LogText(e.Cause()))
	}
}

// ask asks one question and turns its failure into the route's error.
func (s *Server) ask(r *http.Request, c access.Caller, action string, res authz.Resource) (access.Decision, error) {
	d, err := s.Authz.Authorize(r.Context(), c, access.Ask(r, action, res))
	switch {
	case errors.Is(err, access.ErrUnavailable):
		s.log().WarnContext(r.Context(), "the authorizer gave no decision", "route", r.Pattern, "error", apierr.LogText(err))
		return access.Decision{}, apierr.Fail(apierr.CodeAuthorizerUnavailable, "")
	case err != nil:
		return access.Decision{}, apierr.Internal(err)
	}
	return d, nil
}

// forbidden is the refusal of a deny of a create or a list, with the
// authorizer's reason as the detail.
func forbidden(d access.Decision) error { return apierr.Fail(apierr.CodeForbidden, d.Reason) }

// limited holds a subject to the creates it may make in a minute: an add, a
// connect and a reconnect each fetch discovery documents.
func (s *Server) limited(c access.Caller) error {
	if a := s.creates.Allow(c.Subject); !a.OK {
		return apierr.Fail(apierr.CodeRateLimited, "creates_per_minute="+strconv.Itoa(s.CreatesPerMinute))
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
		s.log().WarnContext(ctx, "the store is not ready", "error", apierr.LogText(err))
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
