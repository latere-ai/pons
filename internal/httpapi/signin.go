// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"

	"latere.ai/x/pons/authorizer"
	"latere.ai/x/pons/catalog"
	"latere.ai/x/pons/internal/access"
	"latere.ai/x/pons/internal/apierr"
	"latere.ai/x/pons/internal/signin"
	"latere.ai/x/pons/internal/store"
)

// startedView is the answer to a connect or a reconnect of a connector
// whose people sign in: the connection, pending, and the address to send
// the person's browser to.
type startedView struct {
	Connection       connectionView `json:"connection"`
	AuthorizationURL string         `json:"authorization_url"`
}

// returnTo holds a return_to to PONS_RETURN_URLS (specs/007-sign-in.md).
func (s *Server) returnTo(v string) error {
	switch {
	case v == "":
		return apierr.OnField(apierr.CodeMissingField, "return_to", "")
	case !signin.ReturnAllowed(v, s.Signin.ReturnURLs):
		return apierr.OnField(apierr.CodeInvalidField, "return_to", "not_a_return_url")
	}
	return nil
}

// start begins a sign-in for a stored connection: a new flow, which
// replaces a live one, and the answer with the address to send the person
// to.
func (s *Server) start(w http.ResponseWriter, r *http.Request, row store.Connection, plan signin.Plan, returnTo string, status int) error {
	address, flow, err := s.Signin.Begin(row, plan, returnTo)
	if err != nil {
		return err
	}
	if err := s.Store.Flows().Put(r.Context(), flow); err != nil {
		return apierr.Internal(err)
	}
	return s.writeStarted(w, r, row.ID, address, status)
}

// writeStarted answers a connection with the address of its sign-in.
func (s *Server) writeStarted(w http.ResponseWriter, r *http.Request, connID, address string, status int) error {
	row, err := s.Store.Connections().Get(r.Context(), connID)
	if err != nil {
		return apierr.Internal(err)
	}
	v, err := s.connectionOf(r.Context(), row)
	if err != nil {
		return apierr.Internal(err)
	}
	return write(w, status, startedView{Connection: v, AuthorizationURL: address})
}

// connectBySignIn is POST /connections for a connector whose people sign
// in: discovery, a pending connection with its flow in one transaction, and
// the address to send the person to. A repeat of the request's
// Idempotency-Key answers the same connection with a new flow.
func (s *Server) connectBySignIn(w http.ResponseWriter, r *http.Request, c access.Caller, conn connector, row store.Connection, req connectRequest, limit int) error {
	if conn.added != nil {
		// A connector a person added signs in through the MCP probe, which
		// comes with the MCP carrier.
		return apierr.Fail(apierr.CodeSignInUnsupported, "sign_in_not_available")
	}
	ctx := r.Context()
	plan, err := s.Signin.Discover(ctx, conn.signin(), req.Scopes)
	if err != nil {
		return err
	}
	row.State = store.StatePending
	address, flow, err := s.Signin.Begin(row, plan, req.ReturnTo)
	if err != nil {
		return err
	}
	made, err := s.idempotent(r, c, r.Header.Get("Idempotency-Key"), routeConnect, row.ID, func(tx store.Tx) error {
		if err := tx.Connections().Create(ctx, row, limit); err != nil {
			return err
		}
		return tx.Flows().Put(ctx, flow)
	})
	if err != nil {
		return err
	}
	if made == row.ID {
		return s.writeStarted(w, r, made, address, http.StatusCreated)
	}
	stored, err := s.Store.Connections().Get(ctx, made)
	if err != nil {
		return apierr.Internal(err)
	}
	if stored.State != store.StatePending {
		return s.writeConnection(w, r, made, http.StatusCreated)
	}
	return s.start(w, r, stored, plan, req.ReturnTo, http.StatusCreated)
}

// confirmRequest is the body of POST /connections/{id}/confirm.
type confirmRequest struct {
	Code string `json:"code"`
}

// confirm is POST /connections/{id}/confirm: it asks connection.create for
// the connection's owner and makes the connection usable with the code the
// browser brought back.
func (s *Server) confirm(w http.ResponseWriter, r *http.Request, c access.Caller) error {
	var req confirmRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	if req.Code == "" {
		return apierr.OnField(apierr.CodeMissingField, "code", "")
	}
	row, err := s.stored(r, c, authorizer.ActionConnectionCreate)
	if err != nil {
		return err
	}
	if err := s.Signin.Confirm(r.Context(), row, req.Code); err != nil {
		return err
	}
	return s.writeConnection(w, r, row.ID, http.StatusOK)
}

// reconnectRequest is the body of POST /connections/{id}/reconnect.
type reconnectRequest struct {
	ReturnTo string   `json:"return_to"`
	Scopes   []string `json:"scopes"`
}

// reconnect is POST /connections/{id}/reconnect: discovery again, a new
// flow that replaces a live one, and the connection pending with its old
// credential until the confirm. The issuer of a connection's credential
// does not change, and the scopes asked are the union of the old and the
// named.
func (s *Server) reconnect(w http.ResponseWriter, r *http.Request, c access.Caller) error {
	if err := s.limited(c); err != nil {
		return err
	}
	var req reconnectRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	if err := s.returnTo(req.ReturnTo); err != nil {
		return err
	}
	row, err := s.stored(r, c, authorizer.ActionConnectionCreate)
	if err != nil {
		return err
	}
	if row.Auth != catalog.AuthOAuth {
		return apierr.Fail(apierr.CodeWrongKind, "auth_"+row.Auth)
	}
	ctx := r.Context()
	conn, err := s.resolve(ctx, row.Connector)
	switch {
	case errors.Is(err, errNoConnector) || (err == nil && (conn.Kind != row.Kind || conn.Auth.Type != row.Auth)):
		return &apierr.Error{Code: apierr.CodeConnectionNotConnected, Reason: "connector_removed", Extra: map[string]any{"state": string(row.State)}}
	case err != nil:
		return apierr.Internal(err)
	}
	if conn.added != nil {
		return apierr.Fail(apierr.CodeSignInUnsupported, "sign_in_not_available")
	}
	plan, err := s.Signin.Reconnect(ctx, row, conn.signin(), req.Scopes)
	if err != nil {
		return err
	}
	address, flow, err := s.Signin.Begin(row, plan, req.ReturnTo)
	if err != nil {
		return err
	}
	err = s.Store.Tx(ctx, func(tx store.Tx) error {
		if err := tx.Flows().Put(ctx, flow); err != nil {
			return err
		}
		if row.State == store.StatePending {
			return nil
		}
		return tx.Connections().Move(ctx, row.ID, row.State, store.StatePending, "")
	})
	switch {
	case errors.Is(err, store.ErrStateMoved), errors.Is(err, store.ErrNotFound):
		return apierr.Fail(apierr.CodeConnectionNotFound, "")
	case err != nil:
		return apierr.Internal(err)
	}
	return s.writeStarted(w, r, row.ID, address, http.StatusOK)
}

// expiredPage is what a browser is shown for a callback no live flow
// answers: no redirect, so no address a request names receives anything.
const expiredPage = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>This sign-in link has expired</title></head>
<body><p>This sign-in link has expired or was already used. Start connecting again from the app you came from.</p></body></html>
`

// callback is GET /callback, where the other service returns a person's
// browser: it needs no token, and is held by its state.
func (s *Server) callback(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	dest, err := s.Signin.Callback(r.Context(), r.URL.Query())
	switch {
	case errors.Is(err, signin.ErrNoFlow):
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		if _, err := w.Write([]byte(expiredPage)); err != nil {
			s.log().WarnContext(r.Context(), "the page of an expired sign-in was not written", "error", err.Error())
		}
		return
	case err != nil:
		s.answer(w, r, err)
		return
	}
	w.Header().Set("Location", dest)
	w.WriteHeader(http.StatusFound)
}

// clientDocument is GET /client and GET /client/{id}: the client metadata
// document that names Pons to an authorization server, for the catalog's
// connectors, or for one connector added by its address, with the redirect
// address its add found.
func (s *Server) clientDocument(w http.ResponseWriter, r *http.Request) {
	id, title, redirect := r.PathValue("id"), "", s.Signin.RedirectURI()
	if id != "" {
		row, err := s.Store.Connectors().Get(r.Context(), id)
		switch {
		case errors.Is(err, store.ErrNotFound):
			s.answer(w, r, apierr.Fail(apierr.CodeConnectorNotFound, ""))
			return
		case err != nil:
			s.answer(w, r, apierr.Internal(err))
			return
		}
		title = row.Title
		found, err := foundOf(row)
		if err != nil {
			s.answer(w, r, apierr.Internal(err))
			return
		}
		redirect = s.Signin.RedirectOf(found)
	}
	body, err := json.Marshal(s.Signin.ClientDocument(id, title, redirect))
	if err != nil {
		s.answer(w, r, apierr.Internal(err))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	if _, err := w.Write(body); err != nil {
		s.log().WarnContext(r.Context(), "a client document was not written whole", "error", err.Error())
	}
}
