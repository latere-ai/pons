// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"latere.ai/x/pons/internal/apierr"

	"latere.ai/x/pons/authorizer"
	"latere.ai/x/pons/catalog"
	"latere.ai/x/pons/internal/access"
	"latere.ai/x/pons/internal/id"
	"latere.ai/x/pons/internal/store"
)

// routeConnect names the connect in an idempotency key's row.
const routeConnect = "POST /connections"

// credentialRequest is the credential a connect or a replacement carries:
// the key of a token connection, or the client of a client_credentials one.
// It is write-only.
type credentialRequest struct {
	Value        *string `json:"value"`
	ClientID     *string `json:"client_id"`
	ClientSecret *string `json:"client_secret"`
}

// connectRequest is the body of POST /connections.
type connectRequest struct {
	Connector  string             `json:"connector"`
	Name       string             `json:"name"`
	Owner      string             `json:"owner"`
	ReturnTo   string             `json:"return_to"`
	Credential *credentialRequest `json:"credential"`
	Scopes     []string           `json:"scopes"`
}

// createConnection is POST /connections. A connection by a key, by a
// client of its own or with no credential is connected at once; one by
// signing in is pending with the address of its sign-in. A connect to an
// added connector asks connector.read of it first, so a connector another
// owner added is connected by whom the authorizer lets read it
// (specs/016-connectors-added-for-others.md), and one turned off is
// connected by nobody.
func (s *Server) createConnection(w http.ResponseWriter, r *http.Request, c access.Caller) error {
	if err := s.limited(c); err != nil {
		return err
	}
	var req connectRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	if req.Connector == "" {
		return apierr.OnField(apierr.CodeMissingField, "connector", "")
	}
	conn, err := s.resolve(r.Context(), req.Connector)
	switch {
	case errors.Is(err, errNoConnector):
		return apierr.OnField(apierr.CodeConnectorNotFound, "connector", "")
	case err != nil:
		return apierr.Internal(err)
	}
	name := req.Name
	if name == "" {
		name = conn.Name
	}
	if !catalog.IsLabel(name) {
		return apierr.OnField(apierr.CodeInvalidField, "name", "not_a_dns_label")
	}
	secrets, meta, err := credentialOf(conn, req.Credential)
	if err != nil {
		return err
	}
	if conn.Auth.Type != catalog.AuthOAuth {
		if req.ReturnTo != "" {
			return apierr.OnField(apierr.CodeInvalidField, "return_to", "no_sign_in")
		}
		if len(req.Scopes) > 0 {
			return apierr.OnField(apierr.CodeInvalidField, "scopes", "no_sign_in")
		}
	} else if err := s.returnTo(req.ReturnTo); err != nil {
		return err
	}
	res := access.Connection{Owner: req.Owner, Connector: conn.ref(), Name: name, Kind: conn.Kind, Auth: conn.Auth.Type}
	if conn.added != nil {
		read := access.Connector{ID: conn.added.ID, Owner: conn.added.Owner, Kind: conn.Kind}
		d, err := s.ask(r, c, authorizer.ActionConnectorRead, read.Resource(authorizer.ActionConnectorRead))
		if err != nil {
			return err
		}
		if !d.Allow {
			return apierr.OnField(apierr.CodeConnectorNotFound, "connector", "")
		}
		if conn.added.Disabled {
			return apierr.OnField(apierr.CodeConnectorDisabled, "connector", "")
		}
		res.ConnectorOwner = conn.added.Owner
	}
	d, err := s.ask(r, c, authorizer.ActionConnectionCreate, res.Resource(authorizer.ActionConnectionCreate))
	if err != nil {
		return err
	}
	if !d.Allow {
		return forbidden(d)
	}
	if !d.Limits.AdmitsConnector(conn.ref()) {
		return apierr.OnField(apierr.CodeForbidden, "connector", "connectors")
	}
	owner := ownerOf(d, req.Owner, c)
	row := store.Connection{
		ID: s.newID(id.Connection), Owner: owner, Name: name, Connector: conn.ref(), Kind: conn.Kind,
		Auth: conn.Auth.Type, State: store.StateConnected, CreatedBy: c.Subject,
	}
	limit := d.Limits.Cap(s.MaxConnectionsPerOwner)
	if conn.Auth.Type == catalog.AuthOAuth {
		err := s.connectBySignIn(w, r, c, conn, row, req, limit)
		return createError(err, limit)
	}
	var sealed *store.SealedCredential
	if secrets != nil {
		if err := s.try(r.Context(), conn, *secrets, meta); err != nil {
			return err
		}
		sc, err := s.seal(row, conn, *secrets, meta)
		if err != nil {
			return err
		}
		sealed = &sc
	}
	ctx := r.Context()
	made, err := s.idempotent(r, c, r.Header.Get("Idempotency-Key"), routeConnect, row.ID, func(tx store.Tx) error {
		if err := tx.Connections().Create(ctx, row, limit); err != nil {
			return err
		}
		if sealed == nil {
			return nil
		}
		_, err := tx.Credentials().Put(ctx, row.ID, *sealed)
		return err
	})
	if err != nil {
		return createError(err, limit)
	}
	return s.writeConnection(w, r, made, http.StatusCreated)
}

// createError is the route error of a create the store refused.
func createError(err error, limit int) error {
	switch {
	case errors.Is(err, store.ErrNameTaken):
		return apierr.OnField(apierr.CodeNameTaken, "name", "")
	case errors.Is(err, store.ErrLimitReached):
		return apierr.OnField(apierr.CodeForbidden, "owner", "max_connections="+strconv.Itoa(limit))
	}
	return err
}

// credentialOf checks the credential a request carries against the way
// its connector takes access, and is the plaintext and the meta to seal,
// or none for a connector that takes no credential.
func credentialOf(conn connector, cr *credentialRequest) (*store.Secrets, store.Meta, error) {
	var none credentialRequest
	if cr == nil {
		cr = &none
	}
	// refuse is the first member set that the connector's way to give
	// access does not take.
	refuse := func(set map[string]bool) error {
		for _, field := range []string{"value", "client_id", "client_secret"} {
			if set[field] {
				return apierr.OnField(apierr.CodeInvalidField, "credential."+field, "not_taken_by_"+conn.Auth.Type)
			}
		}
		return nil
	}
	secret := func(field string, v *string) error {
		switch {
		case v == nil || *v == "":
			return apierr.OnField(apierr.CodeMissingField, "credential."+field, "")
		case len(*v) < store.MinSecretBytes:
			return apierr.OnField(apierr.CodeInvalidField, "credential."+field, "shorter_than_8_bytes")
		}
		return nil
	}
	switch conn.Auth.Type {
	case catalog.AuthToken:
		if err := refuse(map[string]bool{"client_id": cr.ClientID != nil, "client_secret": cr.ClientSecret != nil}); err != nil {
			return nil, store.Meta{}, err
		}
		if err := secret("value", cr.Value); err != nil {
			return nil, store.Meta{}, err
		}
		in := conn.InjectOrDefault()
		return &store.Secrets{Value: *cr.Value}, store.Meta{Header: in.Header, Format: in.Format}, nil
	case catalog.AuthClientCredentials:
		if err := refuse(map[string]bool{"value": cr.Value != nil}); err != nil {
			return nil, store.Meta{}, err
		}
		if cr.ClientID == nil || *cr.ClientID == "" {
			return nil, store.Meta{}, apierr.OnField(apierr.CodeMissingField, "credential.client_id", "")
		}
		if err := secret("client_secret", cr.ClientSecret); err != nil {
			return nil, store.Meta{}, err
		}
		return &store.Secrets{ClientSecret: *cr.ClientSecret}, store.Meta{
			ClientID: *cr.ClientID, TokenEndpoint: conn.Auth.TokenURL, Scopes: conn.Auth.Scopes, Audience: conn.Auth.Audience,
		}, nil
	}
	// oauth takes its credential from the sign-in, and none takes none.
	return nil, store.Meta{}, refuse(map[string]bool{
		"value": cr.Value != nil, "client_id": cr.ClientID != nil, "client_secret": cr.ClientSecret != nil,
	})
}

// try tries a credential once before it is kept (specs/007-sign-in.md): a
// key by the probe, a client by a first mint. Either refused stores
// nothing.
func (s *Server) try(ctx context.Context, conn connector, secrets store.Secrets, meta store.Meta) error {
	if conn.Auth.Type == catalog.AuthClientCredentials {
		return s.Signin.FirstMint(ctx, conn.signin(), meta, secrets.ClientSecret)
	}
	return s.Carrier.Probe(ctx, conn.signin(), secrets, meta)
}

// seal seals a credential under the binding of its connection.
func (s *Server) seal(c store.Connection, conn connector, secrets store.Secrets, meta store.Meta) (store.SealedCredential, error) {
	plaintext, err := secrets.Encode()
	if err != nil {
		return store.SealedCredential{}, apierr.Internal(err)
	}
	doc, err := store.EncodeMeta(meta)
	if err != nil {
		return store.SealedCredential{}, apierr.Internal(err)
	}
	sealed, err := s.Sealer.Seal(plaintext, store.CredentialBinding(c.ID, c.Owner, c.Auth, meta, conn.addedURL()))
	switch {
	case errors.Is(err, store.ErrNoSealingKey):
		return store.SealedCredential{}, apierr.Fail(apierr.CodeSealingUnavailable, "no_sealing_key")
	case err != nil:
		return store.SealedCredential{}, apierr.Internal(err)
	}
	return store.SealedCredential{Kind: c.Auth, Meta: doc, Sealed: sealed}, nil
}

// idempotent runs a create under its idempotency key. The key's row is
// written first, in the transaction that makes the object, so of two
// requests with one key the second loses on the key, makes nothing, and is
// answered with the object the first made. It returns the id of the object
// the request is answered with.
func (s *Server) idempotent(r *http.Request, c access.Caller, key, route, object string, create func(store.Tx) error) (string, error) {
	if key == "" {
		return object, s.Store.Tx(r.Context(), create)
	}
	ctx := r.Context()
	err := s.Store.Tx(ctx, func(tx store.Tx) error {
		if err := tx.Idempotency().Put(ctx, store.IdempotencyKey{
			Subject: c.Subject, Key: key, Route: route, Status: http.StatusCreated, Object: object,
		}); err != nil {
			return err
		}
		return create(tx)
	})
	if !errors.Is(err, store.ErrKeyTaken) {
		return object, err
	}
	stored, err := s.Store.Idempotency().Get(r.Context(), c.Subject, key)
	if err != nil {
		return "", apierr.Internal(err)
	}
	if stored.Route != route {
		return "", apierr.OnField(apierr.CodeInvalidRequest, "Idempotency-Key", "used_by_another_route")
	}
	return stored.Object, nil
}

// writeConnection answers a stored connection.
func (s *Server) writeConnection(w http.ResponseWriter, r *http.Request, connID string, status int) error {
	row, err := s.Store.Connections().Get(r.Context(), connID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return apierr.Fail(apierr.CodeConnectionNotFound, "")
	case err != nil:
		return apierr.Internal(err)
	}
	v, err := s.connectionOf(r.Context(), row)
	if err != nil {
		return apierr.Internal(err)
	}
	return write(w, status, v)
}

// stored loads the connection a route is about and asks its question. A
// deny answers as a missing connection does, byte for byte, and an id that
// names nothing is answered before any question is asked.
func (s *Server) stored(r *http.Request, c access.Caller, action string) (store.Connection, error) {
	row, err := s.Store.Connections().Get(r.Context(), r.PathValue("id"))
	switch {
	case errors.Is(err, store.ErrNotFound):
		return store.Connection{}, apierr.Fail(apierr.CodeConnectionNotFound, "")
	case err != nil:
		return store.Connection{}, apierr.Internal(err)
	}
	res := access.Connection{ID: row.ID, Owner: row.Owner, Connector: row.Connector, Name: row.Name, Kind: row.Kind, Auth: row.Auth}
	d, err := s.ask(r, c, action, res.Resource(action))
	if err != nil {
		return store.Connection{}, err
	}
	if !d.Allow {
		return store.Connection{}, apierr.Fail(apierr.CodeConnectionNotFound, "")
	}
	return row, nil
}

// listConnections is GET /connections: the connections of the owners the
// allow's filter names, or the caller's own, narrowed by owner, connector
// and state.
func (s *Server) listConnections(w http.ResponseWriter, r *http.Request, c access.Caller) error {
	p, err := page(r)
	if err != nil {
		return err
	}
	q := r.URL.Query()
	state := store.State(q.Get("state"))
	switch state {
	case "", store.StatePending, store.StateConnected, store.StateNeedsReconnect:
	default:
		return apierr.OnField(apierr.CodeInvalidField, "state", "not_a_state")
	}
	d, err := s.ask(r, c, authorizer.ActionConnectionList, access.ListOf(authorizer.ActionConnectionList, q.Get("owner")))
	if err != nil {
		return err
	}
	if !d.Allow {
		return forbidden(d)
	}
	f := store.Filter{Owners: d.Owners(c, q.Get("owner")), Connector: q.Get("connector"), State: state}
	rows, next, err := s.Store.Connections().List(r.Context(), f, p)
	if err != nil {
		return apierr.Internal(err)
	}
	out := list[connectionView]{Items: []connectionView{}, NextCursor: next}
	for _, row := range rows {
		v, err := s.connectionOf(r.Context(), row)
		if err != nil {
			return apierr.Internal(err)
		}
		out.Items = append(out.Items, v)
	}
	return write(w, http.StatusOK, out)
}

// readConnection is GET /connections/{id}.
func (s *Server) readConnection(w http.ResponseWriter, r *http.Request, c access.Caller) error {
	row, err := s.stored(r, c, authorizer.ActionConnectionRead)
	if err != nil {
		return err
	}
	v, err := s.connectionOf(r.Context(), row)
	if err != nil {
		return apierr.Internal(err)
	}
	return write(w, http.StatusOK, v)
}

// renameRequest is the body of PATCH /connections/{id}.
type renameRequest struct {
	Name string `json:"name"`
}

// renameConnection is PATCH /connections/{id}.
func (s *Server) renameConnection(w http.ResponseWriter, r *http.Request, c access.Caller) error {
	var req renameRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	if req.Name == "" {
		return apierr.OnField(apierr.CodeMissingField, "name", "")
	}
	if !catalog.IsLabel(req.Name) {
		return apierr.OnField(apierr.CodeInvalidField, "name", "not_a_dns_label")
	}
	row, err := s.stored(r, c, authorizer.ActionConnectionUpdate)
	if err != nil {
		return err
	}
	switch err := s.Store.Connections().Rename(r.Context(), row.ID, req.Name); {
	case errors.Is(err, store.ErrNameTaken):
		return apierr.OnField(apierr.CodeNameTaken, "name", "")
	case errors.Is(err, store.ErrNotFound):
		return apierr.Fail(apierr.CodeConnectionNotFound, "")
	case err != nil:
		return apierr.Internal(err)
	}
	return s.writeConnection(w, r, row.ID, http.StatusOK)
}

// replaceRequest is the body of PUT /connections/{id}/credential.
type replaceRequest struct {
	Credential *credentialRequest `json:"credential"`
}

// replaceCredential is PUT /connections/{id}/credential: a new key for a
// token connection, or a new client for a client_credentials one. It asks
// connection.create for the stored connection, replaces the old credential
// in one write and clears the connection's reason.
func (s *Server) replaceCredential(w http.ResponseWriter, r *http.Request, c access.Caller) error {
	var req replaceRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	if req.Credential == nil {
		return apierr.OnField(apierr.CodeMissingField, "credential", "")
	}
	row, err := s.stored(r, c, authorizer.ActionConnectionCreate)
	if err != nil {
		return err
	}
	if row.Auth != catalog.AuthToken && row.Auth != catalog.AuthClientCredentials {
		return apierr.Fail(apierr.CodeWrongKind, "auth_"+row.Auth)
	}
	conn, err := s.resolve(r.Context(), row.Connector)
	switch {
	case errors.Is(err, errNoConnector) || (err == nil && (conn.Kind != row.Kind || conn.Auth.Type != row.Auth)):
		return &apierr.Error{Code: apierr.CodeConnectionNotConnected, Reason: "connector_removed", Extra: map[string]any{"state": string(row.State)}}
	case err != nil:
		return apierr.Internal(err)
	case conn.added != nil && conn.added.Disabled:
		// A new key is tried at the server, which nobody reaches through a
		// connector turned off.
		return apierr.OnField(apierr.CodeConnectorDisabled, "connector", "")
	}
	secrets, meta, err := credentialOf(conn, req.Credential)
	if err != nil {
		return err
	}
	if err := s.try(r.Context(), conn, *secrets, meta); err != nil {
		return err
	}
	sealed, err := s.seal(row, conn, *secrets, meta)
	if err != nil {
		return err
	}
	ctx := r.Context()
	err = s.Store.Tx(ctx, func(tx store.Tx) error {
		if _, err := tx.Credentials().Put(ctx, row.ID, sealed); err != nil {
			return err
		}
		if row.State == store.StateNeedsReconnect {
			return tx.Connections().Move(ctx, row.ID, store.StateNeedsReconnect, store.StateConnected, "")
		}
		return nil
	})
	switch {
	case errors.Is(err, store.ErrNotFound):
		return apierr.Fail(apierr.CodeConnectionNotFound, "")
	case err != nil:
		return apierr.Internal(err)
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// deleteConnection is DELETE /connections/{id}: the row, its credential and
// its flow in one transaction, and then a revocation where the credential
// recorded an endpoint for one.
func (s *Server) deleteConnection(w http.ResponseWriter, r *http.Request, c access.Caller) error {
	row, err := s.stored(r, c, authorizer.ActionConnectionDelete)
	if err != nil {
		return err
	}
	switch err := s.Signin.Disconnect(r.Context(), row); {
	case errors.Is(err, store.ErrNotFound):
		return apierr.Fail(apierr.CodeConnectionNotFound, "")
	case err != nil:
		return apierr.Internal(err)
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// listCalls is GET /connections/{id}/calls: the connection's records,
// newest first.
func (s *Server) listCalls(w http.ResponseWriter, r *http.Request, c access.Caller) error {
	p, err := page(r)
	if err != nil {
		return err
	}
	row, err := s.stored(r, c, authorizer.ActionConnectionRead)
	if err != nil {
		return err
	}
	calls, next, err := s.Store.Calls().List(r.Context(), row.ID, p)
	if err != nil {
		return apierr.Internal(err)
	}
	out := list[callView]{Items: []callView{}, NextCursor: next}
	for _, call := range calls {
		out.Items = append(out.Items, callOf(call))
	}
	return write(w, http.StatusOK, out)
}

// toolView is one tool a connection's server lists, with the effect its
// connector's marks give it and whether they hide it.
type toolView struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Effect      string `json:"effect"`
	Hidden      bool   `json:"hidden,omitempty"`
}

// listTools is GET /connections/{id}/tools: the tools the connection's
// server lists through it, asked each time and recorded as no call, so an
// administrator chooses tool marks from the tools a server has
// (specs/016-connectors-added-for-others.md).
func (s *Server) listTools(w http.ResponseWriter, r *http.Request, c access.Caller) error {
	row, err := s.stored(r, c, authorizer.ActionConnectionRead)
	if err != nil {
		return err
	}
	tools, err := s.Carrier.Tools(r.Context(), row)
	if err != nil {
		return err
	}
	out := list[toolView]{Items: make([]toolView, 0, len(tools))}
	for _, t := range tools {
		out.Items = append(out.Items, toolView{Name: t.Name, Description: t.Description, Effect: t.Effect, Hidden: t.Hidden})
	}
	return write(w, http.StatusOK, out)
}
