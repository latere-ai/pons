// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"latere.ai/x/pkg/httpjson"

	"latere.ai/x/pons/authorizer"
	"latere.ai/x/pons/catalog"
	"latere.ai/x/pons/internal/access"
	"latere.ai/x/pons/internal/id"
	"latere.ai/x/pons/internal/store"
)

// routeAddConnector names the add in an idempotency key's row.
const routeAddConnector = "POST /connectors"

// listConnectors is GET /connectors: the catalog, in the order of its file,
// then the connectors the allowed owners added, newest first. The filter of
// the allow narrows the added connectors; the catalog is the installation's
// and is listed whatever it says.
func (s *Server) listConnectors(w http.ResponseWriter, r *http.Request, c access.Caller) error {
	p, err := page(r)
	if err != nil {
		return err
	}
	kind := r.URL.Query().Get("kind")
	if kind != "" && kind != catalog.KindMCP && kind != catalog.KindHTTP {
		return onField(CodeInvalidField, "kind", "not_mcp_or_http")
	}
	d, err := s.ask(r, c, authorizer.ActionConnectorList, access.List(authorizer.ActionConnectorList))
	if err != nil {
		return err
	}
	if !d.Allow {
		return forbidden(d)
	}
	out := list[connectorView]{Items: []connectorView{}}
	// A cursor that holds no underscore is a catalog name; one that does is
	// the id of an added connector, past the whole catalog.
	inCatalog := !strings.Contains(p.Cursor, "_")
	if inCatalog {
		past := p.Cursor == ""
		for _, conn := range s.Catalog.Connectors {
			if !past {
				past = conn.Name == p.Cursor
				continue
			}
			if kind != "" && conn.Kind != kind {
				continue
			}
			if len(out.Items) == p.Limit {
				out.NextCursor = out.Items[len(out.Items)-1].Name
				return write(w, http.StatusOK, out)
			}
			out.Items = append(out.Items, connector{Connector: conn}.view())
		}
	}
	if kind == catalog.KindHTTP {
		// A connector of kind http comes from the catalog alone.
		return write(w, http.StatusOK, out)
	}
	added := store.Page{Limit: p.Limit - len(out.Items)}
	if !inCatalog {
		added.Cursor = p.Cursor
	}
	if added.Limit == 0 {
		// The page is full of catalog entries; the next starts at the
		// first added connector, if there is one.
		rows, _, err := s.Store.Connectors().List(r.Context(), d.Owners(c, ""), store.Page{Limit: 1})
		if err != nil {
			return internal(err)
		}
		if len(rows) > 0 {
			out.NextCursor = out.Items[len(out.Items)-1].Name
		}
		return write(w, http.StatusOK, out)
	}
	rows, next, err := s.Store.Connectors().List(r.Context(), d.Owners(c, ""), added)
	if err != nil {
		return internal(err)
	}
	for _, row := range rows {
		conn, err := fromRow(row)
		if err != nil {
			return internal(err)
		}
		out.Items = append(out.Items, conn.view())
	}
	out.NextCursor = next
	return write(w, http.StatusOK, out)
}

// readConnector is GET /connectors/{ref}. An added connector is its owner's
// alone, and a deny reads as a missing connector.
func (s *Server) readConnector(w http.ResponseWriter, r *http.Request, c access.Caller) error {
	conn, err := s.resolve(r.Context(), r.PathValue("ref"))
	switch {
	case errors.Is(err, errNoConnector):
		return fail(CodeConnectorNotFound, "")
	case err != nil:
		return internal(err)
	}
	res := access.Connector{Name: conn.Name, Kind: conn.Kind}
	if conn.added != nil {
		res = access.Connector{ID: conn.added.ID, Owner: conn.added.Owner, Kind: conn.Kind}
	}
	d, err := s.ask(r, c, authorizer.ActionConnectorRead, res.Resource(authorizer.ActionConnectorRead))
	if err != nil {
		return err
	}
	if !d.Allow {
		return fail(CodeConnectorNotFound, "")
	}
	return write(w, http.StatusOK, conn.view())
}

// addRequest is the body of POST /connectors.
type addRequest struct {
	Name        string `json:"name"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Icon        string `json:"icon"`
	Kind        string `json:"kind"`
	URL         string `json:"url"`
	Owner       string `json:"owner"`
	Auth        *struct {
		Type   string          `json:"type"`
		Scopes []string        `json:"scopes"`
		Inject *catalog.Inject `json:"inject"`
		Hint   string          `json:"hint"`
	} `json:"auth"`
	Tools *catalog.Marks `json:"tools"`
}

// addConnector is POST /connectors: a connector a person adds by its
// address, theirs alone. An oauth connector needs discovery, which comes
// with the sign-in, and is refused until then.
func (s *Server) addConnector(w http.ResponseWriter, r *http.Request, c access.Caller) error {
	if err := s.limited(c); err != nil {
		return err
	}
	var req addRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	for field, missing := range map[string]bool{"name": req.Name == "", "title": req.Title == "", "kind": req.Kind == "", "url": req.URL == "", "auth": req.Auth == nil} {
		if missing {
			return onField(CodeMissingField, field, "")
		}
	}
	conn := catalog.Connector{
		Name: req.Name, Title: req.Title, Description: req.Description, Icon: req.Icon, Kind: req.Kind, URL: req.URL,
		Auth: catalog.Auth{Type: req.Auth.Type, Scopes: req.Auth.Scopes, Inject: req.Auth.Inject, Hint: req.Auth.Hint},
	}
	if req.Tools != nil {
		conn.Tools = *req.Tools
	}
	if ps := catalog.Validate(conn, true); len(ps) > 0 {
		return onField(CodeInvalidField, ps[0].Field, ps[0].Rule())
	}
	u, err := url.Parse(conn.URL)
	if err != nil {
		return onField(CodeInvalidField, "url", "not_a_url")
	}
	res := access.Connector{Owner: req.Owner, Kind: conn.Kind, Host: catalog.Normalize(u.Hostname())}
	d, err := s.ask(r, c, authorizer.ActionConnectorCreate, res.Resource(authorizer.ActionConnectorCreate))
	if err != nil {
		return err
	}
	if !d.Allow {
		return forbidden(d)
	}
	if conn.Auth.Type == catalog.AuthOAuth {
		return fail(CodeSignInUnsupported, "sign_in_not_available")
	}
	owner := ownerOf(d, req.Owner, c)
	authDoc, err := json.Marshal(conn.Auth)
	if err != nil {
		return internal(err)
	}
	toolsDoc, err := json.Marshal(conn.Tools)
	if err != nil {
		return internal(err)
	}
	row := store.Connector{
		ID: s.newID(id.Connector), Owner: owner, Name: conn.Name, Title: conn.Title, Description: conn.Description,
		Icon: conn.Icon, Kind: conn.Kind, URL: conn.URL, Hosts: conn.HostPatterns(), Auth: authDoc, Tools: toolsDoc,
	}
	key := r.Header.Get("Idempotency-Key")
	ctx := r.Context()
	replayed, err := s.idempotent(r, c, key, routeAddConnector, row.ID, func(tx store.Tx) error {
		return tx.Connectors().Create(ctx, row)
	})
	switch {
	case errors.Is(err, store.ErrNameTaken):
		return onField(CodeNameTaken, "name", "")
	case err != nil:
		return err
	}
	stored, err := s.Store.Connectors().Get(r.Context(), replayed)
	if err != nil {
		return internal(err)
	}
	view, err := fromRow(stored)
	if err != nil {
		return internal(err)
	}
	return write(w, http.StatusCreated, view.view())
}

// removeConnector is DELETE /connectors/{id}: an added connector its owner
// removes when no connection uses it.
func (s *Server) removeConnector(w http.ResponseWriter, r *http.Request, c access.Caller) error {
	ref := r.PathValue("id")
	if !strings.Contains(ref, "_") {
		// A catalog connector is the installation's, and no person removes
		// it: to the API it is no connector this route knows.
		return fail(CodeConnectorNotFound, "")
	}
	conn, err := s.resolve(r.Context(), ref)
	switch {
	case errors.Is(err, errNoConnector):
		return fail(CodeConnectorNotFound, "")
	case err != nil:
		return internal(err)
	}
	res := access.Connector{ID: conn.added.ID, Owner: conn.added.Owner}
	d, err := s.ask(r, c, authorizer.ActionConnectorDelete, res.Resource(authorizer.ActionConnectorDelete))
	if err != nil {
		return err
	}
	if !d.Allow {
		return fail(CodeConnectorNotFound, "")
	}
	switch err := s.Store.Connectors().Delete(r.Context(), ref); {
	case errors.Is(err, store.ErrInUse):
		return fail(CodeConnectorInUse, "")
	case errors.Is(err, store.ErrNotFound):
		return fail(CodeConnectorNotFound, "")
	case err != nil:
		return internal(err)
	}
	w.WriteHeader(http.StatusNoContent)
	return nil
}

// ownerOf is whose a created object is: the owner its allow names, else the
// owner the request named, else the caller.
func ownerOf(d access.Decision, requested string, c access.Caller) string {
	switch {
	case d.Limits.Owner != "":
		return d.Limits.Owner
	case requested != "":
		return requested
	}
	return c.Subject
}

// write answers a value as JSON.
func write[T any](w http.ResponseWriter, status int, v T) error {
	httpjson.Write(w, status, v)
	return nil
}
