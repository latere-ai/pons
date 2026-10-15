// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"latere.ai/x/pons/internal/apierr"

	"latere.ai/x/pkg/httpjson"

	"latere.ai/x/pons/authorizer"
	"latere.ai/x/pons/catalog"
	"latere.ai/x/pons/internal/access"
	"latere.ai/x/pons/internal/id"
	"latere.ai/x/pons/internal/signin"
	"latere.ai/x/pons/internal/store"
)

// routeAddConnector names the add in an idempotency key's row.
const routeAddConnector = "POST /connectors"

// keyHint is the hint of a connector whose server asked for a key at the
// add, when the add named none.
const keyHint = "API key"

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
		return apierr.OnField(apierr.CodeInvalidField, "kind", "not_mcp_or_http")
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
			out.Items = append(out.Items, s.view(connector{Connector: conn}))
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
			return apierr.Internal(err)
		}
		if len(rows) > 0 {
			out.NextCursor = out.Items[len(out.Items)-1].Name
		}
		return write(w, http.StatusOK, out)
	}
	rows, next, err := s.Store.Connectors().List(r.Context(), d.Owners(c, ""), added)
	if err != nil {
		return apierr.Internal(err)
	}
	first := len(out.Items)
	for _, row := range rows {
		conn, err := fromRow(row)
		if err != nil {
			return apierr.Internal(err)
		}
		out.Items = append(out.Items, s.view(conn))
	}
	if err := s.countFor(r, c, out.Items[first:]); err != nil {
		return err
	}
	out.NextCursor = next
	return write(w, http.StatusOK, out)
}

// countFor sets how many connections use each added connector of a page
// the caller may change: connector.update is asked once per owner on the
// page, with the owner and no id, and the connections of the allowed
// owners' connectors are counted in one statement. A deny, and an
// authorizer that gave no decision, show no count.
func (s *Server) countFor(r *http.Request, c access.Caller, items []connectorView) error {
	allowed := map[string]bool{}
	var refs []string
	for _, v := range items {
		mine, asked := allowed[v.Owner]
		if !asked {
			mine = s.mayChange(r, c, access.Connector{Owner: v.Owner})
			allowed[v.Owner] = mine
		}
		if mine {
			refs = append(refs, v.ID)
		}
	}
	if len(refs) == 0 {
		return nil
	}
	counts, err := s.Store.Connections().CountByConnector(r.Context(), refs)
	if err != nil {
		return apierr.Internal(err)
	}
	for i := range items {
		if allowed[items[i].Owner] {
			items[i].Connections = new(counts[items[i].ID])
		}
	}
	return nil
}

// mayChange asks connector.update for the count of a connector's
// connections, which is no reason to fail the read or the list it rides
// on: an authorizer that gave no decision shows no count, and is logged.
func (s *Server) mayChange(r *http.Request, c access.Caller, res access.Connector) bool {
	d, err := s.ask(r, c, authorizer.ActionConnectorUpdate, res.Resource(authorizer.ActionConnectorUpdate))
	if err != nil {
		s.log().WarnContext(r.Context(), "the count of a connector's connections is not shown", "route", r.Pattern, "reason", apierr.Classify(err).Code)
		return false
	}
	return d.Allow
}

// readConnector is GET /connectors/{ref}. A deny reads as a missing
// connector. An added connector the caller may change shows how many
// connections use it.
func (s *Server) readConnector(w http.ResponseWriter, r *http.Request, c access.Caller) error {
	conn, err := s.resolve(r.Context(), r.PathValue("ref"))
	switch {
	case errors.Is(err, errNoConnector):
		return apierr.Fail(apierr.CodeConnectorNotFound, "")
	case err != nil:
		return apierr.Internal(err)
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
		return apierr.Fail(apierr.CodeConnectorNotFound, "")
	}
	v := s.view(conn)
	if conn.added != nil && s.mayChange(r, c, res) {
		if err := s.count(r, &v); err != nil {
			return err
		}
	}
	return write(w, http.StatusOK, v)
}

// count sets how many connections of every owner use one added connector.
func (s *Server) count(r *http.Request, v *connectorView) error {
	counts, err := s.Store.Connections().CountByConnector(r.Context(), []string{v.ID})
	if err != nil {
		return apierr.Internal(err)
	}
	v.Connections = new(counts[v.ID])
	return nil
}

// clientRequest is the client registered at the server that a vouched-for
// add carries, its secret write-only.
type clientRequest struct {
	ID     *string `json:"id"`
	Secret *string `json:"secret"`
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
		Client *clientRequest  `json:"client"`
	} `json:"auth"`
	Tools *catalog.Marks `json:"tools"`
}

// addConnector is POST /connectors: a connector added by its address,
// whose owner is the one the allow names
// (specs/016-connectors-added-for-others.md). After the question, Pons asks
// the server how to sign in, through the dialer and within the add's rate,
// and stores what it answered: the way the add names, which the answer
// must admit, or the answer's own.
func (s *Server) addConnector(w http.ResponseWriter, r *http.Request, c access.Caller) error {
	if err := s.limited(c); err != nil {
		return err
	}
	var req addRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	for _, field := range []struct {
		name    string
		missing bool
	}{{"name", req.Name == ""}, {"title", req.Title == ""}, {"kind", req.Kind == ""}, {"url", req.URL == ""}, {"auth.type", req.Auth != nil && req.Auth.Type == ""}} {
		if field.missing {
			return apierr.OnField(apierr.CodeMissingField, field.name, "")
		}
	}
	conn := catalog.Connector{
		Name: req.Name, Title: req.Title, Description: req.Description, Icon: req.Icon, Kind: req.Kind, URL: req.URL,
		Auth: catalog.Auth{Type: catalog.AuthNone},
	}
	var client *clientRequest
	named := ""
	if req.Auth != nil {
		named, client = req.Auth.Type, req.Auth.Client
		conn.Auth = catalog.Auth{Type: req.Auth.Type, Scopes: req.Auth.Scopes, Inject: req.Auth.Inject, Hint: req.Auth.Hint}
	}
	if req.Tools != nil {
		conn.Tools = *req.Tools
	}
	if ps := catalog.Validate(conn, true); len(ps) > 0 {
		return apierr.OnField(apierr.CodeInvalidField, ps[0].Field, ps[0].Rule())
	}
	u, err := url.Parse(conn.URL)
	if err != nil {
		return apierr.OnField(apierr.CodeInvalidField, "url", "not_a_url")
	}
	res := access.Connector{Owner: req.Owner, Kind: conn.Kind, Host: catalog.Normalize(u.Hostname())}
	d, err := s.ask(r, c, authorizer.ActionConnectorCreate, res.Resource(authorizer.ActionConnectorCreate))
	if err != nil {
		return err
	}
	if !d.Allow {
		return forbidden(d)
	}
	if err := checkClient(client, named, d.Limits.Vouched); err != nil {
		return err
	}
	row := store.Connector{ID: s.newID(id.Connector), Owner: ownerOf(d, req.Owner, c), Vouched: d.Limits.Vouched}
	added := connector{Connector: conn, added: &row}
	way, err := s.Signin.Ask(r.Context(), added.signin(), client != nil)
	if err != nil {
		return err
	}
	if err := reconcile(&conn, named, way, client); err != nil {
		return err
	}
	if client != nil {
		conn.Auth.Client, conn.Auth.Issuer = &catalog.Client{ID: *client.ID}, way.Found.Issuer
		if row.ClientSecret, err = s.sealClient(row.ID, way.Found.TokenEndpoint, *client.Secret); err != nil {
			return err
		}
	}
	if conn.Auth.Type == catalog.AuthOAuth {
		if row.SignIn, err = json.Marshal(way.Found); err != nil {
			return apierr.Internal(err)
		}
	}
	if row.Auth, err = json.Marshal(conn.Auth); err != nil {
		return apierr.Internal(err)
	}
	if row.Tools, err = json.Marshal(conn.Tools); err != nil {
		return apierr.Internal(err)
	}
	row.Name, row.Title, row.Description, row.Icon = conn.Name, conn.Title, conn.Description, conn.Icon
	row.Kind, row.URL, row.Hosts = conn.Kind, conn.URL, conn.HostPatterns()
	key := r.Header.Get("Idempotency-Key")
	ctx := r.Context()
	replayed, err := s.idempotent(r, c, key, routeAddConnector, row.ID, func(tx store.Tx) error {
		return tx.Connectors().Create(ctx, row, s.MaxAddedConnectors)
	})
	switch {
	case errors.Is(err, store.ErrNameTaken):
		return apierr.OnField(apierr.CodeNameTaken, "name", "")
	case errors.Is(err, store.ErrLimitReached):
		return apierr.OnField(apierr.CodeConnectorLimit, "owner", "max_added_connectors="+strconv.Itoa(s.MaxAddedConnectors))
	case err != nil:
		return err
	}
	stored, err := s.Store.Connectors().Get(r.Context(), replayed)
	if err != nil {
		return apierr.Internal(err)
	}
	view, err := fromRow(stored)
	if err != nil {
		return apierr.Internal(err)
	}
	return write(w, http.StatusCreated, s.view(view))
}

// sealClient seals a vouched-for connector's client secret, bound to the
// connector and the token endpoint its add found.
func (s *Server) sealClient(connectorID, tokenEndpoint, secret string) (store.Sealed, error) {
	sealed, err := s.Sealer.Seal([]byte(secret), store.ConnectorClientBinding(connectorID, tokenEndpoint))
	switch {
	case errors.Is(err, store.ErrNoSealingKey):
		return store.Sealed{}, apierr.Fail(apierr.CodeSealingUnavailable, "no_sealing_key")
	case err != nil:
		return store.Sealed{}, apierr.Internal(err)
	}
	return sealed, nil
}

// checkClient holds the client an add carries to its rules: a vouched-for
// add alone takes one, as unknown to any other; it takes an id and a
// secret, and an add of a way other than oauth takes none.
func checkClient(client *clientRequest, named string, vouched bool) error {
	switch {
	case client == nil:
		return nil
	case !vouched:
		return apierr.OnField(apierr.CodeUnknownField, "auth.client", "not_vouched")
	case named != "" && named != catalog.AuthOAuth:
		return apierr.OnField(apierr.CodeInvalidField, "auth.client", "not_taken_by_"+named)
	case client.ID == nil || *client.ID == "":
		return apierr.OnField(apierr.CodeMissingField, "auth.client.id", "")
	}
	return checkSecret(client.Secret)
}

// checkSecret holds a client secret to the bounds of a credential.
func checkSecret(secret *string) error {
	switch {
	case secret == nil || *secret == "":
		return apierr.OnField(apierr.CodeMissingField, "auth.client.secret", "")
	case len(*secret) < store.MinSecretBytes:
		return apierr.OnField(apierr.CodeInvalidField, "auth.client.secret", "shorter_than_8_bytes")
	}
	return nil
}

// reconcile holds the way an add names to the server's answer, or takes
// the answer's: none named for a server that asks for a credential, oauth
// named for one that does not sign people in, and a client for one that
// does not, are 422 auth_mismatch. A key may be named for a server that
// answered without one, since a key may be optional, and for one that
// signs people in, since many take a key as well.
func reconcile(conn *catalog.Connector, named string, way signin.Way, client *clientRequest) error {
	switch {
	case named == "":
		conn.Auth.Type = way.Type
		if way.Type == catalog.AuthToken && conn.Auth.Hint == "" {
			conn.Auth.Hint = keyHint
		}
	case named == catalog.AuthNone && way.Type != catalog.AuthNone:
		return apierr.OnField(apierr.CodeAuthMismatch, "auth.type", "server_asks_"+way.Type)
	case named == catalog.AuthOAuth && way.Type != catalog.AuthOAuth:
		return apierr.OnField(apierr.CodeAuthMismatch, "auth.type", "server_asks_"+way.Type)
	}
	if client != nil && conn.Auth.Type != catalog.AuthOAuth {
		return apierr.OnField(apierr.CodeAuthMismatch, "auth.client", "server_asks_"+way.Type)
	}
	return nil
}

// removeConnector is DELETE /connectors/{id}: an added connector its owner
// removes when no connection uses it.
func (s *Server) removeConnector(w http.ResponseWriter, r *http.Request, c access.Caller) error {
	ref := r.PathValue("id")
	if !strings.Contains(ref, "_") {
		// A catalog connector is the installation's, and no person removes
		// it: to the API it is no connector this route knows.
		return apierr.Fail(apierr.CodeConnectorNotFound, "")
	}
	conn, err := s.resolve(r.Context(), ref)
	switch {
	case errors.Is(err, errNoConnector):
		return apierr.Fail(apierr.CodeConnectorNotFound, "")
	case err != nil:
		return apierr.Internal(err)
	}
	res := access.Connector{ID: conn.added.ID, Owner: conn.added.Owner}
	d, err := s.ask(r, c, authorizer.ActionConnectorDelete, res.Resource(authorizer.ActionConnectorDelete))
	if err != nil {
		return err
	}
	if !d.Allow {
		return apierr.Fail(apierr.CodeConnectorNotFound, "")
	}
	switch err := s.Store.Connectors().Delete(r.Context(), ref); {
	case errors.Is(err, store.ErrInUse):
		return apierr.Fail(apierr.CodeConnectorInUse, "")
	case errors.Is(err, store.ErrNotFound):
		return apierr.Fail(apierr.CodeConnectorNotFound, "")
	case err != nil:
		return apierr.Internal(err)
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
