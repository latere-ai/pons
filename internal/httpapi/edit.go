// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"

	"latere.ai/x/pons/authorizer"
	"latere.ai/x/pons/catalog"
	"latere.ai/x/pons/internal/access"
	"latere.ai/x/pons/internal/apierr"
	"latere.ai/x/pons/internal/signin"
	"latere.ai/x/pons/internal/store"
)

// editRequest is the body of PATCH /connectors/{id}: what an edit changes,
// each member left out unchanged, and the members that never change, which
// are taken only as they are.
type editRequest struct {
	Name        *string `json:"name"`
	Title       *string `json:"title"`
	Description *string `json:"description"`
	Icon        *string `json:"icon"`
	Kind        *string `json:"kind"`
	URL         *string `json:"url"`
	Auth        *struct {
		Type   *string        `json:"type"`
		Scopes *[]string      `json:"scopes"`
		Client *clientRequest `json:"client"`
	} `json:"auth"`
	Tools *struct {
		ReadOnly *[]string `json:"read_only"`
		Hidden   *[]string `json:"hidden"`
	} `json:"tools"`
	Disabled *bool `json:"disabled"`
}

// editConnector is PATCH /connectors/{id}: an added connector changed in
// place, asking connector.update (specs/016-connectors-added-for-others.md).
// Its presentation, its tool marks, the scopes a sign-in asks for, a
// vouched-for connector's client secret and whether it is turned off
// change; its name, its kind, its url, its way to give access and its
// client's id do not, since a connection's credential is bound to them.
// Every replica reads the connector at each request, so the next request
// holds to the edit.
func (s *Server) editConnector(w http.ResponseWriter, r *http.Request, c access.Caller) error {
	var req editRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	ref := r.PathValue("id")
	if !strings.Contains(ref, "_") {
		// A catalog connector is the operator's file, and no request edits
		// it.
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
	d, err := s.ask(r, c, authorizer.ActionConnectorUpdate, res.Resource(authorizer.ActionConnectorUpdate))
	if err != nil {
		return err
	}
	if !d.Allow {
		return apierr.Fail(apierr.CodeConnectorNotFound, "")
	}
	if err := immutable(req, conn); err != nil {
		return err
	}
	edited, secret, err := applyEdit(req, conn)
	if err != nil {
		return err
	}
	row := *conn.added
	row.Title, row.Description, row.Icon = edited.Title, edited.Description, edited.Icon
	if req.Disabled != nil {
		row.Disabled = *req.Disabled
	}
	if secret != nil {
		if row.ClientSecret, err = s.sealClient(row.ID, conn.found.TokenEndpoint, *secret); err != nil {
			return err
		}
	}
	if row.Auth, err = json.Marshal(edited.Auth); err != nil {
		return apierr.Internal(err)
	}
	if row.Tools, err = json.Marshal(edited.Tools); err != nil {
		return apierr.Internal(err)
	}
	switch err := s.Store.Connectors().Update(r.Context(), row); {
	case errors.Is(err, store.ErrNotFound):
		return apierr.Fail(apierr.CodeConnectorNotFound, "")
	case err != nil:
		return apierr.Internal(err)
	}
	stored, err := s.Store.Connectors().Get(r.Context(), row.ID)
	if err != nil {
		return apierr.Internal(err)
	}
	after, err := fromRow(stored)
	if err != nil {
		return apierr.Internal(err)
	}
	v := s.view(after)
	if err := s.count(r, &v); err != nil {
		return err
	}
	return write(w, http.StatusOK, v)
}

// immutable refuses a change of a member that never changes, 400
// immutable_field: a member named with its stored value is no change.
func immutable(req editRequest, conn connector) error {
	clientID := ""
	if conn.Auth.Client != nil {
		clientID = conn.Auth.Client.ID
	}
	fixed := []struct {
		field     string
		requested *string
		stored    string
	}{
		{"name", req.Name, conn.Name},
		{"kind", req.Kind, conn.Kind},
		{"url", req.URL, conn.URL},
	}
	if req.Auth != nil {
		fixed = append(fixed, struct {
			field     string
			requested *string
			stored    string
		}{"auth.type", req.Auth.Type, conn.Auth.Type})
		if req.Auth.Client != nil {
			fixed = append(fixed, struct {
				field     string
				requested *string
				stored    string
			}{"auth.client.id", req.Auth.Client.ID, clientID})
		}
	}
	for _, f := range fixed {
		if f.requested != nil && *f.requested != f.stored {
			return apierr.OnField(apierr.CodeImmutableField, f.field, "")
		}
	}
	return nil
}

// applyEdit is the connector with the edit's changes, held to the rules of
// an added connector, and the new client secret when the edit gives one.
func applyEdit(req editRequest, conn connector) (catalog.Connector, *string, error) {
	edited := conn.Connector
	edited.Auth.Scopes = slices.Clone(conn.Auth.Scopes)
	edited.Tools = catalog.Marks{ReadOnly: slices.Clone(conn.Tools.ReadOnly), Hidden: slices.Clone(conn.Tools.Hidden)}
	for _, m := range []struct {
		into *string
		from *string
	}{{&edited.Title, req.Title}, {&edited.Description, req.Description}, {&edited.Icon, req.Icon}} {
		if m.from != nil {
			*m.into = *m.from
		}
	}
	if req.Tools != nil {
		if req.Tools.ReadOnly != nil {
			edited.Tools.ReadOnly = *req.Tools.ReadOnly
		}
		if req.Tools.Hidden != nil {
			edited.Tools.Hidden = *req.Tools.Hidden
		}
	}
	var secret *string
	if req.Auth != nil {
		if req.Auth.Scopes != nil {
			if conn.Auth.Type != catalog.AuthOAuth {
				return catalog.Connector{}, nil, apierr.OnField(apierr.CodeInvalidField, "auth.scopes", "not_taken_by_"+conn.Auth.Type)
			}
			edited.Auth.Scopes = *req.Auth.Scopes
		}
		if cl := req.Auth.Client; cl != nil && cl.Secret != nil {
			switch {
			case !conn.added.Vouched:
				return catalog.Connector{}, nil, apierr.OnField(apierr.CodeUnknownField, "auth.client", "not_vouched")
			case conn.found.Client != signin.ClientOwn:
				return catalog.Connector{}, nil, apierr.OnField(apierr.CodeInvalidField, "auth.client.secret", "no_client")
			}
			if err := checkSecret(cl.Secret); err != nil {
				return catalog.Connector{}, nil, err
			}
			secret = cl.Secret
		}
	}
	// A vouched-for connector's client and the issuer the add found, and
	// the hosts its url gave, are the add's, which the rules of an add's
	// request do not take, so they are held apart while the rest is
	// checked.
	check := edited
	check.Auth.Client, check.Auth.Issuer, check.Hosts = nil, "", nil
	if ps := catalog.Validate(check, true); len(ps) > 0 {
		return catalog.Connector{}, nil, apierr.OnField(apierr.CodeInvalidField, ps[0].Field, ps[0].Rule())
	}
	return edited, secret, nil
}
