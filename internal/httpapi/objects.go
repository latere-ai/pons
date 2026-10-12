// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"latere.ai/x/pons/catalog"
	"latere.ai/x/pons/internal/store"
)

// connectorView is a connector as the API shows it (specs/002-objects.md).
// Of auth it shows the type, the scopes, the inject and the hint: no
// client, no reference to a secret and no endpoint.
type connectorView struct {
	Name        string    `json:"name"`
	ID          string    `json:"id,omitempty"`
	Owner       string    `json:"owner,omitempty"`
	Title       string    `json:"title"`
	Description string    `json:"description,omitempty"`
	Icon        string    `json:"icon,omitempty"`
	Kind        string    `json:"kind"`
	URL         string    `json:"url"`
	Hosts       []string  `json:"hosts"`
	Auth        authView  `json:"auth"`
	Tools       marksView `json:"tools"`
}

type authView struct {
	Type   string          `json:"type"`
	Scopes []string        `json:"scopes,omitempty"`
	Inject *catalog.Inject `json:"inject,omitempty"`
	Hint   string          `json:"hint,omitempty"`
}

type marksView struct {
	ReadOnly []string `json:"read_only"`
	Hidden   []string `json:"hidden"`
}

func marks(m catalog.Marks) marksView {
	return marksView{ReadOnly: nonNil(m.ReadOnly), Hidden: nonNil(m.Hidden)}
}

func nonNil(xs []string) []string {
	if xs == nil {
		return []string{}
	}
	return xs
}

// connector is the connector a reference names: an entry of the catalog,
// or one a person added, with its row.
type connector struct {
	catalog.Connector
	added *store.Connector
}

// ref is the connector's reference: its catalog name, or its id.
func (c connector) ref() string {
	if c.added != nil {
		return c.added.ID
	}
	return c.Name
}

// addedURL is the url a credential of an added connector is bound to, and
// empty for a catalog connector.
func (c connector) addedURL() string {
	if c.added != nil {
		return c.added.URL
	}
	return ""
}

func (c connector) view() connectorView {
	v := connectorView{
		Name: c.Name, Title: c.Title, Description: c.Description, Icon: c.Icon,
		Kind: c.Kind, URL: c.URL, Hosts: nonNil(c.HostPatterns()),
		Auth:  authView{Type: c.Auth.Type, Scopes: c.Auth.Scopes, Hint: c.Auth.Hint},
		Tools: marks(c.Tools),
	}
	if c.Auth.Type == catalog.AuthToken {
		in := c.InjectOrDefault()
		v.Auth.Inject = &in
	}
	if c.added != nil {
		v.ID, v.Owner = c.added.ID, c.added.Owner
	}
	return v
}

// errNoConnector is a reference that names no connector.
var errNoConnector = errors.New("httpapi: no connector")

// resolve finds the connector a reference names: an id when it holds an
// underscore, which a catalog name never does, and a catalog name
// otherwise.
func (s *Server) resolve(ctx context.Context, ref string) (connector, error) {
	if !strings.Contains(ref, "_") {
		if c, ok := s.Catalog.Get(ref); ok {
			return connector{Connector: c}, nil
		}
		return connector{}, errNoConnector
	}
	row, err := s.Store.Connectors().Get(ctx, ref)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return connector{}, errNoConnector
	case err != nil:
		return connector{}, err
	}
	return fromRow(row)
}

// fromRow reads an added connector's row.
func fromRow(row store.Connector) (connector, error) {
	c := catalog.Connector{
		Name: row.Name, Title: row.Title, Description: row.Description, Icon: row.Icon,
		Kind: row.Kind, URL: row.URL, Hosts: row.Hosts,
	}
	if err := json.Unmarshal(row.Auth, &c.Auth); err != nil {
		return connector{}, err
	}
	if len(row.Tools) > 0 {
		if err := json.Unmarshal(row.Tools, &c.Tools); err != nil {
			return connector{}, err
		}
	}
	return connector{Connector: c, added: &row}, nil
}

// connectionView is a connection as the API shows it
// (specs/002-objects.md).
type connectionView struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Owner      string     `json:"owner"`
	Connector  string     `json:"connector"`
	Kind       string     `json:"kind"`
	Auth       string     `json:"auth"`
	State      string     `json:"state"`
	Reason     string     `json:"reason,omitempty"`
	Account    string     `json:"account,omitempty"`
	Scopes     []string   `json:"scopes,omitempty"`
	Address    string     `json:"address"`
	GitAddress string     `json:"git_address,omitempty"`
	Tools      marksView  `json:"tools"`
	Links      linksView  `json:"links"`
	CreatedBy  string     `json:"created_by"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
}

type linksView struct {
	Manage string `json:"manage,omitempty"`
}

// connectionOf renders a connection with what is derived from its
// connector: the address, the marks and the links. A connector that left
// the catalog, or whose kind or way to give access no longer equals the
// connection's copy, gives empty marks and no links.
func (s *Server) connectionOf(ctx context.Context, c store.Connection) (connectionView, error) {
	v := connectionView{
		ID: c.ID, Name: c.Name, Owner: c.Owner, Connector: c.Connector, Kind: c.Kind, Auth: c.Auth,
		State: string(c.State), Reason: c.Reason, Account: c.Account, Scopes: c.Scopes,
		Address:   s.address(c),
		Tools:     marks(catalog.Marks{}),
		CreatedBy: c.CreatedBy, CreatedAt: c.CreatedAt.UTC(), UpdatedAt: c.UpdatedAt.UTC(),
		LastUsedAt: when(c.LastUsedAt), ExpiresAt: when(c.ExpiresAt),
	}
	conn, err := s.resolve(ctx, c.Connector)
	switch {
	case errors.Is(err, errNoConnector):
		return v, nil
	case err != nil:
		return connectionView{}, err
	}
	if conn.Kind == c.Kind && conn.Auth.Type == c.Auth {
		v.Tools = marks(conn.Tools)
		v.Links = linksView{Manage: conn.Links.Manage}
	}
	return v, nil
}

// address is where a caller reaches a connection: the MCP address for kind
// mcp (specs/008-carrying-a-call.md), the forwarding address for kind http
// (specs/014-http-forwarding.md).
func (s *Server) address(c store.Connection) string {
	base := s.PublicURL + s.BasePath + "/connections/" + c.ID
	if c.Kind == catalog.KindHTTP {
		return base + "/http"
	}
	return base + "/mcp"
}

func when(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}

// callView is a call record as the API shows it (specs/002-objects.md).
type callView struct {
	ID         string    `json:"id"`
	Connection string    `json:"connection"`
	Owner      string    `json:"owner"`
	Connector  string    `json:"connector"`
	Subject    string    `json:"subject"`
	Session    string    `json:"session,omitempty"`
	At         time.Time `json:"at"`
	DurationMS int64     `json:"duration_ms"`
	Method     string    `json:"method"`
	Tool       string    `json:"tool,omitempty"`
	Refs       int       `json:"refs,omitempty"`
	Effect     string    `json:"effect,omitempty"`
	Outcome    string    `json:"outcome"`
	Status     int       `json:"status,omitempty"`
	BytesIn    int64     `json:"bytes_in"`
	BytesOut   int64     `json:"bytes_out"`
}

func callOf(c store.Call) callView {
	return callView{
		ID: c.ID, Connection: c.Connection, Owner: c.Owner, Connector: c.Connector, Subject: c.Subject,
		Session: c.Session, At: c.At.UTC(), DurationMS: c.DurationMS, Method: c.Method, Tool: c.Tool,
		Refs: c.Refs, Effect: c.Effect, Outcome: c.Outcome, Status: c.Status,
		BytesIn: c.BytesIn, BytesOut: c.BytesOut,
	}
}
