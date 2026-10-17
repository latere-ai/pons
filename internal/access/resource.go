// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package access

import (
	"slices"

	"latere.ai/x/pkg/authz"

	"latere.ai/x/pons/authorizer"
)

// Connector is what a question about a connector carries. A catalog
// connector has a name and no id or owner; an added one has an id and an
// owner. Host is the host of the address a person asks to add.
type Connector struct {
	ID, Owner, Name, Kind, Host string
}

// Resource is the connector as the resource of an action. A member Pons
// does not know is left out, never sent empty, and only the members the
// action sends are carried.
func (c Connector) Resource(action string) authz.Resource {
	return build(authorizer.KindConnector, action, c.ID, map[string]string{
		authorizer.FieldOwner: c.Owner, authorizer.FieldName: c.Name,
		authorizer.FieldConnectorKind: c.Kind, authorizer.FieldHost: c.Host,
	})
}

// Connection is what a question about a connection carries: a stored one,
// with its id, or one a connect would make, with none. A connect to an
// added connector carries that connector's owner. A rename carries the
// name it gives the connection beside the one the connection has. A use
// also carries what the request names: its method, the tool, a path or a
// git service, with its effect, and the refs a push updates.
type Connection struct {
	ID, Owner, Connector, Name, Kind, Auth string
	ConnectorOwner                         string
	NewName                                string
	Method, Tool, Effect                   string
	Refs                                   []string
}

// Resource is the connection as the resource of an action.
func (c Connection) Resource(action string) authz.Resource {
	r := build(authorizer.KindConnection, action, c.ID, map[string]string{
		authorizer.FieldOwner: c.Owner, authorizer.FieldConnector: c.Connector, authorizer.FieldName: c.Name,
		authorizer.FieldConnectionKind: c.Kind, authorizer.FieldAuth: c.Auth, authorizer.FieldConnectorOwner: c.ConnectorOwner,
		authorizer.FieldNewName: c.NewName, authorizer.FieldMethod: c.Method, authorizer.FieldTool: c.Tool, authorizer.FieldEffect: c.Effect,
	})
	if len(c.Refs) > 0 && slices.Contains(authorizer.Fields(action), authorizer.FieldRefs) {
		r.Fields[authorizer.FieldRefs] = slices.Clone(c.Refs)
	}
	return r
}

// List is the resource of a list action, which names no object.
func List(action string) authz.Resource {
	return authz.NewResource(authorizer.Kind(action), "", nil)
}

// ListOf is the resource of a list action that names the owner whose
// objects it lists, for the actions that send one; an empty owner is
// List's resource.
func ListOf(action, owner string) authz.Resource {
	return build(authorizer.Kind(action), action, "", map[string]string{authorizer.FieldOwner: owner})
}

// build keeps the fields an action sends and that are known, and the id
// for the actions that send one, as resource.id.
func build(kind, action, id string, members map[string]string) authz.Resource {
	fields := map[string]any{}
	for _, name := range authorizer.Fields(action) {
		if v := members[name]; v != "" {
			fields[name] = v
		}
	}
	if !authorizer.SendsID(action) {
		id = ""
	}
	return authz.NewResource(kind, id, fields)
}
