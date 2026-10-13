// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package authorizer

import (
	"slices"

	"latere.ai/x/pkg/authz"
)

// Core is the name the shared contract carries this vocabulary under. A
// grant on a personal access token qualifies an action with it:
// "pons:connection.use".
const Core = "pons"

// The resource kinds. An action acts on exactly one.
const (
	KindConnector  = "Connector"
	KindConnection = "Connection"
)

// The actions: every question ponsd asks an authorizer, in the order of
// the table of specs/004-identity-and-authorization.md.
const (
	// ActionConnectorList is asked by the list of connectors. Its filter
	// narrows the connectors people added; the catalog is listed whatever
	// it says.
	ActionConnectorList = "connector.list"
	// ActionConnectorRead is asked by a read of one connector.
	ActionConnectorRead = "connector.read"
	// ActionConnectorCreate is asked by adding a connector by its address.
	// The allow's owner is whose the connector is.
	ActionConnectorCreate = "connector.create"
	// ActionConnectorDelete is asked by removing an added connector.
	ActionConnectorDelete = "connector.delete"

	// ActionConnectionCreate is asked by a connect, which sends no id, and
	// by a confirm, a reconnect and a replaced credential, which send the
	// stored connection's id and fields. The allow of a connect carries
	// the owner and the limits the create is held to.
	ActionConnectionCreate = "connection.create"
	// ActionConnectionRead is asked by a read of a connection and of its
	// call records.
	ActionConnectionRead = "connection.read"
	// ActionConnectionList is asked by the list of connections. Its filter
	// narrows the list to owners. A list that names an owner sends it, so
	// an authorizer can answer a service that lists one owner's
	// connections with a filter naming that owner.
	ActionConnectionList   = "connection.list"
	ActionConnectionUpdate = "connection.update"
	ActionConnectionDelete = "connection.delete"
	// ActionConnectionUse is asked for every request to a connection's
	// address, with the tool and its effect when the request names one.
	// The allow carries the limits the call is held to.
	ActionConnectionUse = "connection.use"
)

// The members a resource carries beside its kind. FieldID is the id of a
// stored object, which the envelope carries as resource.id.
const (
	FieldID    = "id"
	FieldOwner = "owner"
	// FieldName is a catalog connector's name, or a connection's.
	FieldName = "name"
	// FieldKind is mcp or http.
	FieldKind = "kind"
	// FieldHost is the host of the address a person asks to add.
	FieldHost = "host"
	// FieldConnector is a connector reference: a catalog name, or the id
	// of an added connector.
	FieldConnector = "connector"
	// FieldAuth is how a person gives access: oauth, token,
	// client_credentials or none.
	FieldAuth = "auth"
	// FieldMethod, FieldTool and FieldEffect are a use's: the protocol
	// method, the tool's name and read or write. FieldRefs is a push's:
	// the full names of the refs it updates.
	FieldMethod = "method"
	FieldTool   = "tool"
	FieldEffect = "effect"
	FieldRefs   = "refs"
)

// action is one row of the vocabulary table.
type action struct {
	name, kind string
	fields     []string
}

// connection is the members of a stored connection.
var connection = []string{FieldID, FieldOwner, FieldConnector, FieldName, FieldKind, FieldAuth}

// table is the vocabulary of specs/004-identity-and-authorization.md, in its
// order, with the fields each action sends.
var table = []action{
	{ActionConnectorList, KindConnector, nil},
	{ActionConnectorRead, KindConnector, []string{FieldName, FieldID, FieldOwner, FieldKind}},
	{ActionConnectorCreate, KindConnector, []string{FieldOwner, FieldKind, FieldHost}},
	{ActionConnectorDelete, KindConnector, []string{FieldID, FieldOwner}},
	{ActionConnectionCreate, KindConnection, []string{FieldOwner, FieldConnector, FieldName, FieldKind, FieldAuth, FieldID}},
	{ActionConnectionRead, KindConnection, connection},
	{ActionConnectionList, KindConnection, []string{FieldOwner}},
	{ActionConnectionUpdate, KindConnection, connection},
	{ActionConnectionDelete, KindConnection, connection},
	{ActionConnectionUse, KindConnection, []string{FieldID, FieldOwner, FieldConnector, FieldName, FieldKind, FieldMethod, FieldTool, FieldEffect, FieldRefs}},
}

// vocabulary is the table as the shared contract reads it, built once. A
// table that does not build is a mistake in this file, which the package's
// tests find.
var vocabulary = func() authz.Vocabulary {
	actions := make([]authz.Action, len(table))
	for i, a := range table {
		actions[i] = authz.Action{Name: a.name, Kind: a.kind}
	}
	v, err := authz.NewVocabulary(Core, actions...)
	if err != nil {
		panic(err)
	}
	return v.WithLabels(map[string]string{KindConnector: "Connectors", KindConnection: "Connections"})
}()

// Vocabulary is the whole action table, for an authorizer to validate
// against and for the conformance suite to drive a case per row from.
func Vocabulary() authz.Vocabulary { return vocabulary }

// Actions lists every action in the order of the table.
func Actions() []string {
	out := make([]string, len(table))
	for i, a := range table {
		out[i] = a.name
	}
	return out
}

// Kind is the resource kind an action acts on, and "" for a string that is
// no action of the table.
func Kind(name string) string {
	kind, _ := vocabulary.Kind(name)
	return kind
}

// Known reports whether name is an action of the table.
func Known(name string) bool { return vocabulary.Known(name) }

// Fields lists the members an action's resource may carry beside its kind,
// each sent when it is known. The value is a fresh copy.
func Fields(name string) []string {
	for _, a := range table {
		if a.name == name {
			return slices.Clone(a.fields)
		}
	}
	return nil
}
