// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package access

import (
	"net/http"

	"latere.ai/x/pons/authorizer"
)

// AnyMethod is the method of a route that takes every method.
const AnyMethod = "*"

// Route is one operation of the contract of specs/003-api.md with the
// question it asks.
type Route struct {
	// Method and Path name the operation, the path as the contract spells
	// it, below the base path.
	Method, Path string
	// Action is the action the route asks before it acts. It is empty for a
	// route that takes no token and asks nothing.
	Action string
}

// routes is the table of specs/003-api.md, in its order. The address of a
// connector of kind mcp takes GET and DELETE beside POST, for a connector on
// an earlier protocol revision (specs/008-carrying-a-call.md).
var routes = []Route{
	{http.MethodGet, "/connectors", authorizer.ActionConnectorList},
	{http.MethodGet, "/connectors/{ref}", authorizer.ActionConnectorRead},
	{http.MethodPost, "/connectors", authorizer.ActionConnectorCreate},
	{http.MethodPatch, "/connectors/{id}", authorizer.ActionConnectorUpdate},
	{http.MethodDelete, "/connectors/{id}", authorizer.ActionConnectorDelete},
	{http.MethodPost, "/connections", authorizer.ActionConnectionCreate},
	{http.MethodGet, "/connections", authorizer.ActionConnectionList},
	{http.MethodGet, "/connections/{id}", authorizer.ActionConnectionRead},
	{http.MethodPatch, "/connections/{id}", authorizer.ActionConnectionUpdate},
	{http.MethodPost, "/connections/{id}/confirm", authorizer.ActionConnectionCreate},
	{http.MethodPost, "/connections/{id}/reconnect", authorizer.ActionConnectionCreate},
	{http.MethodPut, "/connections/{id}/credential", authorizer.ActionConnectionCreate},
	{http.MethodDelete, "/connections/{id}", authorizer.ActionConnectionDelete},
	{http.MethodGet, "/connections/{id}/calls", authorizer.ActionConnectionRead},
	{http.MethodGet, "/connections/{id}/tools", authorizer.ActionConnectionRead},
	{AnyMethod, "/connections/{id}/http/{path}", authorizer.ActionConnectionUse},
	{http.MethodGet, "/connections/{id}/git/{path}", authorizer.ActionConnectionUse},
	{http.MethodPost, "/connections/{id}/git/{path}", authorizer.ActionConnectionUse},
	{http.MethodPost, "/connections/{id}/mcp", authorizer.ActionConnectionUse},
	{http.MethodGet, "/connections/{id}/mcp", authorizer.ActionConnectionUse},
	{http.MethodDelete, "/connections/{id}/mcp", authorizer.ActionConnectionUse},
	{http.MethodGet, "/callback", ""},
	{http.MethodGet, "/callback/{key}", ""},
	{http.MethodGet, "/client", ""},
	{http.MethodGet, "/client/{id}", ""},
	{http.MethodGet, "/openapi.yaml", ""},
}

// Routes lists every operation of the contract with the action it asks, in
// the contract's order. The value is a fresh copy.
func Routes() []Route { return append([]Route(nil), routes...) }

// RouteOf finds the row of one operation. ok is false for an operation the
// contract does not have.
func RouteOf(method, path string) (Route, bool) {
	for _, rt := range routes {
		if (rt.Method == method || rt.Method == AnyMethod) && rt.Path == path {
			return rt, true
		}
	}
	return Route{}, false
}
