// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package authorizer

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"latere.ai/x/pkg/authz"

	"latere.ai/x/pons/catalog"
)

// Limits are what an allow holds a request to. The JSON form has every
// member optional and exactly these keys. Pons enforces what it is told and
// stores no plan.
type Limits struct {
	// Owner is whose a created connection or connector is; empty is the
	// owner the request named, or the caller's subject. Read from the allow
	// of a connect and of an add.
	Owner string `json:"owner,omitempty"`
	// MaxConnections is how many connections one owner may hold; 0 leaves
	// the installation's cap, and so does a figure above it. Read from the
	// allow of a connect.
	MaxConnections int `json:"max_connections,omitempty"`
	// Connectors are globs of the connector references the caller may
	// connect; empty is all. Read from the allow of a connect.
	Connectors []string `json:"connectors,omitempty"`
	// ReadOnly holds a use to tools whose effect is read.
	ReadOnly bool `json:"read_only,omitempty"`
	// Tools are globs of the tools a use may call; empty is all.
	Tools []string `json:"tools,omitempty"`
	// Refs are globs of the full ref names a push may update; empty is
	// all.
	Refs []string `json:"refs,omitempty"`
	// CallsPerMinute caps the requests of one subject to one connection;
	// 0 is no cap.
	CallsPerMinute int `json:"calls_per_minute,omitempty"`
}

// ErrUnreadableLimits is an allow whose limits cannot be held: an object
// that does not parse, a key this version does not know, a figure below
// zero or an empty glob. A ceiling Pons cannot read is not one it can hold,
// so the answer is no decision.
var ErrUnreadableLimits = errors.New("authorizer: the allow's limits cannot be read")

// DecodeLimits reads the limits of a decision. A decision with none is the
// zero Limits.
func DecodeLimits(d authz.Decision) (Limits, error) {
	var l Limits
	raw := bytes.TrimSpace(d.Limits)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return l, nil
	}
	// The keys are read first and compared by their exact spelling: the
	// decoder below matches a member's name without regard to case, and a
	// key spelled another way is one this version does not know.
	var members map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&members); err != nil {
		return Limits{}, fmt.Errorf("%w: %w", ErrUnreadableLimits, err)
	}
	if dec.More() {
		return Limits{}, fmt.Errorf("%w: more than one object", ErrUnreadableLimits)
	}
	for key := range members {
		if !slices.Contains(wireNames, key) {
			return Limits{}, fmt.Errorf("%w: the key %q is not one this version knows", ErrUnreadableLimits, key)
		}
	}
	if err := json.Unmarshal(raw, &l); err != nil {
		return Limits{}, fmt.Errorf("%w: %w", ErrUnreadableLimits, err)
	}
	switch {
	case l.MaxConnections < 0:
		return Limits{}, fmt.Errorf("%w: max_connections is below zero", ErrUnreadableLimits)
	case l.CallsPerMinute < 0:
		return Limits{}, fmt.Errorf("%w: calls_per_minute is below zero", ErrUnreadableLimits)
	case emptyGlob(l.Connectors):
		return Limits{}, fmt.Errorf("%w: connectors has an empty glob", ErrUnreadableLimits)
	case emptyGlob(l.Tools):
		return Limits{}, fmt.Errorf("%w: tools has an empty glob", ErrUnreadableLimits)
	case emptyGlob(l.Refs):
		return Limits{}, fmt.Errorf("%w: refs has an empty glob", ErrUnreadableLimits)
	}
	return l, nil
}

// wireNames are the keys of the limits object.
var wireNames = []string{"owner", "max_connections", "connectors", "read_only", "tools", "refs", "calls_per_minute"}

func emptyGlob(globs []string) bool {
	return slices.Contains(globs, "")
}

// AdmitsConnector reports whether a connect of the connector reference is
// within Connectors. A list of catalog names admits no added connector, and
// "ctr_*" admits them all.
func (l Limits) AdmitsConnector(ref string) bool {
	return len(l.Connectors) == 0 || catalog.MatchAny(l.Connectors, ref)
}

// AdmitsTool reports whether a call of the tool is within Tools.
func (l Limits) AdmitsTool(tool string) bool {
	return len(l.Tools) == 0 || catalog.MatchAny(l.Tools, tool)
}

// AdmitsRef reports whether a push may update the ref, by its full name.
func (l Limits) AdmitsRef(ref string) bool {
	return len(l.Refs) == 0 || catalog.MatchAny(l.Refs, ref)
}

// Cap is the cap on an owner's connections: MaxConnections, held to the
// installation's own, which it narrows and never widens.
func (l Limits) Cap(installation int) int {
	if l.MaxConnections > 0 && (installation <= 0 || l.MaxConnections < installation) {
		return l.MaxConnections
	}
	return installation
}
