// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package id makes the identifiers of connections, added connectors, flows
// and call records (specs/002-objects.md): a prefix that says what the thing
// is, an underscore, and a ULID in lowercase, which is 48 bits of time
// followed by 80 random bits in 26 characters of Crockford's base 32. An
// identifier sorts by when it was made, so a list ordered by id is a list
// ordered by time, and a page of that list is addressed by the last id on
// it.
package id

import (
	"sync"
	"time"

	"latere.ai/x/pkg/ulid"
)

// The prefixes of the identifiers Pons makes.
const (
	Connection = "con"
	Connector  = "ctr"
	Flow       = "flw"
	Call       = "call"
)

// Generator makes identifiers. Two made in the same millisecond still sort
// in the order they were made. The zero value is ready to use.
type Generator struct {
	// Now is the clock. Nil takes time.Now. It is read when the first
	// identifier is made.
	Now func() time.Time

	once sync.Once
	gen  ulid.Generator
}

// Default is the generator the server uses.
var Default = &Generator{}

// New returns a new identifier with the prefix from Default.
func New(prefix string) string { return Default.New(prefix) }

// New returns a new identifier with the prefix: "<prefix>_<ulid>", the ULID
// in lowercase.
func (g *Generator) New(prefix string) string {
	g.once.Do(func() { g.gen.Now = g.Now })
	return g.gen.New(prefix + "_")
}
