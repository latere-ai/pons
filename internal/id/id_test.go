// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package id

import (
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"latere.ai/x/pkg/ulid"
)

var shape = regexp.MustCompile(`^(con|ctr|flw|call)_[0-7][0-9a-hjkmnp-tv-z]{25}$`)

// Every identifier is its prefix, an underscore and a lowercase ULID, and ids
// of one kind sort by creation time, within one millisecond too.
func TestPrefixedAndOrdered(t *testing.T) {
	at := time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)
	g := &Generator{Now: func() time.Time { return at }}
	var made []string
	for i := range 200 {
		if i%50 == 0 {
			at = at.Add(time.Millisecond)
		}
		for _, p := range []string{Connection, Connector, Flow, Call} {
			s := g.New(p)
			if !shape.MatchString(s) || !ulid.Valid(p+"_", s) {
				t.Fatalf("%q is not a %s id", s, p)
			}
			if p == Connection {
				made = append(made, s)
			}
		}
	}
	if !slices.IsSorted(made) {
		t.Fatal("ids made one after another do not sort in the order they were made")
	}
}

// A clock that steps back keeps the order.
func TestAClockThatStepsBackKeepsTheOrder(t *testing.T) {
	at := time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)
	g := &Generator{Now: func() time.Time { return at }}
	first := g.New(Call)
	at = at.Add(-time.Hour)
	second := g.New(Call)
	if second <= first {
		t.Fatalf("%q does not sort after %q", second, first)
	}
}

// The package-level New names the prefix, an underscore and a lowercase
// ULID, whatever the clock, and the ULID reads back as a valid one.
func TestNew(t *testing.T) {
	got := New(Connection)
	if !shape.MatchString(got) || !ulid.Valid(Connection+"_", got) {
		t.Fatalf("New(%q) = %q", Connection, got)
	}
	if got != strings.ToLower(got) {
		t.Fatalf("%q is not lowercase", got)
	}
}
