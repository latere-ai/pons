// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package store_test

import (
	"flag"
	"slices"
	"testing"

	"latere.ai/x/pkg/statemachine/statemachinetest"

	"latere.ai/x/pons/internal/store"
)

var update = flag.Bool("update", false, "rewrite the formal models under formal/")

// TestFormalModels holds formal/, which the lean and tla gates check, to the
// lifecycle tables.
func TestFormalModels(t *testing.T) {
	statemachinetest.Models(t, "../../formal", *update, store.ConnectionTable.Graph(), store.FlowTable.Graph())
}

// TestEveryStatusIsInItsTable keeps each status type and its table to one
// set of states, so a status added to one is added to the other.
func TestEveryStatusIsInItsTable(t *testing.T) {
	sameStates(t, "Connection", store.ConnectionTable.States(), store.StateConnected, store.StateNeedsReconnect, store.StatePending)
	sameStates(t, "Flow", store.FlowTable.States(), store.FlowAnswered, store.FlowEnded, store.FlowOpen)
}

func sameStates[S ~string](t *testing.T, name string, states []S, consts ...S) {
	t.Helper()
	want := slices.Sorted(slices.Values(consts))
	if !slices.Equal(states, want) {
		t.Errorf("%s table states %v, constants %v", name, states, want)
	}
}

// A flow's state is told by its hashes, and the condition a writer binds to
// the states before its target names the same rows.
func TestFlowStateFollowsTheHashes(t *testing.T) {
	for _, c := range []struct {
		flow store.Flow
		want store.FlowStatus
	}{
		{store.Flow{StateHash: []byte("s")}, store.FlowOpen},
		{store.Flow{FinishHash: []byte("f")}, store.FlowAnswered},
		{store.Flow{}, store.FlowEnded},
	} {
		if got := store.FlowStatusOf(c.flow); got != c.want {
			t.Errorf("FlowStatusOf(%+v) = %s, want %s", c.flow, got, c.want)
		}
	}
	for _, c := range []struct {
		got, want string
	}{
		{store.FlowIn(store.FlowOpen), "(state_hash IS NOT NULL)"},
		{store.FlowIn(store.FlowTable.Sources(store.FlowAnswered)...), "(state_hash IS NOT NULL)"},
		{store.FlowIn(store.FlowTable.Sources(store.FlowEnded)...), "((state_hash IS NULL AND finish_hash IS NOT NULL) OR state_hash IS NOT NULL)"},
		{store.FlowIn(), "false"},
	} {
		if c.got != c.want {
			t.Errorf("condition %q, want %q", c.got, c.want)
		}
	}
}

func TestParseState(t *testing.T) {
	if s, ok := store.ParseState("needs_reconnect"); !ok || s != store.StateNeedsReconnect {
		t.Errorf(`ParseState("needs_reconnect") = %q, %v`, s, ok)
	}
	if _, ok := store.ParseState("deleted"); ok {
		t.Error(`ParseState("deleted") reports a state`)
	}
}
