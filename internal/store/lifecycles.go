// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"fmt"
	"slices"
	"strings"

	"latere.ai/x/pkg/statemachine"
)

// The lifecycles the store keeps, each as a statemachine table. Every writer
// of a lifecycle takes its guard from the table: a write that would take a
// record along a step the table lacks changes nothing. The suite in
// storetest drives the real writers of both adapters through each table, and
// formal/ renders the tables into the Lean and TLA+ models the lean and tla
// gates check.
//
// The end of a record is not a state of either table. Deleting a connection
// or a flow removes the row, from every state, and is Connections.Delete,
// Connections.DeletePending, Flows.Delete and Flows.TakeExpired.

// ConnectionTable is the lifecycle of a connection, held in
// connections.state (specs/002-objects.md). The writers of its steps are
// Connections.Move, which takes a connection along a step from the state the
// caller names, and Connections.Create, which starts one in pending or
// connected. A connection that needs its sign-in again, and one whose key is
// replaced, return to connected or to pending through Move.
//
// Refuse is not a step: a pending connection whose old credential was
// refused keeps its state and takes a reason, so there is no step from
// pending to pending.
var ConnectionTable = statemachine.Must(statemachine.New("Connection", []State{StatePending, StateConnected}, map[State][]State{
	StatePending:        {StateConnected, StateNeedsReconnect},
	StateConnected:      {StatePending, StateNeedsReconnect},
	StateNeedsReconnect: {StateConnected, StatePending},
}))

// CheckMove reports whether from to is a step of ConnectionTable, as an
// error wrapping ErrIllegalMove when it is not.
func CheckMove(from, to State) error {
	if ConnectionTable.Check(from, to) != nil {
		return fmt.Errorf("%w: %s to %s", ErrIllegalMove, from, to)
	}
	return nil
}

// CheckStart reports whether a connection may be created in state s, as an
// error wrapping ErrIllegalMove when it may not.
func CheckStart(s State) error {
	if ConnectionTable.CheckStart(s) != nil {
		return fmt.Errorf("%w: a connection does not start %s", ErrIllegalMove, s)
	}
	return nil
}

// ParseState reads a connection state written as text outside the store, such
// as a query parameter, and reports whether ConnectionTable has it.
func ParseState(raw string) (State, bool) {
	s := State(raw)
	return s, slices.Contains(ConnectionTable.States(), s)
}

// FlowStatus is the state of a sign-in flow, which flows.state_hash and
// flows.finish_hash tell apart.
type FlowStatus string

// The states of a flow.
const (
	// FlowOpen is a flow waiting for the browser's callback: it holds the
	// hash of the state the callback must bring.
	FlowOpen FlowStatus = "open"
	// FlowAnswered is a flow the callback reached: its state hash is
	// cleared, and it holds the hash of the finish code the confirm must
	// bring and the credential the callback received.
	FlowAnswered FlowStatus = "answered"
	// FlowEnded is a flow that failed or was refused: both hashes are
	// cleared, so no callback or confirm matches it, and its time is the
	// moment it ended, so the next sweep takes it.
	FlowEnded FlowStatus = "ended"
)

// FlowTable is the lifecycle of a flow (specs/007-sign-in.md). Flows.Put
// starts a flow open, Flows.Answer takes an open flow to answered, and
// Flows.End takes an open or an answered flow to ended. Each matches only the
// states the table lists before its target, so a flow another request
// already answered, ended or replaced is left as it is.
//
// A flow's time is a clock overlay, as a key's expiry is: a flow past its
// time is still in its state until the sweep deletes it.
var FlowTable = statemachine.Must(statemachine.New("Flow", []FlowStatus{FlowOpen}, map[FlowStatus][]FlowStatus{
	FlowOpen:     {FlowAnswered, FlowEnded},
	FlowAnswered: {FlowEnded},
	FlowEnded:    nil,
}))

// FlowStatusOf is the state of a flow, as its hashes tell it.
func FlowStatusOf(f Flow) FlowStatus {
	switch {
	case len(f.StateHash) > 0:
		return FlowOpen
	case len(f.FinishHash) > 0:
		return FlowAnswered
	}
	return FlowEnded
}

// FlowIn is the condition on flows.state_hash and flows.finish_hash that
// holds for the rows in any of the states, which a writer puts in its WHERE
// clause. An adapter that keeps flows in a database binds a step to the
// states the table lists before its target:
// FlowIn(FlowTable.Sources(to)...).
func FlowIn(states ...FlowStatus) string {
	var terms []string
	for _, s := range states {
		switch s {
		case FlowOpen:
			terms = append(terms, "state_hash IS NOT NULL")
		case FlowAnswered:
			terms = append(terms, "(state_hash IS NULL AND finish_hash IS NOT NULL)")
		case FlowEnded:
			terms = append(terms, "(state_hash IS NULL AND finish_hash IS NULL)")
		}
	}
	if len(terms) == 0 {
		return "false"
	}
	return "(" + strings.Join(terms, " OR ") + ")"
}
