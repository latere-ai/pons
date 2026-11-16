import Machines.Connection

/-!
Claims about the connection table, proved over the table that
`internal/store.ConnectionTable` renders into `Machines/Connection.lean`.
-/

namespace Proofs.Connection
open Machines.Connection Statemachine

/-- A connection is never created needing its sign-in again: that state is
reached only by a step from another. -/
theorem needs_reconnect_is_never_a_start : State.needs_reconnect ∉ machine.initial := by
  decide

/-- Only a connection that is pending or connected is moved to
`needs_reconnect`: no state moves to itself, so a refusal that keeps a
pending connection pending is not a step. -/
theorem no_step_keeps_a_state :
    ∀ s ∈ machine.states, s ∉ machine.next s := by
  decide

/-- Every state has a way out, so only a delete ends a connection. -/
theorem no_state_is_a_dead_end :
    ∀ s ∈ machine.states, machine.next s ≠ [] := by
  decide

/-- Concurrent writers that check the state they land on keep the table,
whatever they read and in whatever order their writes land. -/
theorem guarded_writers_follow (ws : List (Write State)) (row : State) :
    Reaches machine row (ws.foldl machine.guarded row) :=
  machine.guarded_follows ws row

end Proofs.Connection
