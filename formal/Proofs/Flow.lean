import Machines.Flow

/-!
Claims about the sign-in flow table, proved over the table that
`internal/store.FlowTable` renders into `Machines/Flow.lean`.
-/

namespace Proofs.Flow
open Machines.Flow Statemachine

/-- An ended flow stays ended: nothing follows `ended`, so no callback or
confirm matches it again. -/
theorem ended_stays_ended (s : State) (r : Reaches machine .ended s) :
    s = .ended :=
  machine.terminal_stays terminal_ended r

/-- A flow is answered only while it is open: every predecessor of `answered`
is `open`. -/
theorem answered_only_from_open :
    ∀ s ∈ machine.states, State.answered ∈ machine.next s → s = .open := by
  decide

/-- A flow never goes back to waiting for its callback: no state leads to
`open`. -/
theorem open_is_only_a_start :
    ∀ s ∈ machine.states, State.open ∉ machine.next s := by
  decide

/-- Concurrent writers that check the state they land on keep the table,
whatever they read and in whatever order their writes land. -/
theorem guarded_writers_follow (ws : List (Write State)) (row : State) :
    Reaches machine row (ws.foldl machine.guarded row) :=
  machine.guarded_follows ws row

end Proofs.Flow
