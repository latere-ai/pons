------------------------------ MODULE Refresh -------------------------------
(***************************************************************************)
(* The refresh of a connection's credential (internal/signin Refresh):     *)
(* replicas claim a lease on the credential before they ask the token      *)
(* endpoint for new tokens, and the lease is the only thing that keeps two *)
(* of them from asking at once. A claim stamps refresh_until, and another  *)
(* replica may claim once that time has passed. The refresh ends in a      *)
(* complete or a release, and either clears the lease. Time is in whole    *)
(* seconds. Lease and Budget are refreshLease and tokenTimeout, rendered   *)
(* from the Go constants into RefreshConstants.tla by                      *)
(* TestRefreshConstants.                                                   *)
(*                                                                         *)
(* An authorization server that rotates refresh tokens refuses the second  *)
(* of two refreshes with the one token, and the refusal moves the          *)
(* connection to needs_reconnect. The model keeps that from happening: no  *)
(* two replicas refresh at once.                                           *)
(***************************************************************************)
EXTENDS Integers, FiniteSets, RefreshConstants

CONSTANTS Replicas, Horizon

Never == -1

VARIABLES
    clock,       \* seconds since the start
    until,       \* the end of the lease, or Never
    refreshing,  \* replica -> TRUE while it asks the token endpoint
    elapsed      \* replica -> seconds spent on the current refresh

vars == <<clock, until, refreshing, elapsed>>

Init == /\ clock = 0
        /\ until = Never
        /\ refreshing = [r \in Replicas |-> FALSE]
        /\ elapsed = [r \in Replicas |-> 0]

\* ClaimRefresh: stamp the lease when the credential has none or one that
\* has lapsed, in one statement, and start the refresh.
Claim(r) ==
    /\ ~refreshing[r]
    /\ \/ until = Never
       \/ clock >= until
    /\ until' = clock + Lease
    /\ refreshing' = [refreshing EXCEPT ![r] = TRUE]
    /\ elapsed' = [elapsed EXCEPT ![r] = 0]
    /\ UNCHANGED clock

\* The refresh ends within Budget seconds, in a complete or a release, and
\* either clears the lease.
Finish(r) ==
    /\ refreshing[r]
    /\ refreshing' = [refreshing EXCEPT ![r] = FALSE]
    /\ until' = Never
    /\ UNCHANGED <<clock, elapsed>>

\* A second passes. A refresh that has used its whole budget ends first.
Tick ==
    /\ clock < Horizon
    /\ \A r \in Replicas : refreshing[r] => elapsed[r] < Budget
    /\ clock' = clock + 1
    /\ elapsed' = [r \in Replicas |-> IF refreshing[r] THEN elapsed[r] + 1 ELSE elapsed[r]]
    /\ UNCHANGED <<until, refreshing>>

\* The model stops at Horizon seconds.
Stop == clock = Horizon /\ UNCHANGED vars

Next == Tick \/ Stop \/ \E r \in Replicas : Claim(r) \/ Finish(r)

Spec == Init /\ [][Next]_vars

\* No two replicas ask the token endpoint with one refresh token at once.
Exclusive == Cardinality({r \in Replicas : refreshing[r]}) <= 1

TypeOK == /\ clock \in 0..Horizon
          /\ until \in -1..(Horizon + Lease)
          /\ \A r \in Replicas : elapsed[r] \in 0..Budget

\* A refresh that may use the whole lease: a second replica claims the
\* credential while the first still asks the token endpoint.
\* Refresh.overlong.cfg uses it.
OverlongBudget == Lease
=============================================================================
