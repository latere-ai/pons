// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package store

import "time"

// TouchInterval is how far behind last_used_at may fall before a call
// writes it again.
const TouchInterval = time.Minute

// NextReason is a connection's reason after a move, the rule both adapters
// apply (specs/005-store-and-sealing.md). A move to StateConnected clears
// it. A move to StateNeedsReconnect, and a refusal of a pending
// connection's old credential, a move from StatePending to StatePending,
// set it to the reason given, and keep the current one when none is given,
// so a reconnect again keeps a reason it had. Every other move keeps it.
func NextReason(from, to State, current, given string) string {
	switch {
	case to == StateConnected:
		return ""
	case given != "" && (to == StateNeedsReconnect || (from == StatePending && to == StatePending)):
		return given
	}
	return current
}
