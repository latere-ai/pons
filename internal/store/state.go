// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package store

import "time"

// TouchInterval is how far behind last_used_at may fall before a call
// writes it again.
const TouchInterval = time.Minute

// NextReason is a connection's reason after a move, the rule both adapters
// apply (specs/005-store-and-sealing.md). A move to StateConnected clears
// it. A move to StateNeedsReconnect sets the reason given, and keeps the
// current one when none is given, so a reconnect again keeps a reason it
// had. Every other move keeps it. Connections.Refuse sets the reason of a
// pending connection by NextRefusedReason.
func NextReason(to State, current, given string) string {
	switch {
	case to == StateConnected:
		return ""
	case given != "" && to == StateNeedsReconnect:
		return given
	}
	return current
}

// NextRefusedReason is a pending connection's reason after a refusal: the
// one given, or the current one when none is given.
func NextRefusedReason(current, given string) string {
	if given != "" {
		return given
	}
	return current
}
