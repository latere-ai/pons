// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package version

import "testing"

func TestStringNamesTheBuild(t *testing.T) {
	old := [3]string{Version, Commit, Date}
	t.Cleanup(func() { Version, Commit, Date = old[0], old[1], old[2] })
	Version, Commit, Date = "v1.2.3", "abc1234", "2026-10-12T00:00:00Z"
	if got, want := String(), "ponsd v1.2.3 (abc1234, 2026-10-12T00:00:00Z)"; got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
	if got, want := UserAgent(), "pons/v1.2.3"; got != want {
		t.Fatalf("UserAgent() = %q, want %q", got, want)
	}
}
