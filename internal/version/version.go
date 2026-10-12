// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package version holds the build metadata the linker stamps into a binary.
package version

import "fmt"

// Version, Commit and Date are set at link time by `make build` and by the
// image's build stage. A binary built any other way reports the defaults.
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// String is the one line `ponsd version` prints.
func String() string {
	return fmt.Sprintf("ponsd %s (%s, %s)", Version, Commit, Date)
}

// UserAgent is what Pons sends as its own User-Agent on a request it makes.
func UserAgent() string { return "pons/" + Version }
