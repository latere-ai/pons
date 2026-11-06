// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package wire holds the JSON options Pons reads and writes with, by where
// the bytes come from and go to.
package wire

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
)

// Foreign reads JSON Pons does not produce: answers of MCP servers,
// authorization servers and resource servers. It accepts duplicate member
// names (the last wins), invalid UTF-8 and member names in any letter case,
// which such servers send and a decoder with the defaults would refuse.
var Foreign = json.JoinOptions(
	jsontext.AllowDuplicateNames(true),
	jsontext.AllowInvalidUTF8(true),
	json.MatchCaseInsensitiveNames(true),
)

// Outbound writes JSON that a service Pons does not own reads: members in
// a fixed order, a nil list or map as null, and text from a third party
// with its invalid bytes replaced.
var Outbound = json.JoinOptions(
	json.Deterministic(true),
	json.FormatNilSliceAsNull(true),
	json.FormatNilMapAsNull(true),
	jsontext.AllowInvalidUTF8(true),
)

// Stored writes JSON that is kept in a column or sealed and compared as
// bytes: members in a fixed order, and text from a third party with its
// invalid bytes replaced.
var Stored = json.JoinOptions(
	json.Deterministic(true),
	jsontext.AllowInvalidUTF8(true),
)

// RawLenient are the options for marshaling a value that embeds a raw value
// read from a foreign party, so the raw value is not validated again.
var RawLenient = json.JoinOptions(
	jsontext.AllowDuplicateNames(true),
	jsontext.AllowInvalidUTF8(true),
)
