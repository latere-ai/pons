// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package migrations embeds the schema of the store as golang-migrate
// files, numbered from 000001 and applied in order over the direct
// connection. A released migration is never edited, because the databases
// that ran it already have.
package migrations

import (
	"embed"

	"latere.ai/x/pkg/pgxmigrate"
)

// FS holds the migration files.
//
//go:embed *.sql
var FS embed.FS

// Highest is the newest migration this binary carries.
func Highest() (uint, error) { return pgxmigrate.HighestOf(FS, ".") }
