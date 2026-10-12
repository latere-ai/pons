// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package catalog is the catalog of specs/006-catalog.md: the file an
// operator writes, one entry per connector the installation offers, its
// validation, the connector a person adds by its address, the host rule a
// credential's hosts are held to, and the marks that say which tools only
// read.
//
// The package is public and imports nothing that dials. A consumer reads a
// catalog with Load, checks one connector with Validate, and asks a
// connector's marks for a tool's effect.
package catalog
