// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package carry

import (
	"bytes"
	"errors"
	"io"
	"strconv"
	"strings"
)

// The bounds of a push's commands (specs/014-http-forwarding.md).
const (
	// MaxCommandBytes bounds what is read of a push before its pack.
	MaxCommandBytes = 64 << 10
	// MaxCommands bounds how many refs one push names.
	MaxCommands = 1000
)

// errCommands is a push whose commands do not parse or run past a bound.
var errCommands = errors.New("carry: the push's commands do not parse")

// command is one ref a push updates: its old and new object ids and its full
// name. A new id of zeros deletes the ref.
type command struct {
	Old, New, Ref string
}

// readCommands reads the commands that begin a git-receive-pack request:
// any shallow lines, one pkt-line per ref, the first followed by a NUL and
// the client's capabilities, then a flush-pkt. It answers the commands and
// every byte it read, which the forwarded body begins with again; the pack
// after them is not read.
func readCommands(body io.Reader) ([]command, []byte, error) {
	var read bytes.Buffer
	var out []command
	for {
		if read.Len() > MaxCommandBytes {
			return nil, nil, errCommands
		}
		var size [4]byte
		if _, err := io.ReadFull(body, size[:]); err != nil {
			return nil, nil, errCommands
		}
		read.Write(size[:])
		n, err := strconv.ParseUint(string(size[:]), 16, 16)
		if err != nil {
			return nil, nil, errCommands
		}
		if n == 0 {
			if len(out) == 0 {
				return nil, nil, errCommands
			}
			return out, read.Bytes(), nil
		}
		if n < 5 || read.Len()+int(n)-4 > MaxCommandBytes {
			return nil, nil, errCommands
		}
		line := make([]byte, n-4)
		if _, err := io.ReadFull(body, line); err != nil {
			return nil, nil, errCommands
		}
		read.Write(line)
		text := strings.TrimSuffix(string(line), "\n")
		if len(out) == 0 && strings.HasPrefix(text, "shallow ") {
			if !objectID(strings.TrimPrefix(text, "shallow ")) {
				return nil, nil, errCommands
			}
			continue
		}
		if len(out) == 0 {
			text, _, _ = strings.Cut(text, "\x00")
		}
		c, ok := parseCommand(text)
		if !ok || len(out) == MaxCommands {
			return nil, nil, errCommands
		}
		out = append(out, c)
	}
}

// parseCommand reads "<old id> <new id> <ref name>".
func parseCommand(text string) (command, bool) {
	parts := strings.Split(text, " ")
	if len(parts) != 3 || !objectID(parts[0]) || !objectID(parts[1]) || len(parts[0]) != len(parts[1]) {
		return command{}, false
	}
	ref := parts[2]
	if !strings.HasPrefix(ref, "refs/") || strings.ContainsFunc(ref, func(r rune) bool { return r < 0x21 || r == 0x7f }) {
		return command{}, false
	}
	return command{Old: parts[0], New: parts[1], Ref: ref}, true
}

// objectID reports whether s is an object id of SHA-1 or SHA-256 in
// lowercase hex.
func objectID(s string) bool {
	if len(s) != 40 && len(s) != 64 {
		return false
	}
	for i := range len(s) {
		if (s[i] < '0' || s[i] > '9') && (s[i] < 'a' || s[i] > 'f') {
			return false
		}
	}
	return true
}
