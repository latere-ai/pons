// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package catalog

// The effects of a tool call.
const (
	EffectRead  = "read"
	EffectWrite = "write"
)

// Marks are a connector's tool marks: the globs of the tools that only
// read, and of the tools a caller should not offer.
type Marks struct {
	ReadOnly []string `yaml:"read_only,omitempty" json:"read_only"`
	Hidden   []string `yaml:"hidden,omitempty" json:"hidden"`
}

// Effect is a tool call's effect: read when a read_only glob matches the
// tool, and write otherwise, so a connector with no marks makes every tool
// write. A server's own hints about a tool are not read.
func (m Marks) Effect(tool string) string {
	if MatchAny(m.ReadOnly, tool) {
		return EffectRead
	}
	return EffectWrite
}

// Hidden reports whether a hidden glob matches the tool.
func (m Marks) IsHidden(tool string) bool { return MatchAny(m.Hidden, tool) }

// MatchAny reports whether any glob matches name.
func MatchAny(globs []string, name string) bool {
	for _, g := range globs {
		if Glob(g, name) {
			return true
		}
	}
	return false
}

// Glob reports whether a glob matches a whole name, by case. In a glob `*`
// stands for any run of characters, the empty one included, and every other
// character for itself. An empty glob matches nothing.
func Glob(glob, name string) bool {
	if glob == "" {
		return false
	}
	// The classic two-pointer match with one backtrack point: the last
	// star seen, and where in name it began to match.
	g, n := 0, 0
	star, from := -1, 0
	for n < len(name) {
		switch {
		case g < len(glob) && glob[g] == '*':
			star, from = g, n
			g++
		case g < len(glob) && glob[g] == name[n]:
			g++
			n++
		case star >= 0:
			from++
			g, n = star+1, from
		default:
			return false
		}
	}
	for g < len(glob) && glob[g] == '*' {
		g++
	}
	return g == len(glob)
}
