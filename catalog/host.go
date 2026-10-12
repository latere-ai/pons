// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package catalog

import (
	"errors"
	"strings"

	"latere.ai/x/pkg/hostmatch"
)

// ErrHostNotAName is a host that is an address, a single label or a name
// reserved for a private network. Its text is the refusal's name in
// specs/009-outbound-requests.md.
var ErrHostNotAName = errors.New("host_not_a_name")

// reservedSuffixes are the names that are loopback, link-local or private by
// their spelling: the name itself and every name under it.
var reservedSuffixes = []string{"localhost", "local", "internal", "home.arpa"}

// Normalize is a host as the host rule compares it: in lower case, without
// a trailing dot. A port is the caller's to remove.
func Normalize(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}

// CheckHost is the host rule of specs/006-catalog.md and
// specs/009-outbound-requests.md, for the host of a URL: one function,
// which the catalog's validation, the route that adds a connector and the
// dialer all call. It refuses what hostmatch.ValidPattern refuses with no
// option, a wildcard, an IP literal in any notation a resolver reads as
// one, and every name under localhost, local, internal and home.arpa. The
// host is normalized first; it carries no port.
func CheckHost(host string) error {
	h := Normalize(host)
	if strings.HasPrefix(h, "*.") {
		return ErrHostNotAName
	}
	return checkName(h)
}

// CheckPattern is the same rule for a pattern of a connector's hosts,
// which may carry one leading "*." before a name of two labels or more.
func CheckPattern(pattern string) error {
	p := Normalize(pattern)
	return checkName(strings.TrimPrefix(p, "*."))
}

// checkName is the rule over a name with no wildcard.
func checkName(h string) error {
	if !hostmatch.ValidPattern(h) || strings.Contains(h, "*") {
		// A single label, an IPv6 literal, a name that is not ASCII, a
		// wildcard anywhere but in front.
		return ErrHostNotAName
	}
	last := h[strings.LastIndexByte(h, '.')+1:]
	if allDigits(last) || strings.HasPrefix(last, "0x") {
		// The notations a resolver reads as an IPv4 address and netip
		// does not, such as 10.1 and 0x7f.1, all end on such a label.
		return ErrHostNotAName
	}
	for _, s := range reservedSuffixes {
		if h == s || strings.HasSuffix(h, "."+s) {
			return ErrHostNotAName
		}
	}
	return nil
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// Matcher is a matcher of host patterns, normalized as the host rule
// normalizes a host. A host handed to its Matches is normalized by the
// caller with Normalize.
func Matcher(patterns []string) hostmatch.Matcher {
	return hostmatch.New(patterns, Normalize)
}
