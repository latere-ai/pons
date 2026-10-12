// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package dial

import "net/netip"

// privateV4 are the IPv4 blocks of the address table of
// specs/009-outbound-requests.md.
var privateV4 = prefixes(
	"0.0.0.0/8",       // the unspecified address and "this network"
	"10.0.0.0/8",      // private
	"172.16.0.0/12",   // private
	"192.168.0.0/16",  // private
	"100.64.0.0/10",   // carrier-grade NAT
	"127.0.0.0/8",     // loopback
	"169.254.0.0/16",  // link-local, the metadata address included
	"192.0.0.0/24",    // protocol assignments
	"192.0.2.0/24",    // documentation
	"198.18.0.0/15",   // benchmarking
	"198.51.100.0/24", // documentation
	"203.0.113.0/24",  // documentation
	"224.0.0.0/4",     // multicast
	"240.0.0.0/4",     // reserved, broadcast included
)

// privateV6 are the IPv6 blocks of the table. The IPv4-mapped block and
// the translated block are not here: an address in either is judged as the
// IPv4 address it holds.
var privateV6 = prefixes(
	"::/128",         // unspecified
	"::1/128",        // loopback
	"64:ff9b:1::/48", // local translation
	"2001::/32",      // a tunnel that holds an IPv4 address
	"2002::/16",      // a tunnel that holds an IPv4 address
	"2001:db8::/32",  // documentation
	"fc00::/7",       // unique local, a metadata address under it included
	"fe80::/10",      // link-local
	"fec0::/10",      // the retired site-local range
	"ff00::/8",       // multicast
)

// translated is 64:ff9b::/96, whose last 32 bits are an IPv4 address.
var translated = netip.MustParsePrefix("64:ff9b::/96")

func prefixes(blocks ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(blocks))
	for i, b := range blocks {
		out[i] = netip.MustParsePrefix(b)
	}
	return out
}

// Public reports whether an address is in none of the blocks of the address
// table. It is the one judgment of an address in the module. Its argument
// is the value the resolver returned or the socket is about to use, so no
// notation of an address reaches a parser of Pons's own.
func Public(a netip.Addr) bool {
	if !a.IsValid() {
		return false
	}
	// A zone names an interface, and a prefix never contains a zoned
	// address; the address without it is what the table judges.
	a = a.WithZone("")
	if a.Is4In6() {
		a = a.Unmap()
	} else if a.Is6() && translated.Contains(a) {
		b := a.As16()
		a = netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
	}
	blocks := privateV6
	if a.Is4() {
		blocks = privateV4
	}
	for _, p := range blocks {
		if p.Contains(a) {
			return false
		}
	}
	return true
}
