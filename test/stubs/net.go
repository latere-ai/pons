// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package stubs

import (
	"context"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

// loopback is the address every stub listens on.
var loopback = netip.MustParseAddr("127.0.0.1")

// Domain is the name every stub listens under: a stub's name is a label
// before it, such as api.example.com.
const Domain = "example.com"

// NameResolver resolves every name under Domain to the loopback address the
// stubs listen on, and no other name, so a test reaches a stub by the name
// on its certificate while the dialer's host rule and address check stay on.
// It is the resolver the dialer of specs/009-outbound-requests.md takes.
type NameResolver struct{}

// Resolver is the stubs' resolver.
func Resolver() NameResolver { return NameResolver{} }

// LookupNetIP answers loopback for a name under Domain and a failure for
// any other.
func (NameResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	h := strings.TrimSuffix(strings.ToLower(host), ".")
	if h == Domain || strings.HasSuffix(h, "."+Domain) {
		return []netip.Addr{loopback}, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

// Permit admits the loopback address on the ports given and nothing else:
// the dialer's Permit for a test that starts stubs on those ports, so a
// stub is reached and every other address stays refused.
func Permit(ports ...int) func(netip.Addr, int) bool {
	return func(a netip.Addr, port int) bool {
		return a.Unmap() == loopback && slices.Contains(ports, port)
	}
}

// portOf is the port a stub's server listens on.
func portOf(rawURL string) int {
	u, err := url.Parse(rawURL)
	if err != nil {
		panic("stubs: a listener's address does not parse: " + err.Error())
	}
	p, err := strconv.Atoi(u.Port())
	if err != nil {
		panic("stubs: a listener's address has no port: " + err.Error())
	}
	return p
}

// named is a stub's address by its name: https, the name and the port.
func named(name string, port int) string {
	return "https://" + name + ":" + strconv.Itoa(port)
}
