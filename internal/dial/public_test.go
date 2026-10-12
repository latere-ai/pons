// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package dial

import (
	"net/netip"
	"testing"
)

// Every block of the table is refused, a mapped and a translated form of
// each IPv4 block included, and an address outside every block is admitted.
func TestPublic(t *testing.T) {
	private := []string{
		"0.0.0.0", "0.255.255.255",
		"10.0.0.0", "10.255.255.255",
		"172.16.0.1", "172.31.255.255",
		"192.168.0.1", "192.168.255.255",
		"100.64.0.1", "100.127.255.255",
		"127.0.0.1", "127.255.255.254",
		"169.254.0.1", "169.254.169.254",
		"192.0.0.1", "192.0.0.255",
		"192.0.2.1", "198.18.0.1", "198.19.255.255",
		"198.51.100.1", "203.0.113.1",
		"224.0.0.1", "239.255.255.255",
		"240.0.0.1", "255.255.255.255",
	}
	for _, s := range private {
		a := netip.MustParseAddr(s)
		b := a.As4()
		mapped := netip.AddrFrom16([16]byte{10: 0xff, 11: 0xff, 12: b[0], 13: b[1], 14: b[2], 15: b[3]})
		trans := netip.AddrFrom16([16]byte{0: 0x00, 1: 0x64, 2: 0xff, 3: 0x9b, 12: b[0], 13: b[1], 14: b[2], 15: b[3]})
		for _, form := range []netip.Addr{a, mapped, trans} {
			if Public(form) {
				t.Errorf("%s is admitted", form)
			}
		}
	}
	for _, s := range []string{
		"::", "::1",
		"64:ff9b:1::1", "64:ff9b:1:ffff::1",
		"2001::1", "2001:0:ffff::1",
		"2002::1", "2002:ffff::1",
		"2001:db8::1", "2001:db8:ffff::1",
		"fc00::1", "fd00:ec2::254",
		"fe80::1", "febf::1",
		"fec0::1", "feff::1",
		"ff02::1", "ff00::",
		"fe80::1%en0",
	} {
		if Public(netip.MustParseAddr(s)) {
			t.Errorf("%s is admitted", s)
		}
	}
	for _, s := range []string{
		"8.8.8.8", "1.1.1.1", "93.184.216.34", "172.32.0.1", "100.128.0.1", "198.20.0.1",
		"::ffff:8.8.8.8", "64:ff9b::808:808",
		"2606:4700:4700::1111", "2a00:1450:4001::1", "2001:4860:4860::8888",
	} {
		if !Public(netip.MustParseAddr(s)) {
			t.Errorf("%s is refused", s)
		}
	}
	if Public(netip.Addr{}) {
		t.Error("the zero address is admitted")
	}
}
