// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package dial

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"syscall"
	"time"

	"latere.ai/x/pons/catalog"
)

// admit judges one address and port: the Permit when the client has one,
// and the address table otherwise. The port rule was applied to the URL
// before the name was resolved.
func (c *Client) admit(a netip.Addr, port int) bool {
	if c.permit != nil {
		return c.permit(a, port)
	}
	return Public(a)
}

// dialTLS opens one connection: it resolves the name once, refuses it whole
// when any address is not admitted, connects to the checked addresses in
// the order answered, by address, and verifies the certificate for the
// name. Resolving, connecting and the handshake share one bound.
func (c *Client) dialTLS(ctx context.Context, _, hostport string) (net.Conn, error) {
	host, rawPort, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil, refuse(HostNotAName)
	}
	port, err := strconv.ParseUint(rawPort, 10, 16)
	if err != nil || port == 0 {
		return nil, refuse(PortNotAllowed)
	}
	if catalog.CheckHost(host) != nil {
		return nil, refuse(HostNotAName)
	}
	ctx, cancel := context.WithTimeout(ctx, c.connectTimeout)
	defer cancel()

	addrs, err := c.resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		if ctx.Err() != nil {
			return nil, refuse(Timeout)
		}
		return nil, refuse(ResolveFailed)
	}
	if len(addrs) == 0 {
		return nil, refuse(ResolveFailed)
	}
	for _, a := range addrs {
		if !c.admit(a, int(port)) {
			return nil, refuse(AddressNotPublic)
		}
	}

	var conn net.Conn
	for _, a := range addrs {
		if conn, err = c.connect(ctx, netip.AddrPortFrom(a.Unmap(), uint16(port))); err == nil {
			break
		}
	}
	if err != nil {
		var r *Refusal
		switch {
		case errors.As(err, &r):
			return nil, r
		case ctx.Err() != nil:
			return nil, refuse(Timeout)
		}
		return nil, refuse(ConnectFailed)
	}

	tc := tls.Client(conn, &tls.Config{
		ServerName: host,
		RootCAs:    c.roots,
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
	})
	if err := tc.HandshakeContext(ctx); err != nil {
		// The connection failed its handshake and is refused whatever its
		// close answers.
		_ = conn.Close()
		switch {
		case certificateError(err):
			return nil, refuse(CertificateNotVerified)
		case ctx.Err() != nil:
			return nil, refuse(Timeout)
		}
		return nil, refuse(ConnectFailed)
	}
	return tc, nil
}

// connect opens a TCP connection to a checked address, directly or through
// the operator's proxy.
func (c *Client) connect(ctx context.Context, target netip.AddrPort) (net.Conn, error) {
	if c.proxy != nil {
		return c.tunnel(ctx, target)
	}
	d := &net.Dialer{Control: c.control}
	return d.DialContext(ctx, "tcp", target.String())
}

// control is the socket's control hook: it is given the literal address
// about to be connected and applies the same judgment once more, so no
// path inside the package connects unchecked.
func (c *Client) control(_, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil || !c.admit(ap.Addr(), int(ap.Port())) {
		return refuse(AddressNotPublic)
	}
	return nil
}

// tunnel opens a tunnel to a checked address through the operator's proxy.
// CONNECT names the address and the port, never the name, so the proxy
// resolves nothing and the tunnel ends at the address that was judged. The
// name travels only inside the tunnel. The proxy's own address is the
// operator's and is not judged.
func (c *Client) tunnel(ctx context.Context, target netip.AddrPort) (net.Conn, error) {
	proxyAddr := c.proxy.Host
	if c.proxy.Port() == "" {
		port := "80"
		if c.proxy.Scheme == "https" {
			port = "443"
		}
		proxyAddr = net.JoinHostPort(c.proxy.Hostname(), port)
	}
	d := &net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, err
	}
	if c.proxy.Scheme == "https" {
		tc := tls.Client(conn, &tls.Config{ServerName: c.proxy.Hostname(), RootCAs: c.roots, MinVersion: tls.VersionTLS12})
		if err := tc.HandshakeContext(ctx); err != nil {
			return nil, errors.Join(err, conn.Close())
		}
		conn = tc
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, errors.Join(err, conn.Close())
		}
	}
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: target.String()},
		Host:   target.String(),
		Header: http.Header{},
	}
	if user := c.proxy.User; user != nil {
		password, _ := user.Password()
		credential := base64.StdEncoding.EncodeToString([]byte(user.Username() + ":" + password))
		req.Header.Set("Proxy-Authorization", "Basic "+credential)
	}
	if err := req.Write(conn); err != nil {
		return nil, errors.Join(err, conn.Close())
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return nil, errors.Join(err, conn.Close())
	}
	if err := resp.Body.Close(); err != nil {
		return nil, errors.Join(err, conn.Close())
	}
	if resp.StatusCode != http.StatusOK {
		return nil, errors.Join(refuse(ConnectFailed), conn.Close())
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, errors.Join(err, conn.Close())
	}
	return &bufferedConn{Conn: conn, r: br}, nil
}

// bufferedConn is a tunnel read through the reader that read the proxy's
// answer, which may hold the tunnel's first bytes.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.r.Read(p) }
