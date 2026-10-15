// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package stubs

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
)

// Dial opens a connection, as a net.Dialer's DialContext does. The stubs
// build no dialer of their own, so a test hands the front its own.
type Dial func(ctx context.Context, network, address string) (net.Conn, error)

// Front is a proxy a test gives the dialer as the operator's proxy
// (PONS_OUTBOUND_PROXY), so the server under test reaches stubs at
// addresses on port 443, where no stub can listen: a connector added by
// its address takes port 443 alone (specs/006-catalog.md). A tunnel to
// port 443 ends at the stub the TLS handshake names, by Route; a tunnel to
// any other port ends at the address it asked for. A name no route names
// is a tunnel closed before its handshake.
type Front struct {
	url  *url.URL
	dial Dial

	mu     sync.Mutex
	routes map[string]int
}

// NewFront starts a front for the test on loopback.
func NewFront(t TB, dial Dial) *Front {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		panic("stubs: the front cannot listen: " + err.Error())
	}
	f := &Front{url: &url.URL{Scheme: "http", Host: ln.Addr().String()}, dial: dial, routes: map[string]int{}}
	t.Cleanup(func() {
		// The listener is closed with the test; a close that fails leaves
		// nothing a later test reaches.
		_ = ln.Close()
	})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(conn)
		}
	}()
	return f
}

// URL is the front's address, the proxy a dialer is given.
func (f *Front) URL() *url.URL { u := *f.url; return &u }

// Route ends a tunnel to port 443 whose handshake names name at the stub
// listening on port.
func (f *Front) Route(name string, port int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.routes[name] = port
}

func (f *Front) route(name string) (int, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	port, ok := f.routes[name]
	return port, ok
}

// errHello ends the handshake the front reads a tunnel's server name from.
var errHello = errors.New("stubs: the front read the hello")

// serve answers one CONNECT and carries its tunnel.
func (f *Front) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil || req.Method != http.MethodConnect {
		return
	}
	host, port, err := net.SplitHostPort(req.RequestURI)
	if err != nil {
		return
	}
	ctx := context.Background()
	var seen bytes.Buffer
	target := net.JoinHostPort(host, port)
	if port == "443" {
		if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
			return
		}
		// The client's hello is read as a server would read it, and kept
		// to be sent on to the stub that serves its name.
		var name string
		hello := tls.Server(helloConn{Conn: conn, r: io.TeeReader(br, &seen)}, &tls.Config{
			GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
				name = h.ServerName
				return nil, errHello
			},
		})
		if err := hello.HandshakeContext(ctx); !errors.Is(err, errHello) {
			return
		}
		p, ok := f.route(name)
		if !ok {
			return
		}
		target = net.JoinHostPort("127.0.0.1", strconv.Itoa(p))
	}
	backend, err := f.dial(ctx, "tcp", target)
	if err != nil {
		if port != "443" {
			_, _ = io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		}
		return
	}
	defer func() { _ = backend.Close() }()
	if port != "443" {
		if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
			return
		}
	}
	if _, err := backend.Write(seen.Bytes()); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(backend, br); done <- struct{}{} }()
	go func() { _, _ = io.Copy(conn, backend); done <- struct{}{} }()
	<-done
}

// helloConn is a tunnel as the handshake that reads its hello sees it: it
// reads through the front's reader and writes nothing, so the alert the
// ended handshake sends never reaches the client.
type helloConn struct {
	net.Conn
	r io.Reader
}

func (h helloConn) Read(b []byte) (int, error)  { return h.r.Read(b) }
func (h helloConn) Write(b []byte) (int, error) { return len(b), nil }
