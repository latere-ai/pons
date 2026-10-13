// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/tls"
	"maps"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"latere.ai/x/pons/test/stubs"
)

// browser stands for the person: it follows the sign-in's redirects by
// hand, reaching a stub by its name on loopback and the server where the
// test started it, and stops at the first address that is neither: the
// client's return address. It answers that address, or the status of an
// answer that sent the browser nowhere.
func (s *stack) browser(t testing.TB, address string) (*url.URL, int) {
	t.Helper()
	dialer := &net.Dialer{}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: stubs.Roots(), MinVersion: tls.VersionTLS12},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				if host, port, err := net.SplitHostPort(addr); err == nil && strings.HasSuffix(host, "."+stubs.Domain) {
					addr = net.JoinHostPort("127.0.0.1", port)
				}
				return dialer.DialContext(ctx, network, addr)
			},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	next := address
	for range 6 {
		// Every address the server hands out starts with its public URL;
		// it listens where the test started it.
		next = strings.Replace(next, s.env["PONS_PUBLIC_URL"], s.base, 1)
		u, err := url.Parse(next)
		if err != nil {
			t.Fatal(err)
		}
		if u.Host == "app.example.com" {
			return u, http.StatusFound
		}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, next, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if err := resp.Body.Close(); err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(next, s.base+"/v1/callback") {
			called.Lock()
			called.routes["GET /callback"] = true
			called.Unlock()
			for _, h := range []string{"Cache-Control", "Referrer-Policy"} {
				if resp.Header.Get(h) == "" {
					t.Errorf("the callback's answer has no %s", h)
				}
			}
		}
		loc := resp.Header.Get("Location")
		if loc == "" {
			return nil, resp.StatusCode
		}
		ref, err := u.Parse(loc)
		if err != nil {
			t.Fatal(err)
		}
		next = ref.String()
	}
	t.Fatalf("the sign-in did not return from %s", address)
	return nil, 0
}

// started is the answer of a connect or a reconnect by sign-in.
type started struct {
	id, address string
}

// startSignIn connects a connector whose people sign in, as sub.
func (s *stack) startSignIn(t testing.TB, sub, connector string, extra map[string]any) started {
	t.Helper()
	body := map[string]any{"connector": connector, "return_to": returnURL}
	maps.Copy(body, extra)
	a := s.do(http.MethodPost, "/v1/connections", sub, body)
	if a.status != http.StatusCreated {
		t.Fatalf("connect %s: %d %s", connector, a.status, a.body)
	}
	v := a.json(t)
	conn := v["connection"].(map[string]any)
	if conn["state"] != "pending" {
		t.Fatalf("a sign-in's connection %v", conn)
	}
	return started{id: conn["id"].(string), address: v["authorization_url"].(string)}
}

// signIn runs a whole sign-in as sub: the connect, the browser, and the
// confirm with the code it brought back. It answers the connection.
func (s *stack) signIn(t testing.TB, sub, connector string) map[string]any {
	t.Helper()
	st := s.startSignIn(t, sub, connector, nil)
	back, _ := s.browser(t, st.address)
	if back == nil || back.Query().Get("connection") != st.id || back.Query().Get("code") == "" {
		t.Fatalf("the browser came back to %v", back)
	}
	a := s.do(http.MethodPost, "/v1/connections/"+st.id+"/confirm", sub, map[string]any{"code": back.Query().Get("code")})
	if a.status != http.StatusOK || a.json(t)["state"] != "connected" {
		t.Fatalf("confirm: %d %s", a.status, a.body)
	}
	return a.json(t)
}
