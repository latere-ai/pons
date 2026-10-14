// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package mcp holds what Pons itself says in the Model Context Protocol
// over streamable HTTP (specs/008-carrying-a-call.md): the revisions it
// speaks, the requests of the probe, which tries a key and makes the first
// request of discovery, and the reading of a header the transport mirrors
// from a body. A caller's own messages are carried unread and never built
// here.
package mcp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"

	"latere.ai/x/pons/internal/version"
)

// The revisions Pons speaks when it sends a request of its own: Revision
// first, and Legacy in the handshake of a connector of an earlier one.
const (
	Revision = "2026-07-28"
	Legacy   = "2025-11-25"
)

// The JSON-RPC error codes the current revision defines. A 400 whose body
// is an error of another code, or no JSON-RPC error at all, comes from a
// connector of an earlier revision.
const (
	minModernCode = -32099
	maxModernCode = -32020
)

// The headers of the transport Pons reads or sets.
const (
	HeaderVersion = "MCP-Protocol-Version"
	HeaderMethod  = "Mcp-Method"
	HeaderName    = "Mcp-Name"
	HeaderSession = "Mcp-Session-Id"
)

// base64Form is the form the transport gives a mirrored value that is not
// plain ASCII: =?base64?<standard base64>?=.
const (
	base64Open  = "=?base64?"
	base64Close = "?="
)

// HeaderValue is a mirrored header's value as the body holds it: the
// value itself, or its base64 form decoded. ok is false for a base64 form
// that does not decode.
func HeaderValue(v string) (string, bool) {
	inner, open := strings.CutPrefix(v, base64Open)
	if !open {
		return v, true
	}
	inner, closed := strings.CutSuffix(inner, base64Close)
	if !closed {
		return v, true
	}
	b, err := base64.StdEncoding.DecodeString(inner)
	if err != nil {
		return "", false
	}
	return string(b), true
}

// ModernError reports whether a body is a JSON-RPC error of the current
// revision.
func ModernError(body []byte) bool {
	var r struct {
		JSONRPC string `json:"jsonrpc"`
		Error   *struct {
			Code *int `json:"code"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &r) != nil || r.JSONRPC != "2.0" || r.Error == nil || r.Error.Code == nil {
		return false
	}
	return *r.Error.Code >= minModernCode && *r.Error.Code <= maxModernCode
}

// clientInfo is how Pons names itself in a request of its own.
func clientInfo() map[string]string {
	return map[string]string{"name": "pons", "version": version.Version}
}

// ListTools is the probe's request of the current revision: a POST of
// tools/list to url whose _meta carries the protocol version, Pons as the
// client and empty client capabilities, with the headers the revision
// requires.
func ListTools(ctx context.Context, url string) (*http.Request, error) {
	body := map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": map[string]any{
		"_meta": map[string]any{
			"io.modelcontextprotocol/protocolVersion":    Revision,
			"io.modelcontextprotocol/clientInfo":         clientInfo(),
			"io.modelcontextprotocol/clientCapabilities": map[string]any{},
		},
	}}
	req, err := post(ctx, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set(HeaderVersion, Revision)
	req.Header.Set(HeaderMethod, "tools/list")
	return req, nil
}

// Initialize is the handshake's first request of the earlier revision.
func Initialize(ctx context.Context, url string) (*http.Request, error) {
	return post(ctx, url, map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]any{
		"protocolVersion": Legacy, "capabilities": map[string]any{}, "clientInfo": clientInfo(),
	}})
}

// Initialized is the notification that ends the earlier revision's
// handshake, in the session it opened at the version it negotiated.
func Initialized(ctx context.Context, url, session, negotiated string) (*http.Request, error) {
	req, err := post(ctx, url, map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
	if err != nil {
		return nil, err
	}
	inSession(req, session, negotiated)
	return req, nil
}

// ListToolsIn is tools/list of the earlier revision, in a session.
func ListToolsIn(ctx context.Context, url, session, negotiated string) (*http.Request, error) {
	req, err := post(ctx, url, map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
	if err != nil {
		return nil, err
	}
	inSession(req, session, negotiated)
	return req, nil
}

// End is the DELETE that ends a session of the earlier revision.
func End(ctx context.Context, url, session, negotiated string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return nil, err
	}
	inSession(req, session, negotiated)
	return req, nil
}

// Negotiated reads the protocol version an initialize answer names, from a
// JSON body or the first data line of an event stream that holds one;
// Legacy when it names none Pons can read.
func Negotiated(body []byte) string {
	for line := range bytes.SplitSeq(body, []byte("\n")) {
		if data, ok := bytes.CutPrefix(bytes.TrimSpace(line), []byte("data:")); ok {
			body = bytes.TrimSpace(data)
			break
		}
	}
	var r struct {
		Result struct {
			ProtocolVersion string `json:"protocolVersion"`
		} `json:"result"`
	}
	if json.Unmarshal(body, &r) != nil || r.Result.ProtocolVersion == "" {
		return Legacy
	}
	return r.Result.ProtocolVersion
}

// post is a POST of one JSON-RPC message with the transport's content
// headers.
func post(ctx context.Context, url string, body map[string]any) (*http.Request, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Content-Type", "application/json")
	return req, nil
}

// inSession names the session and the negotiated version on a request of
// the earlier revision.
func inSession(req *http.Request, session, negotiated string) {
	req.Header.Set(HeaderVersion, negotiated)
	if session != "" {
		req.Header.Set(HeaderSession, session)
	}
}
