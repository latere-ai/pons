// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package carry

import (
	"bytes"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"strings"

	"latere.ai/x/pons/internal/mcp"
	"latere.ai/x/pons/internal/wire"
)

// MethodToolsCall is the one protocol method whose request names a tool.
const MethodToolsCall = "tools/call"

// message is what Pons reads of the one JSON-RPC message a POST to an MCP
// address carries (specs/008-carrying-a-call.md): its method, empty for a
// reply to a request the server sent, and for tools/call the tool's name.
// Nothing else is decoded.
type message struct {
	method string
	tool   string
}

// The reasons a body is refused, each a 400 invalid_request.
const (
	whyNotAnObject = "not_one_object"
	whyDuplicate   = "duplicate_key"
	whyKeyCase     = "key_case"
	whyMethod      = "method_not_a_string"
	whyToolName    = "tool_name"
	whyMirrored    = "mirrored_header"
)

// parseMessage reads a body as the transport puts one message in it: one
// JSON object whose method, and for tools/call whose params.name, is read
// by exact case. A second method, params or params.name key, or one that
// differs from those by case alone, is refused, so Pons and the connector
// cannot read two different calls from one body. Every other member is
// scanned as far as the JSON grammar needs and not decoded. It answers why
// a body is refused, or "".
func parseMessage(body []byte) (message, string) {
	dec := newScanner(body)
	if tok, err := dec.ReadToken(); err != nil || tok.Kind() != '{' {
		return message{}, whyNotAnObject
	}
	var (
		m                   message
		method, params, has bool
		name                jsontext.Value
	)
	for dec.PeekKind() != '}' {
		key, err := objectKey(dec)
		if err != nil {
			return message{}, whyNotAnObject
		}
		raw, err := dec.ReadValue()
		if err != nil {
			return message{}, whyNotAnObject
		}
		switch {
		case key == "method":
			if method {
				return message{}, whyDuplicate
			}
			method = true
			if json.Unmarshal(raw, &m.method, wire.Foreign) != nil {
				return message{}, whyMethod
			}
		case key == "params":
			if params {
				return message{}, whyDuplicate
			}
			params = true
			var why string
			if name, has, why = paramsName(raw); why != "" {
				return message{}, why
			}
		case strings.EqualFold(key, "method"), strings.EqualFold(key, "params"):
			return message{}, whyKeyCase
		}
	}
	if _, err := dec.ReadToken(); err != nil {
		return message{}, whyNotAnObject
	}
	if _, err := dec.ReadToken(); !errors.Is(err, io.EOF) {
		// A second value after the object: not one message.
		return message{}, whyNotAnObject
	}
	if m.method == MethodToolsCall {
		if !has || json.Unmarshal(name, &m.tool, wire.Foreign) != nil || m.tool == "" {
			return message{}, whyToolName
		}
	}
	return m, ""
}

// newScanner reads a body's tokens. It accepts a repeated member name and
// invalid UTF-8 so the repeat is found and refused here, by the reason
// that names it, and not by the decoder as a body that is no JSON.
func newScanner(b []byte) *jsontext.Decoder {
	return jsontext.NewDecoder(bytes.NewReader(b), jsontext.AllowDuplicateNames(true), jsontext.AllowInvalidUTF8(true))
}

// paramsName reads the name member of params when params is an object, by
// exact case and once, and nothing else of it.
func paramsName(raw jsontext.Value) (jsontext.Value, bool, string) {
	dec := newScanner(raw)
	if tok, err := dec.ReadToken(); err != nil || tok.Kind() != '{' {
		// params that is no object names no tool.
		return nil, false, ""
	}
	var name jsontext.Value
	has := false
	for dec.PeekKind() != '}' {
		key, err := objectKey(dec)
		if err != nil {
			return nil, false, whyNotAnObject
		}
		value, err := dec.ReadValue()
		if err != nil {
			return nil, false, whyNotAnObject
		}
		switch {
		case key == "name":
			if has {
				return nil, false, whyDuplicate
			}
			name, has = value.Clone(), true
		case strings.EqualFold(key, "name"):
			return nil, false, whyKeyCase
		}
	}
	return name, has, ""
}

// objectKey reads the next key of an object.
func objectKey(dec *jsontext.Decoder) (string, error) {
	tok, err := dec.ReadToken()
	if err != nil {
		return "", err
	}
	if tok.Kind() != '"' {
		return "", errors.New("carry: an object key that is not a string")
	}
	return tok.String(), nil
}

// mirroredDiffers reports whether a header the transport mirrors from the
// body says otherwise than the body: Mcp-Method against the method, and for
// tools/call Mcp-Name against the tool, each after its base64 form is
// decoded. A header that is absent is not compared.
func mirroredDiffers(h http.Header, m message) bool {
	differs := func(name, want string) bool {
		values := h.Values(name)
		if len(values) == 0 {
			return false
		}
		got, ok := mcp.HeaderValue(values[0])
		return len(values) > 1 || !ok || got != want
	}
	if differs(mcp.HeaderMethod, m.method) {
		return true
	}
	return m.method == MethodToolsCall && differs(mcp.HeaderName, m.tool)
}
