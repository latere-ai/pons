// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package carry

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"latere.ai/x/pons/internal/mcp"
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
	dec := json.NewDecoder(bytes.NewReader(body))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return message{}, whyNotAnObject
	}
	var (
		m                   message
		method, params, has bool
		name                json.RawMessage
	)
	for dec.More() {
		key, err := objectKey(dec)
		if err != nil {
			return message{}, whyNotAnObject
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return message{}, whyNotAnObject
		}
		switch {
		case key == "method":
			if method {
				return message{}, whyDuplicate
			}
			method = true
			if json.Unmarshal(raw, &m.method) != nil {
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
	if _, err := dec.Token(); err != nil {
		return message{}, whyNotAnObject
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		// A second value after the object: not one message.
		return message{}, whyNotAnObject
	}
	if m.method == MethodToolsCall {
		if !has || json.Unmarshal(name, &m.tool) != nil || m.tool == "" {
			return message{}, whyToolName
		}
	}
	return m, ""
}

// paramsName reads the name member of params when params is an object, by
// exact case and once, and nothing else of it.
func paramsName(raw json.RawMessage) (json.RawMessage, bool, string) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		// params that is no object names no tool.
		return nil, false, ""
	}
	var name json.RawMessage
	has := false
	for dec.More() {
		key, err := objectKey(dec)
		if err != nil {
			return nil, false, whyNotAnObject
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, false, whyNotAnObject
		}
		switch {
		case key == "name":
			if has {
				return nil, false, whyDuplicate
			}
			name, has = value, true
		case strings.EqualFold(key, "name"):
			return nil, false, whyKeyCase
		}
	}
	return name, has, ""
}

// objectKey reads the next key of an object.
func objectKey(dec *json.Decoder) (string, error) {
	tok, err := dec.Token()
	if err != nil {
		return "", err
	}
	key, ok := tok.(string)
	if !ok {
		return "", errors.New("carry: an object key that is not a string")
	}
	return key, nil
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
