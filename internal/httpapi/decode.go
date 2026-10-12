// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"latere.ai/x/pons/internal/store"
)

// The bounds of a page.
const (
	defaultLimit = 50
	maxLimit     = 200
)

// decode reads a JSON body into v: one object, no member the contract does
// not describe, nothing after it. The errors are the contract's.
func decode(r *http.Request, v any) error {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err != nil {
		return fail(CodeInvalidRequest, "body_unreadable")
	}
	if len(body) > maxBodyBytes {
		return fail(CodeRequestTooLarge, "")
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return decodeError(err)
	}
	if dec.More() {
		return fail(CodeInvalidRequest, "trailing_data")
	}
	return nil
}

// decodeError names the member a body's error is about.
func decodeError(err error) error {
	var typeErr *json.UnmarshalTypeError
	switch {
	case strings.HasPrefix(err.Error(), "json: unknown field "):
		name := strings.Trim(strings.TrimPrefix(err.Error(), "json: unknown field "), `"`)
		return onField(CodeUnknownField, name, "")
	case errors.As(err, &typeErr):
		return onField(CodeInvalidField, typeErr.Field, "wrong_type")
	}
	return fail(CodeInvalidRequest, "not_json")
}

// page reads limit and cursor: 50 by default, 200 at most, and a cursor
// the caller treats as opaque.
func page(r *http.Request) (store.Page, error) {
	p := store.Page{Limit: defaultLimit, Cursor: r.URL.Query().Get("cursor")}
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 {
			return p, onField(CodeInvalidField, "limit", "not_a_positive_number")
		}
		p.Limit = min(n, maxLimit)
	}
	return p, nil
}

// list is the envelope of a page.
type list[T any] struct {
	Items      []T    `json:"items"`
	NextCursor string `json:"next_cursor,omitempty"`
}
