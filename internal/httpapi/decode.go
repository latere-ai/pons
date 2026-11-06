// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"bytes"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"latere.ai/x/pons/internal/apierr"

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
		return apierr.Fail(apierr.CodeInvalidRequest, "body_unreadable")
	}
	if len(body) > maxBodyBytes {
		return apierr.Fail(apierr.CodeRequestTooLarge, "")
	}
	dec := jsontext.NewDecoder(bytes.NewReader(body))
	// The value is read whole before it is decoded, so a body that is no
	// JSON is told from one that is JSON of another shape.
	value, err := dec.ReadValue()
	if err != nil {
		return decodeError(err)
	}
	if err := json.Unmarshal(value, v, json.RejectUnknownMembers(true)); err != nil {
		return decodeError(err)
	}
	if _, err := dec.ReadValue(); !errors.Is(err, io.EOF) {
		return apierr.Fail(apierr.CodeInvalidRequest, "trailing_data")
	}
	return nil
}

// decodeError names the member a body's error is about.
func decodeError(err error) error {
	var semantic *json.SemanticError
	switch {
	case errors.Is(err, json.ErrUnknownName) && errors.As(err, &semantic):
		names := memberPath(semantic.JSONPointer)
		return apierr.OnField(apierr.CodeUnknownField, names[len(names)-1], "")
	case errors.As(err, &semantic):
		return apierr.OnField(apierr.CodeInvalidField, strings.Join(memberPath(semantic.JSONPointer), "."), "wrong_type")
	}
	return apierr.Fail(apierr.CodeInvalidRequest, "not_json")
}

// memberPath is the names a JSON pointer walks, "" for the body itself. It
// is never empty, so the last name of a pointer to a member is that member.
func memberPath(p jsontext.Pointer) []string {
	var names []string
	for name := range p.Tokens() {
		names = append(names, name)
	}
	if len(names) == 0 {
		return []string{""}
	}
	return names
}

// page reads limit and cursor: 50 by default, 200 at most, and a cursor
// the caller treats as opaque.
func page(r *http.Request) (store.Page, error) {
	p := store.Page{Limit: defaultLimit, Cursor: r.URL.Query().Get("cursor")}
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 {
			return p, apierr.OnField(apierr.CodeInvalidField, "limit", "not_a_positive_number")
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
