// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package httpapi

import (
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"latere.ai/x/pons/internal/apierr"
)

// A body that is no JSON, trailing data, an unknown member and a member of
// the wrong type are each told apart, and the member is named by its path.
func TestDecodeNamesWhatIsWrong(t *testing.T) {
	type inner struct {
		C []int `json:"c"`
	}
	type body struct {
		A int   `json:"a"`
		B inner `json:"b"`
	}
	for _, tc := range []struct {
		in, code, field, reason string
	}{
		{`{"a":1}`, "", "", ""},
		{``, apierr.CodeInvalidRequest, "", "not_json"},
		{`x`, apierr.CodeInvalidRequest, "", "not_json"},
		{`[`, apierr.CodeInvalidRequest, "", "not_json"},
		{`{"a":1} {}`, apierr.CodeInvalidRequest, "", "trailing_data"},
		{`{"a":1} x`, apierr.CodeInvalidRequest, "", "trailing_data"},
		{`{"a":1,"zz":2}`, apierr.CodeUnknownField, "zz", ""},
		{`{"b":{"zz":2}}`, apierr.CodeUnknownField, "zz", ""},
		{`{"a":"x"}`, apierr.CodeInvalidField, "a", "wrong_type"},
		{`{"b":{"c":["x"]}}`, apierr.CodeInvalidField, "b.c.0", "wrong_type"},
		{`{"A":1}`, apierr.CodeUnknownField, "A", ""},
	} {
		var v body
		err := decode(httptest.NewRequest("POST", "/", strings.NewReader(tc.in)), &v)
		if tc.code == "" {
			if err != nil {
				t.Errorf("%q: %v", tc.in, err)
			}
			continue
		}
		var e *apierr.Error
		if !errors.As(err, &e) || e.Code != tc.code || e.Field != tc.field || e.Reason != tc.reason {
			t.Errorf("%q: %#v", tc.in, err)
		}
	}
}
