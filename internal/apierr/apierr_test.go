// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package apierr_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"latere.ai/x/pons/internal/apierr"
)

// Write answers the error's code with its sentence and the instance's
// detail, a rate refusal with Retry-After, and an error nobody classified as
// internal with its cause kept for the log alone.
func TestWrite(t *testing.T) {
	rec := httptest.NewRecorder()
	e := apierr.Write(rec, &apierr.Error{Code: apierr.CodeConnectionNotConnected, Reason: "revoked", Extra: map[string]any{"state": "needs_reconnect"}})
	var body struct {
		Error struct {
			Code    string         `json:"code"`
			Message string         `json:"message"`
			Details map[string]any `json:"details"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusConflict || body.Error.Details["state"] != "needs_reconnect" || body.Error.Details["reason"] != "revoked" || e.Cause().Error() != e.Error() {
		t.Fatalf("%d %+v", rec.Code, body)
	}
	rec = httptest.NewRecorder()
	apierr.Write(rec, apierr.Fail(apierr.CodeRateLimited, "calls_per_minute=1"))
	if rec.Header().Get("Retry-After") != "1" {
		t.Fatal("a rate refusal has no Retry-After")
	}
	cause := errors.New("a cause with https://api.example.com/x?token=t in it")
	rec = httptest.NewRecorder()
	e = apierr.Write(rec, cause)
	if rec.Code != http.StatusInternalServerError || !errors.Is(e.Cause(), cause) || !errors.Is(e, cause) {
		t.Fatalf("%d %v", rec.Code, e)
	}
	if got := apierr.OnField(apierr.CodeInvalidField, "name", "x").Error(); got != "apierr: invalid_field: x (name)" {
		t.Fatalf("%q", got)
	}
}
