// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package apierr is the error table of specs/003-api.md, shared by every
// surface that answers in its shape: the API's routes, the addresses a
// caller uses, and the sign-in. An error has one code, one fixed sentence a
// person reads in message, and the developer detail of its instance apart.
package apierr

import (
	"errors"

	"fmt"
	"maps"
	"net/http"
	"regexp"

	"latere.ai/x/pons/internal/access"

	"latere.ai/x/pkg/httpjson"
)

// Status is the status of a code, and 500 for a code the table lacks.
func Status(code string) int {
	if k, ok := table[code]; ok {
		return k.status
	}
	return table[CodeInternal].status
}

// Message is the fixed sentence a person reads for a code, and "" for a code
// the table lacks.
func Message(code string) string { return table[code].message }

// Codes lists every code of the table.
func Codes() []string {
	out := make([]string, 0, len(table))
	for c := range table {
		out = append(out, c)
	}
	return out
}

// Write answers an error in the shape of specs/003-api.md, with Retry-After
// on a refusal of a rate, and returns the classified error so the caller
// logs one nobody classified.
func Write(w http.ResponseWriter, err error) *Error {
	e := Classify(err)
	status, body := e.Envelope()
	if body.Code == CodeRateLimited && w.Header().Get("Retry-After") == "" {
		w.Header().Set("Retry-After", "1")
	}
	httpjson.WriteError(w, status, body)
	return e
}

// Token is the error of a bearer the verifier refused: missing_token for a
// request that carries none, invalid_token with the verifier's word for why
// for one it refused, and internal for anything else.
func Token(err error) *Error {
	var te *access.TokenError
	switch {
	case errors.Is(err, access.ErrMissingToken):
		return Fail(CodeMissingToken, "")
	case errors.As(err, &te):
		e := Fail(CodeInvalidToken, te.Reason)
		e.Retryable = &te.Retryable
		return e
	}
	return Internal(err)
}

// Cause is the error an unclassified error was made from, for its log, and
// e itself otherwise.
func (e *Error) Cause() error {
	if e.cause != nil {
		return e.cause
	}
	return e
}

// The error codes of specs/003-api.md.
const (
	CodeInvalidRequest         = "invalid_request"
	CodeUnknownField           = "unknown_field"
	CodeInvalidField           = "invalid_field"
	CodeMissingField           = "missing_field"
	CodeImmutableField         = "immutable_field"
	CodeInvalidCode            = "invalid_code"
	CodeMissingToken           = "missing_token"
	CodeInvalidToken           = "invalid_token"
	CodeForbidden              = "forbidden"
	CodeConnectorNotFound      = "connector_not_found"
	CodeConnectionNotFound     = "connection_not_found"
	CodeNameTaken              = "name_taken"
	CodeConnectorInUse         = "connector_in_use"
	CodeConnectorLimit         = "connector_limit"
	CodeConnectorDisabled      = "connector_disabled"
	CodeConnectionNotConnected = "connection_not_connected"
	CodeWrongKind              = "wrong_kind"
	CodeFlowExpired            = "flow_expired"
	CodeRequestTooLarge        = "request_too_large"
	CodeConnectorUnreachable   = "connector_unreachable"
	CodeSignInUnsupported      = "sign_in_unsupported"
	CodeServerUnreachable      = "server_unreachable"
	CodeAuthMismatch           = "auth_mismatch"
	CodeCredentialRefused      = "credential_refused"
	CodeRateLimited            = "rate_limited"
	CodeInternal               = "internal"
	CodeConnectorUnavailable   = "connector_unavailable"
	CodeAuthorizerUnavailable  = "authorizer_unavailable"
	CodeSealingUnavailable     = "sealing_unavailable"
	CodeConnectorTimeout       = "connector_timeout"
)

// kind is one row of the error table: the status of a code, the one
// sentence a person reads for it, and whether the same request may succeed
// later unless the instance says otherwise.
type kind struct {
	status    int
	message   string
	retryable bool
}

// table is the error table of specs/003-api.md with the fixed sentence of
// each code.
var table = map[string]kind{
	CodeInvalidRequest:         {http.StatusBadRequest, "The request could not be read.", false},
	CodeUnknownField:           {http.StatusBadRequest, "The request has a member this API does not take.", false},
	CodeInvalidField:           {http.StatusBadRequest, "A member of the request is not valid.", false},
	CodeMissingField:           {http.StatusBadRequest, "A required member of the request is missing.", false},
	CodeImmutableField:         {http.StatusBadRequest, "This member of a connector cannot be changed. Add the server again instead.", false},
	CodeInvalidCode:            {http.StatusBadRequest, "The sign-in could not be confirmed. Start it again.", false},
	CodeMissingToken:           {http.StatusUnauthorized, "This request needs a token.", false},
	CodeInvalidToken:           {http.StatusUnauthorized, "The token of this request was not accepted.", false},
	CodeForbidden:              {http.StatusForbidden, "You are not allowed to do this.", false},
	CodeConnectorNotFound:      {http.StatusNotFound, "This connector does not exist.", false},
	CodeConnectionNotFound:     {http.StatusNotFound, "This connection does not exist.", false},
	CodeNameTaken:              {http.StatusConflict, "That name is already in use.", false},
	CodeConnectorInUse:         {http.StatusConflict, "A connection still uses this connector.", false},
	CodeConnectorLimit:         {http.StatusConflict, "No more connectors can be added here. Remove one first.", false},
	CodeConnectorDisabled:      {http.StatusConflict, "This connector is turned off.", false},
	CodeConnectionNotConnected: {http.StatusConflict, "This connection needs to be connected again.", false},
	CodeWrongKind:              {http.StatusConflict, "This connection does not take this request.", false},
	CodeFlowExpired:            {http.StatusGone, "This sign-in has expired. Start it again.", false},
	CodeRequestTooLarge:        {http.StatusRequestEntityTooLarge, "The request is too large.", false},
	CodeConnectorUnreachable:   {http.StatusUnprocessableEntity, "The service could not be reached.", false},
	CodeSignInUnsupported:      {http.StatusUnprocessableEntity, "This service cannot be connected by signing in.", false},
	CodeServerUnreachable:      {http.StatusUnprocessableEntity, "No server that can be connected answered at this address.", false},
	CodeAuthMismatch:           {http.StatusUnprocessableEntity, "This server asks for a different way to connect than the one given.", false},
	CodeCredentialRefused:      {http.StatusUnprocessableEntity, "The service did not accept this credential.", false},
	CodeRateLimited:            {http.StatusTooManyRequests, "Too many requests. Try again in a moment.", true},
	CodeInternal:               {http.StatusInternalServerError, "Something went wrong on our side.", false},
	CodeConnectorUnavailable:   {http.StatusBadGateway, "The service is not available right now.", true},
	CodeAuthorizerUnavailable:  {http.StatusServiceUnavailable, "Access cannot be checked right now. Try again in a moment.", true},
	CodeSealingUnavailable:     {http.StatusServiceUnavailable, "Credentials cannot be kept or used right now.", false},
	CodeConnectorTimeout:       {http.StatusGatewayTimeout, "The service did not answer in time.", true},
}

// Error is an error a route answers with: one code of the table, and the
// developer detail of this instance. The sentence a person reads is the
// code's and never built from the instance.
type Error struct {
	Code string
	// Reason says what happened in this instance, one word or a limit and
	// its figure.
	Reason string
	// Field is the member of the request the error is about.
	Field string
	// Extra are further members of details, such as a connection's state.
	Extra map[string]any
	// Retryable, when set, overrides the code's own.
	Retryable *bool
	// cause is kept for the log of an unclassified error and is never
	// rendered.
	cause error
}

func (e *Error) Error() string {
	s := "apierr: " + e.Code
	if e.Reason != "" {
		s += ": " + e.Reason
	}
	if e.Field != "" {
		s += " (" + e.Field + ")"
	}
	return s
}

// Unwrap is the cause.
func (e *Error) Unwrap() error { return e.cause }

// Fail builds an error of a code.
func Fail(code, reason string) *Error { return &Error{Code: code, Reason: reason} }

// OnField builds an error about one member of the request.
func OnField(code, field, reason string) *Error {
	return &Error{Code: code, Field: field, Reason: reason}
}

// Internal is an error nobody classified. Its text is logged and never
// answered.
func Internal(err error) *Error { return &Error{Code: CodeInternal, cause: err} }

// Envelope renders an error as the status and the body a route answers.
func (e *Error) Envelope() (int, httpjson.Error) {
	k, ok := table[e.Code]
	if !ok || e.Code == CodeInternal {
		k = table[CodeInternal]
		return k.status, httpjson.Error{Code: CodeInternal, Message: k.message}
	}
	details := map[string]any{}
	maps.Copy(details, e.Extra)
	if e.Reason != "" {
		details["reason"] = e.Reason
	}
	if e.Field != "" {
		details["field"] = e.Field
	}
	retryable := k.retryable
	if e.Retryable != nil {
		retryable = *e.Retryable
	}
	details["retryable"] = retryable
	return k.status, httpjson.Error{Code: e.Code, Message: k.message, Details: details}
}

// Classify is the route error of any error.
func Classify(err error) *Error {
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return Internal(err)
}

// query matches the query of a URL in an error's text: a transport error can
// hold the whole URL it was asked for.
var query = regexp.MustCompile(`(https?://[^\s?#"']*)[?#][^\s"']*`)

// CutQueries removes the query and fragment of every URL in a text, so a
// logged error keeps the scheme, the host and the path alone.
func CutQueries(s string) string { return query.ReplaceAllString(s, "$1") }

// LogText is the text of an unclassified error as it is logged.
func LogText(err error) string {
	if err == nil {
		return ""
	}
	return CutQueries(fmt.Sprint(err))
}
