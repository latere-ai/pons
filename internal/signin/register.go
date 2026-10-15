// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package signin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"

	"latere.ai/x/pons/internal/apierr"
	"latere.ai/x/pons/internal/dial"
	"latere.ai/x/pons/internal/store"
)

// Document is a client metadata document: how Pons names itself to an
// authorization server that takes a URL as a client id
// (specs/007-sign-in.md).
type Document struct {
	ClientID                string   `json:"client_id,omitempty"`
	ClientName              string   `json:"client_name"`
	ClientURI               string   `json:"client_uri,omitempty"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	ApplicationType         string   `json:"application_type,omitempty"`
}

// ClientDocument is the client metadata document of the catalog's
// connectors, or of an added connector when title is given: its own
// address as client_id, the one redirect address its sign-ins use, and no
// secret.
func (s *Signin) ClientDocument(id, title, redirect string) Document {
	name := s.ClientName
	if title != "" {
		name += " for " + title
	}
	return Document{
		ClientID: s.ClientDocumentURL(id), ClientName: name, ClientURI: s.ClientURI,
		RedirectURIs: []string{redirect}, GrantTypes: []string{"authorization_code", "refresh_token"},
		ResponseTypes: []string{"code"}, TokenEndpointAuthMethod: "none",
	}
}

// maxRegistrationAnswer bounds a registration endpoint's answer.
const maxRegistrationAnswer = 1 << 20

// register is the client Pons is at an issuer by dynamic registration (RFC
// 7591): the registration kept for the issuer and the redirect address, or
// a new one, its secret sealed. Of two replicas that register at once the
// store keeps the first row, which both use.
func (s *Signin) register(ctx context.Context, conn Connector, md metadataDocument, redirect string) (string, error) {
	reg, err := s.Store.Registrations().Get(ctx, md.Issuer, redirect)
	switch {
	case err == nil:
		return reg.ClientID, nil
	case !errors.Is(err, store.ErrNotFound):
		return "", apierr.Internal(err)
	}
	doc := s.ClientDocument("", "", redirect)
	doc.ClientID = ""
	doc.ApplicationType = "web"
	if u, err := url.Parse(s.PublicURL); err == nil {
		if ip := net.ParseIP(u.Hostname()); u.Hostname() == "localhost" || (ip != nil && ip.IsLoopback()) {
			doc.ApplicationType = "native"
		}
	}
	body, err := json.Marshal(doc)
	if err != nil {
		return "", apierr.Internal(err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, md.RegistrationEndpoint, bytes.NewReader(body))
	if err != nil {
		return "", unsupported("registration_endpoint")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := s.Dial.Do(ctx, dial.Request{HTTP: req, Ports: conn.Ports(), Timeout: tokenTimeout, MaxBody: maxRegistrationAnswer})
	if err != nil {
		return "", unreachable(err)
	}
	raw, err := io.ReadAll(resp.Body)
	if cerr := resp.Body.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", unreachable(err)
	}
	var answer struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 || json.Unmarshal(raw, &answer) != nil || answer.ClientID == "" {
		return "", unsupported("registration")
	}
	row := store.Registration{Issuer: md.Issuer, RedirectURI: redirect, ClientID: answer.ClientID, RegisteredAt: s.now()}
	if answer.ClientSecret != "" {
		sealed, err := s.Sealer.Seal([]byte(answer.ClientSecret), store.RegistrationBinding(md.Issuer, redirect))
		switch {
		case errors.Is(err, store.ErrNoSealingKey):
			return "", apierr.Fail(apierr.CodeSealingUnavailable, "no_sealing_key")
		case err != nil:
			return "", apierr.Internal(err)
		}
		row.Secret = sealed
	}
	kept, err := s.Store.Registrations().Put(ctx, row)
	if err != nil {
		return "", apierr.Internal(err)
	}
	return kept.ClientID, nil
}

// forget deletes a registration the server no longer knows, at the shared
// callback or the issuer's own, so the next sign-in at the issuer
// registers again.
func (s *Signin) forget(ctx context.Context, issuer, clientID string) {
	for _, redirect := range []string{s.RedirectURI(), s.CallbackFor(issuer)} {
		reg, err := s.Store.Registrations().Get(ctx, issuer, redirect)
		if err != nil || reg.ClientID != clientID {
			continue
		}
		if err := s.Store.Registrations().Delete(ctx, issuer, redirect); err != nil {
			s.log().WarnContext(ctx, "a refused registration was not deleted", "error", err.Error())
		}
	}
}
