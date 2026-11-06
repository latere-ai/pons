// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package signin

import (
	"encoding/json/v2"
	"testing"

	"latere.ai/x/pons/internal/wire"
)

// What an add found is stored by the same bytes: a false iss and an empty
// member are left out.
func TestFoundIsStoredByItsBytes(t *testing.T) {
	for _, tc := range []struct {
		f    Found
		want string
	}{
		{Found{}, `{}`},
		{Found{Issuer: "https://a.example.com", TokenEndpoint: "https://a.example.com/token", Iss: true, Client: ClientOwn},
			`{"issuer":"https://a.example.com","token_endpoint":"https://a.example.com/token","iss":true,"client":"own"}`},
		{Found{Issuer: "https://a.example.com"}, `{"issuer":"https://a.example.com"}`},
	} {
		got, err := json.Marshal(tc.f, wire.Stored)
		if err != nil || string(got) != tc.want {
			t.Errorf("%+v: %s %v, want %s", tc.f, got, err, tc.want)
		}
	}
}

// An answer from an authorization server is read with a repeated member
// and invalid UTF-8 in it, as some servers send them.
func TestMembersOfAnAnswerAreReadLeniently(t *testing.T) {
	m, err := members([]byte("{\"Access_Token\":\"a\xff\",\"expires_in\":1,\"expires_in\":3600}"))
	if err != nil {
		t.Fatal(err)
	}
	if number(m["expires_in"]) != 3600 {
		t.Errorf("%+v", m)
	}
}
