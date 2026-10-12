// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package stubs

import (
	"errors"
	"strings"
	"testing"
)

// must passes a value through and panics, naming the error, on a failure.
func TestMust(t *testing.T) {
	if must(1, nil) != 1 {
		t.Fatal("must changed a value")
	}
	defer func() {
		if r := recover(); r == nil || !strings.Contains(r.(string), "no randomness") {
			t.Fatalf("recovered %v", r)
		}
	}()
	must(0, errors.New("no randomness"))
}
