// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package wire_test

import (
	"encoding/json/v2"
	"testing"

	"latere.ai/x/pons/internal/wire"
)

// Foreign reads a repeated member as its last, a name in any letter case,
// and bytes that are no UTF-8.
func TestForeignIsLenient(t *testing.T) {
	var v struct {
		Name string `json:"name"`
		N    int    `json:"n"`
	}
	if err := json.Unmarshal([]byte("{\"NAME\":\"a\xff\",\"n\":1,\"N\":2}"), &v, wire.Foreign); err != nil {
		t.Fatal(err)
	}
	if v.Name != "a�" || v.N != 2 {
		t.Fatalf("%+v", v)
	}
	if err := json.Unmarshal([]byte(`{"n":1,"n":2}`), &v); err == nil {
		t.Error("the defaults accept a repeated member")
	}
}

// Outbound writes members in key order and a nil list or map as null, and
// Stored writes the same order and leaves a nil list as the defaults do.
func TestOutboundAndStoredBytes(t *testing.T) {
	type doc struct {
		B    string         `json:"b"`
		A    []string       `json:"a"`
		M    map[string]int `json:"m"`
		Text string         `json:"text"`
	}
	v := doc{B: "x", Text: "bad\xffbyte"}
	got, err := json.Marshal(v, wire.Outbound)
	if err != nil {
		t.Fatal(err)
	}
	if want := "{\"b\":\"x\",\"a\":null,\"m\":null,\"text\":\"bad�byte\"}"; string(got) != want {
		t.Errorf("outbound %s, want %s", got, want)
	}
	m := map[string]any{"z": 1, "a": 2, "m": map[string]int{"y": 1, "b": 2}}
	for i := range 20 {
		for name, opts := range map[string]json.Options{"outbound": wire.Outbound, "stored": wire.Stored} {
			got, err := json.Marshal(m, opts)
			if err != nil {
				t.Fatal(err)
			}
			if want := `{"a":2,"m":{"b":2,"y":1},"z":1}`; string(got) != want {
				t.Fatalf("%s %d: %s", name, i, got)
			}
		}
	}
	got, err = json.Marshal(v, wire.Stored)
	if err != nil {
		t.Fatal(err)
	}
	if want := "{\"b\":\"x\",\"a\":[],\"m\":{},\"text\":\"bad�byte\"}"; string(got) != want {
		t.Errorf("stored %s, want %s", got, want)
	}
}
