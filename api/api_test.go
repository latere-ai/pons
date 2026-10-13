// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package api_test

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"latere.ai/x/pons/api"
	"latere.ai/x/pons/internal/httpapi"
)

// document is the contract, read.
type document struct {
	Paths      map[string]map[string]any `yaml:"paths"`
	Components struct {
		Schemas map[string]struct {
			Properties map[string]any `yaml:"properties"`
		} `yaml:"schemas"`
	} `yaml:"components"`
}

func read(t *testing.T) document {
	t.Helper()
	var d document
	if err := yaml.Unmarshal(api.OpenAPI, &d); err != nil {
		t.Fatal(err)
	}
	return d
}

var param = regexp.MustCompile(`\{[^}]+\}`)

// The document describes every route the server serves and no other.
// OpenAPI holds two templates of one shape as one path, so a route is
// compared with its parameters' names dropped.
func TestDocumentMatchesTheRoutes(t *testing.T) {
	documented := map[string]bool{}
	for path, item := range read(t).Paths {
		for method := range item {
			documented[strings.ToUpper(method)+" "+param.ReplaceAllString(path, "{}")] = true
		}
	}
	served := map[string]bool{}
	for _, rt := range httpapi.Routes() {
		served[rt.Method+" "+param.ReplaceAllString(rt.Path, "{}")] = true
	}
	for r := range served {
		if !documented[r] {
			t.Errorf("%s is served and not documented", r)
		}
	}
	for r := range documented {
		if !served[r] {
			t.Errorf("%s is documented and not served", r)
		}
	}
}

// fields are the members of one table of spec 002, by the heading above it.
func fields(t *testing.T, heading string) []string {
	t.Helper()
	f, err := os.Open(filepath.Join("..", "specs", "002-objects.md"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			t.Error(err)
		}
	}()
	member := regexp.MustCompile("`([a-z_.]+)`")
	var out []string
	in := false
	scan := bufio.NewScanner(f)
	for scan.Scan() {
		line := scan.Text()
		switch {
		case strings.HasPrefix(line, "### "):
			in = line == "### "+heading
		case in && strings.HasPrefix(line, "| `"):
			cell := strings.SplitN(line, "|", 3)[1]
			for _, m := range member.FindAllStringSubmatch(cell, -1) {
				name, _, _ := strings.Cut(m[1], ".")
				if !slices.Contains(out, name) {
					out = append(out, name)
				}
			}
		}
	}
	if err := scan.Err(); err != nil {
		t.Fatal(err)
	}
	slices.Sort(out)
	return out
}

// The JSON of a connector, a connection and a call record has exactly the
// fields of the tables of spec 002 and no credential member.
func TestObjectShapes(t *testing.T) {
	d := read(t)
	for schema, heading := range map[string]string{"Connector": "Connector", "Connection": "Connection", "Call": "Call record"} {
		var have []string
		for name := range d.Components.Schemas[schema].Properties {
			have = append(have, name)
		}
		slices.Sort(have)
		want := fields(t, heading)
		if len(want) < 10 || !slices.Equal(have, want) {
			t.Errorf("%s has %v, spec 002 lists %v", schema, have, want)
		}
		for _, name := range have {
			if strings.Contains(name, "secret") || strings.Contains(name, "token") || name == "credential" || name == "value" {
				t.Errorf("%s carries %s", schema, name)
			}
		}
	}
}
