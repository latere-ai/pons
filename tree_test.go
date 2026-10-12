// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// The tests of this file hold rules about the whole module that no one
// package can: which package dials, which reads the environment, which
// imports the database driver, and who opens a sealed value. Each reads
// the source, so a rule broken by a new file fails here.
package pons_test

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"io/fs"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"

	"latere.ai/x/pons/internal/store"
)

const module = "latere.ai/x/pons"

// source is one parsed Go file of the module.
type source struct {
	rel  string // the slash path from the module root
	pkg  string // the slash directory, the package's path below the module
	test bool
	file *ast.File
}

// sources parses every Go file of the module.
func sources(t *testing.T) []source {
	t.Helper()
	var out []source
	fset := token.NewFileSet()
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); path != "." && (strings.HasPrefix(name, ".") || name == "testdata") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		rel := filepath.ToSlash(path)
		out = append(out, source{rel: rel, pkg: filepath.ToSlash(filepath.Dir(path)), test: strings.HasSuffix(path, "_test.go"), file: f})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) < 20 {
		t.Fatalf("read %d files; the walk is wrong", len(out))
	}
	return out
}

// imported is the name a file imports a path under, or "".
func imported(f *ast.File, path string) string {
	for _, imp := range f.Imports {
		if strings.Trim(imp.Path.Value, `"`) != path {
			continue
		}
		if imp.Name != nil {
			return imp.Name.Name
		}
		return path[strings.LastIndex(path, "/")+1:]
	}
	return ""
}

// selections lists the pkg.Name selectors a file uses, for one import.
func selections(f *ast.File, path string) map[string][]token.Pos {
	name := imported(f, path)
	out := map[string][]token.Pos{}
	if name == "" {
		return out
	}
	ast.Inspect(f, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if id, ok := sel.X.(*ast.Ident); ok && id.Name == name {
			out[sel.Sel.Name] = append(out[sel.Sel.Name], sel.Pos())
		}
		return true
	})
	return out
}

// dialers are what builds an HTTP client, a transport or a connection: a
// function or a variable used at all, and a type built as a value. A type
// named as a parameter's builds nothing.
var dialers = map[string][]string{
	"net/http":   {"Client", "Transport", "Get", "Head", "Post", "PostForm", "DefaultClient", "DefaultTransport", "ProxyFromEnvironment"},
	"net":        {"Dialer", "Dial", "DialTimeout", "DialTCP", "DialUDP", "DialIP", "DialUnix"},
	"crypto/tls": {"Dial", "DialWithDialer", "Dialer"},
}

// types are the dialers that are types, flagged where a value is built.
var dialerTypes = []string{"Client", "Transport", "Dialer"}

// builds lists the dialers a file builds or calls, for one import.
func builds(f *ast.File, path string) map[string]int {
	out := map[string]int{}
	name := imported(f, path)
	if name == "" {
		return out
	}
	of := func(e ast.Expr) string {
		if sel, ok := e.(*ast.SelectorExpr); ok {
			if id, ok := sel.X.(*ast.Ident); ok && id.Name == name {
				return sel.Sel.Name
			}
		}
		return ""
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CompositeLit:
			if t := of(x.Type); slices.Contains(dialerTypes, t) {
				out[t]++
			}
		case *ast.CallExpr:
			if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "new" && len(x.Args) == 1 {
				if t := of(x.Args[0]); slices.Contains(dialerTypes, t) {
					out[t]++
				}
			}
		case *ast.SelectorExpr:
			if t := of(x); t != "" && !slices.Contains(dialerTypes, t) {
				out[t]++
			}
		}
		return true
	})
	return out
}

// No package but internal/dial builds an HTTP client, a transport or a
// dialer, and no package but internal/access takes the operator client.
// The database driver and the telemetry exporter open their own
// connections to addresses the operator configured, and are reached only
// through internal/store/postgres and latere.ai/x/pkg/otel.
func TestOnlyTheDialerDials(t *testing.T) {
	for _, s := range sources(t) {
		if s.test {
			continue
		}
		if s.pkg != "internal/dial" {
			for path, names := range dialers {
				for name, n := range builds(s.file, path) {
					if slices.Contains(names, name) {
						t.Errorf("%s builds or calls %s.%s (%d times); only internal/dial does", s.rel, path, name, n)
					}
				}
			}
		}
		if s.pkg != "internal/access" && len(selections(s.file, module+"/internal/dial")["Operator"]) > 0 {
			t.Errorf("%s takes the operator client; only internal/access does", s.rel)
		}
		for _, imp := range s.file.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			if strings.HasPrefix(p, "go.opentelemetry.io/otel/exporters") {
				t.Errorf("%s imports an exporter; telemetry is set up through latere.ai/x/pkg/otel alone", s.rel)
			}
		}
	}
}

// deps lists the packages a package depends on, without its tests.
func deps(t *testing.T, pkg string) []string {
	t.Helper()
	out, err := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}}", pkg).Output()
	if err != nil {
		t.Fatalf("go list -deps %s: %v", pkg, err)
	}
	return strings.Fields(string(out))
}

// The public packages api, authorizer and catalog build nothing that
// dials, and depend on no package of the module that does, on the driver,
// or on an exporter.
func TestPublicPackagesDialNothing(t *testing.T) {
	public := []string{"api", "authorizer", "catalog"}
	for _, s := range sources(t) {
		if s.test || !slices.Contains(public, s.pkg) {
			continue
		}
		for path, names := range dialers {
			for name := range builds(s.file, path) {
				if slices.Contains(names, name) {
					t.Errorf("%s builds or calls %s.%s", s.rel, path, name)
				}
			}
		}
	}
	for _, p := range public {
		for _, d := range deps(t, module+"/"+p) {
			if strings.HasPrefix(d, module+"/internal/") || strings.HasPrefix(d, "github.com/jackc/pgx") ||
				strings.HasPrefix(d, "go.opentelemetry.io/otel/exporters") || d == "latere.ai/x/pkg/otel" {
				t.Errorf("%s depends on %s", p, d)
			}
		}
	}
}

// No source file turns certificate verification off.
func TestNothingTurnsVerificationOff(t *testing.T) {
	for _, s := range sources(t) {
		ast.Inspect(s.file, func(n ast.Node) bool {
			if kv, ok := n.(*ast.KeyValueExpr); ok {
				if id, ok := kv.Key.(*ast.Ident); ok && id.Name == "InsecureSkipVerify" {
					t.Errorf("%s sets InsecureSkipVerify", s.rel)
				}
			}
			if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "InsecureSkipVerify" {
				t.Errorf("%s sets InsecureSkipVerify", s.rel)
			}
			return true
		})
	}
}

// The catalog's validation, the add route and the dialer call one host
// rule, catalog.CheckHost, and nothing else judges a host.
func TestTheHostRuleHasOneImplementation(t *testing.T) {
	calls := map[string]bool{}
	for _, s := range sources(t) {
		if s.test {
			continue
		}
		if s.pkg == "catalog" {
			ast.Inspect(s.file, func(n ast.Node) bool {
				if c, ok := n.(*ast.CallExpr); ok {
					if id, ok := c.Fun.(*ast.Ident); ok && id.Name == "CheckHost" {
						calls["catalog"] = true
					}
				}
				return true
			})
			continue
		}
		cat := selections(s.file, module+"/catalog")
		if len(cat["CheckHost"]) > 0 || len(cat["CheckPattern"]) > 0 {
			calls[s.pkg] = true
		}
		if len(cat["Validate"]) > 0 {
			calls[s.pkg+" through Validate"] = true
		}
		if len(selections(s.file, "latere.ai/x/pkg/hostmatch")["ValidPattern"]) > 0 {
			t.Errorf("%s judges a host pattern itself", s.rel)
		}
	}
	for _, want := range []string{"catalog", "internal/dial", "internal/httpapi through Validate"} {
		if !calls[want] {
			t.Errorf("%s does not call the host rule; it calls: %v", want, calls)
		}
	}
}

// envReaders are what reads the process's environment.
var envReaders = map[string][]string{
	"os":       {"Getenv", "LookupEnv", "Environ", "ExpandEnv"},
	"syscall":  {"Getenv", "Environ"},
	"net/http": {"ProxyFromEnvironment"},
}

// No package of the module but internal/config reads the environment. The
// server hands os.Getenv to config as a value and never calls it.
func TestOnlyConfigReadsTheEnvironment(t *testing.T) {
	read := false
	for _, s := range sources(t) {
		if s.test {
			continue
		}
		for path, names := range envReaders {
			for name := range selections(s.file, path) {
				if !slices.Contains(names, name) {
					continue
				}
				if s.pkg == "internal/config" {
					read = true
					continue
				}
				if s.pkg == "cmd/ponsd" && name == "Getenv" {
					// main hands it to config.FromEnv; a call is refused
					// below.
					continue
				}
				t.Errorf("%s reads the environment through %s.%s", s.rel, path, name)
			}
		}
		if s.pkg == "cmd/ponsd" {
			os := imported(s.file, "os")
			ast.Inspect(s.file, func(n ast.Node) bool {
				c, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if sel, ok := c.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Getenv" {
					if id, ok := sel.X.(*ast.Ident); ok && id.Name == os {
						t.Errorf("%s calls os.Getenv", s.rel)
					}
				}
				return true
			})
		}
	}
	if !read {
		t.Error("internal/config reads no variable; the scan is wrong")
	}
}

// listed is one package as go list reports it.
type listed struct {
	ImportPath string
	Imports    []string
}

// No package outside internal/store imports the driver or the migrator.
func TestDriverIsConfined(t *testing.T) {
	out, err := exec.Command("go", "list", "-json", "./...").Output()
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(strings.NewReader(string(out)))
	seen := 0
	for dec.More() {
		var p listed
		if err := dec.Decode(&p); err != nil {
			t.Fatal(err)
		}
		seen++
		if strings.HasPrefix(p.ImportPath, module+"/internal/store") {
			continue
		}
		for _, imp := range p.Imports {
			if strings.HasPrefix(imp, "github.com/jackc/pgx") || strings.HasPrefix(imp, "github.com/golang-migrate") ||
				imp == "latere.ai/x/pkg/pgxmigrate" || strings.HasPrefix(imp, "github.com/testcontainers") {
				t.Errorf("%s imports %s", p.ImportPath, imp)
			}
		}
	}
	if seen < 10 {
		t.Fatalf("listed %d packages", seen)
	}
}

// openers are the packages that may open a sealed value: the sign-in,
// which trades a refresh token, a client secret or a verifier, and the
// carrier, which places a credential in a forwarded request. The store's
// suite, which test binaries alone import, opens what it sealed to check
// both adapters kept it.
var openers = []string{module + "/internal/signin", module + "/internal/carry", module + "/internal/store/storetest"}

// Sealer.Open is the only method that returns a plaintext, its only
// callers are internal/signin and internal/carry, and no adapter holds a
// Sealer.
func TestOpenIsConfined(t *testing.T) {
	sealer := reflect.TypeFor[store.Sealer]()
	for m := range sealer.Methods() {
		for out := range m.Type.Outs() {
			if out == reflect.TypeFor[[]byte]() && m.Name != "Open" {
				t.Errorf("Sealer.%s returns bytes beside Open", m.Name)
			}
		}
	}
	cfg := &packages.Config{Mode: packages.NeedName | packages.NeedTypes | packages.NeedSyntax | packages.NeedTypesInfo}
	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		t.Fatal(err)
	}
	var iface *types.Interface
	for _, p := range pkgs {
		if p.PkgPath == module+"/internal/store" {
			iface = p.Types.Scope().Lookup("Sealer").Type().Underlying().(*types.Interface)
		}
	}
	if iface == nil {
		t.Fatal("no Sealer in internal/store")
	}
	for _, p := range pkgs {
		if len(p.Errors) > 0 {
			t.Fatalf("%s: %v", p.PkgPath, p.Errors)
		}
		adapter := p.PkgPath == module+"/internal/store/memory" || p.PkgPath == module+"/internal/store/postgres"
		for _, f := range p.Syntax {
			ast.Inspect(f, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.SelectorExpr:
					sel := p.TypesInfo.Selections[x]
					if sel == nil || sel.Obj().Name() != "Open" {
						return true
					}
					recv := sel.Recv()
					if !types.Implements(recv, iface) && !types.Implements(types.NewPointer(recv), iface) {
						return true
					}
					if p.PkgPath != module+"/internal/store" && !slices.Contains(openers, p.PkgPath) {
						t.Errorf("%s opens a sealed value at %s", p.PkgPath, p.Fset.Position(x.Pos()))
					}
				case *ast.Ident:
					if !adapter {
						return true
					}
					obj := p.TypesInfo.Uses[x]
					if obj == nil || obj.Pkg() == nil || obj.Pkg().Path() != module+"/internal/store" {
						return true
					}
					if obj.Name() == "Sealer" || obj.Name() == "KeySealer" || obj.Name() == "NewSealer" {
						t.Errorf("the adapter %s holds a sealer at %s", p.PkgPath, p.Fset.Position(x.Pos()))
					}
				}
				return true
			})
		}
	}
}
