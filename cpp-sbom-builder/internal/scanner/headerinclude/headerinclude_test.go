package headerinclude_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"cpp-sbom-builder/internal/scanner"
	"cpp-sbom-builder/internal/scanner/headerinclude"
)

func TestHeaderInclude_ThirdPartyDetected(t *testing.T) {
	dir := t.TempDir()
	writefile(t, dir, "main.cpp", `
#include <vector>
#include <boost/filesystem.hpp>
#include <openssl/ssl.h>
`)

	deps := runHeaderInclude(t, dir, []string{filepath.Join(dir, "main.cpp")}, nil, emptyRegistry{})
	assertContains(t, deps, "boost")
	assertContains(t, deps, "openssl")
	assertAbsent(t, deps, "vector") // stdlib
}

func TestHeaderInclude_InternalHeaderFiltered(t *testing.T) {
	dir := t.TempDir()
	// internal.h lives inside the project
	internalH := filepath.Join(dir, "mylib", "internal.h")
	if err := os.MkdirAll(filepath.Dir(internalH), 0755); err != nil {
		t.Fatal(err)
	}
	writefile(t, dir, filepath.Join("mylib", "internal.h"), "// internal")
	writefile(t, dir, "main.cpp", `#include "mylib/internal.h"`)

	deps := runHeaderInclude(t, dir,
		[]string{filepath.Join(dir, "main.cpp")},
		[]string{internalH},
		emptyRegistry{},
	)
	assertAbsent(t, deps, "mylib")
}

func TestHeaderInclude_NlohmannJson(t *testing.T) {
	dir := t.TempDir()
	writefile(t, dir, "app.cpp", `#include <nlohmann/json.hpp>`)

	deps := runHeaderInclude(t, dir, []string{filepath.Join(dir, "app.cpp")}, nil, emptyRegistry{})
	assertContains(t, deps, "nlohmann")
}

func TestHeaderInclude_EigenDetected(t *testing.T) {
	dir := t.TempDir()
	writefile(t, dir, "app.cpp", `#include <Eigen/Dense>`)

	deps := runHeaderInclude(t, dir, []string{filepath.Join(dir, "app.cpp")}, nil, emptyRegistry{})
	assertContains(t, deps, "Eigen")
}

func TestHeaderInclude_SkipsDepAlreadyInRegistryWithVersion(t *testing.T) {
	dir := t.TempDir()
	writefile(t, dir, "app.cpp", `#include <boost/filesystem.hpp>`)

	reg := registryWithDep(scanner.Dependency{Name: "boost", Version: "1.82.0", PURL: "pkg:generic/boost@1.82.0"})
	deps := runHeaderInclude(t, dir, []string{filepath.Join(dir, "app.cpp")}, nil, reg)
	assertAbsent(t, deps, "boost")
}

// helpers

func writefile(t *testing.T, dir, name, content string) {
	t.Helper()
	fullPath := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func runHeaderInclude(t *testing.T, projectRoot string, sourceFiles, headerFiles []string, reg scanner.ReadOnlyRegistry) []scanner.Dependency {
	t.Helper()
	idx := &scanner.FileIndex{
		SourceFiles: sourceFiles,
		HeaderFiles: headerFiles,
	}
	s := headerinclude.New()
	deps, err := s.Analyze(context.Background(), projectRoot, idx, reg)
	if err != nil {
		t.Fatal(err)
	}
	return deps
}

func assertContains(t *testing.T, deps []scanner.Dependency, name string) {
	t.Helper()
	for _, d := range deps {
		if d.Name == name {
			return
		}
	}
	t.Errorf("dep %q not found in %v", name, deps)
}

func assertAbsent(t *testing.T, deps []scanner.Dependency, name string) {
	t.Helper()
	for _, d := range deps {
		if d.Name == name {
			t.Errorf("dep %q should not be present", name)
			return
		}
	}
}

type emptyRegistry struct{}

func (emptyRegistry) Get(_ string) (scanner.Dependency, bool) { return scanner.Dependency{}, false }
func (emptyRegistry) All() []scanner.Dependency               { return nil }

type staticRegistry struct{ deps []scanner.Dependency }

func registryWithDep(d scanner.Dependency) scanner.ReadOnlyRegistry {
	return &staticRegistry{deps: []scanner.Dependency{d}}
}

func (r *staticRegistry) Get(key string) (scanner.Dependency, bool) {
	for _, d := range r.deps {
		if d.PURL == key || d.Name+"@"+d.Version == key {
			return d, true
		}
	}
	return scanner.Dependency{}, false
}
func (r *staticRegistry) All() []scanner.Dependency { return r.deps }
