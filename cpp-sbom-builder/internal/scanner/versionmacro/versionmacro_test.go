package versionmacro_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"cpp-sbom-builder/internal/scanner"
	"cpp-sbom-builder/internal/scanner/versionmacro"
)

// TestVersionMacro_PatternA_StringMacroFound verifies that a quoted-string
// version macro whose name contains both the dep name and "VERSION" is parsed
// correctly and returned as the dep's version.
func TestVersionMacro_PatternA_StringMacroFound(t *testing.T) {
	dir := t.TempDir()
	writefile(t, dir, "foo/foo_version.h", `
#define FOO_VERSION "2.4.1"
`)
	headers := []string{filepath.Join(dir, "foo", "foo_version.h")}
	reg := registryWithDep(scanner.Dependency{Name: "foo", PURL: "pkg:generic/foo"})

	deps := runVersionMacro(t, dir, headers, reg)
	assertVersion(t, deps, "foo", "2.4.1")
}

// TestVersionMacro_PatternB_MajorMinorPatchReconstruction verifies that
// separate MAJOR / MINOR / PATCH integer macros are combined into a
// "MAJOR.MINOR.PATCH" version string.
func TestVersionMacro_PatternB_MajorMinorPatchReconstruction(t *testing.T) {
	dir := t.TempDir()
	writefile(t, dir, "bar/version.h", `
#define BAR_VERSION_MAJOR 1
#define BAR_VERSION_MINOR 2
#define BAR_VERSION_PATCH 3
`)
	headers := []string{filepath.Join(dir, "bar", "version.h")}
	reg := registryWithDep(scanner.Dependency{Name: "bar", PURL: "pkg:generic/bar"})

	deps := runVersionMacro(t, dir, headers, reg)
	assertVersion(t, deps, "bar", "1.2.3")
}

// TestVersionMacro_MacroNameDoesNotMatchDepName verifies the heuristic filter:
// a VERSION macro whose name does not contain the dep name is ignored so that
// unrelated constants in the same header are not mistaken for a version.
func TestVersionMacro_MacroNameDoesNotMatchDepName(t *testing.T) {
	dir := t.TempDir()
	writefile(t, dir, "baz/baz.h", `
#define UNRELATED_VERSION "1.0"
`)
	headers := []string{filepath.Join(dir, "baz", "baz.h")}
	reg := registryWithDep(scanner.Dependency{Name: "baz", PURL: "pkg:generic/baz"})

	deps := runVersionMacro(t, dir, headers, reg)
	assertAbsent(t, deps, "baz")
}

// TestVersionMacro_DepAlreadyHasVersion verifies that a dep already carrying a
// version is not included in the candidate list and is therefore never returned.
func TestVersionMacro_DepAlreadyHasVersion(t *testing.T) {
	dir := t.TempDir()
	writefile(t, dir, "qux/qux.h", `
#define QUX_VERSION "9.9.9"
`)
	headers := []string{filepath.Join(dir, "qux", "qux.h")}
	reg := registryWithDep(scanner.Dependency{Name: "qux", Version: "1.0.0", PURL: "pkg:generic/qux@1.0.0"})

	deps := runVersionMacro(t, dir, headers, reg)
	assertAbsent(t, deps, "qux")
}

// TestVersionMacro_NoHeaderFoundForDep verifies a graceful no-op: when no
// project header file lives under a directory matching the dep name, the
// strategy returns nothing for that dep.
func TestVersionMacro_NoHeaderFoundForDep(t *testing.T) {
	dir := t.TempDir()
	// Header exists but is NOT under a directory named after the dep.
	writefile(t, dir, "unrelated/version.h", `
#define MYLIB_VERSION "3.0.0"
`)
	headers := []string{filepath.Join(dir, "unrelated", "version.h")}
	reg := registryWithDep(scanner.Dependency{Name: "mylib", PURL: "pkg:generic/mylib"})

	deps := runVersionMacro(t, dir, headers, reg)
	assertAbsent(t, deps, "mylib")
}

// TestVersionMacro_PatternC_CombinedIntegerVersion verifies that a combined integer
// version macro (major*10000 + minor*100 + patch) is decoded correctly, and that
// unrelated integer constants whose names lack "VERSION" are ignored.
func TestVersionMacro_PatternC_CombinedIntegerVersion(t *testing.T) {
	dir := t.TempDir()
	writefile(t, dir, "fmt/base.h", `
#define FMT_SOMETHING 42
#define FMT_VERSION 120100
`)
	headers := []string{filepath.Join(dir, "fmt", "base.h")}
	reg := registryWithDep(scanner.Dependency{Name: "fmt", PURL: "pkg:generic/fmt"})

	deps := runVersionMacro(t, dir, headers, reg)
	assertVersion(t, deps, "fmt", "12.1.0")
}

// ── helpers ──────────────────────────────────────────────────────────────────

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

func runVersionMacro(t *testing.T, projectRoot string, headerFiles []string, reg scanner.ReadOnlyRegistry) []scanner.Dependency {
	t.Helper()
	idx := &scanner.FileIndex{HeaderFiles: headerFiles}
	s := versionmacro.New()
	deps, err := s.Analyze(context.Background(), projectRoot, idx, reg)
	if err != nil {
		t.Fatal(err)
	}
	return deps
}

func assertVersion(t *testing.T, deps []scanner.Dependency, name, wantVersion string) {
	t.Helper()
	for _, d := range deps {
		if d.Name == name {
			if d.Version != wantVersion {
				t.Errorf("dep %q: got version %q, want %q", name, d.Version, wantVersion)
			}
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
