package binary_test

import (
	"context"
	"testing"

	"cpp-sbom-builder/internal/scanner"
	"cpp-sbom-builder/internal/scanner/binary"
)

// These tests exercise filename-based parsing only (no real binary files needed).

func TestBinary_SOWithVersionSuffix(t *testing.T) {
	deps := runBinary(t, "libssl.so.3")
	assertContains(t, deps, "ssl", "3")
}

func TestBinary_SOWithVersionInName(t *testing.T) {
	deps := runBinary(t, "libboost_filesystem.so.1.82.0")
	assertContains(t, deps, "boost_filesystem", "1.82.0")
}

func TestBinary_StaticLib(t *testing.T) {
	deps := runBinary(t, "libfoo.a")
	assertContains(t, deps, "foo", "")
}

func TestBinary_DLLWithVersion(t *testing.T) {
	// Windows DLL with version embedded in filename
	deps := runBinary(t, "zlib1.dll")
	// "zlib1" has no version separable by regex — fallback to stem
	if len(deps) == 0 {
		t.Fatal("expected at least one dep")
	}
	if deps[0].Name == "" {
		t.Error("expected non-empty name")
	}
}

func TestBinary_DyLib(t *testing.T) {
	deps := runBinary(t, "libpng.1.6.37.dylib")
	assertContains(t, deps, "png", "1.6.37")
}

func TestBinary_Deduplication(t *testing.T) {
	// Same lib listed twice should yield one dep
	deps := runBinaryMultiple(t, "libssl.so.3", "libssl.so.3")
	count := 0
	for _, d := range deps {
		if d.Name == "ssl" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 1 occurrence of ssl, got %d", count)
	}
}

// helpers

func runBinary(t *testing.T, filenames ...string) []scanner.Dependency {
	t.Helper()
	return runBinaryMultiple(t, filenames...)
}

func runBinaryMultiple(t *testing.T, filenames ...string) []scanner.Dependency {
	t.Helper()
	idx := &scanner.FileIndex{BinaryFiles: filenames}
	s := binary.New()
	deps, err := s.Analyze(context.Background(), "/project", idx, emptyRegistry{})
	if err != nil {
		t.Fatal(err)
	}
	return deps
}

func assertContains(t *testing.T, deps []scanner.Dependency, name, version string) {
	t.Helper()
	for _, d := range deps {
		if d.Name == name {
			if d.Version != version {
				t.Errorf("dep %q: want version %q, got %q", name, version, d.Version)
			}
			return
		}
	}
	t.Errorf("dep %q not found in %v", name, deps)
}

type emptyRegistry struct{}

func (emptyRegistry) Get(_ string) (scanner.Dependency, bool) { return scanner.Dependency{}, false }
func (emptyRegistry) All() []scanner.Dependency               { return nil }
