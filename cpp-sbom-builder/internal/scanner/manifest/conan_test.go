package manifest_test

import (
	"context"
	"path/filepath"
	"testing"

	"cpp-sbom-builder/internal/scanner"
	"cpp-sbom-builder/internal/scanner/manifest"
)

func TestConan_TxtRequiresSection(t *testing.T) {
	dir := t.TempDir()
	writefile(t, dir, "conanfile.txt", `
[requires]
boost/1.82.0
openssl/3.1.0

[generators]
cmake
`)

	deps := runConan(t, dir, "conanfile.txt")
	assertContainsPURL(t, deps, "boost", "1.82.0", "pkg:conan/boost@1.82.0")
	assertContainsPURL(t, deps, "openssl", "3.1.0", "pkg:conan/openssl@3.1.0")
}

func TestConan_TxtIgnoresOtherSections(t *testing.T) {
	dir := t.TempDir()
	writefile(t, dir, "conanfile.txt", `
[generators]
cmake

[options]
boost:shared=True
`)

	deps := runConan(t, dir, "conanfile.txt")
	if len(deps) != 0 {
		t.Errorf("expected 0 deps, got %d: %v", len(deps), deps)
	}
}

func TestConan_PySelfrequires(t *testing.T) {
	dir := t.TempDir()
	writefile(t, dir, "conanfile.py", `
from conan import ConanFile

class MyPkg(ConanFile):
    def requirements(self):
        self.requires("openssl/3.1.0")
        self.requires("zlib/1.3")
`)

	deps := runConan(t, dir, "conanfile.py")
	assertContains(t, deps, "openssl", "3.1.0")
	assertContains(t, deps, "zlib", "1.3")
}

func TestConan_PyRequiresList(t *testing.T) {
	dir := t.TempDir()
	writefile(t, dir, "conanfile.py", `
from conan import ConanFile

class MyPkg(ConanFile):
    requires = ["zlib/1.3", "fmt/10.0.0"]
`)

	deps := runConan(t, dir, "conanfile.py")
	assertContains(t, deps, "zlib", "1.3")
	assertContains(t, deps, "fmt", "10.0.0")
}

// helpers

func runConan(t *testing.T, dir, filename string) []scanner.Dependency {
	t.Helper()
	idx := &scanner.FileIndex{ManifestFiles: []string{filepath.Join(dir, filename)}}
	s := manifest.NewConan()
	deps, err := s.Analyze(context.Background(), dir, idx, emptyRegistry{})
	if err != nil {
		t.Fatal(err)
	}
	return deps
}

func assertContainsPURL(t *testing.T, deps []scanner.Dependency, name, version, purl string) {
	t.Helper()
	for _, d := range deps {
		if d.Name == name {
			if d.Version != version {
				t.Errorf("dep %q: want version %q, got %q", name, version, d.Version)
			}
			if d.PURL != purl {
				t.Errorf("dep %q: want PURL %q, got %q", name, purl, d.PURL)
			}
			return
		}
	}
	t.Errorf("dep %q not found in %v", name, deps)
}
