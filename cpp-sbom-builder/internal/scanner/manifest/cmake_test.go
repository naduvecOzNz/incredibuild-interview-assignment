package manifest_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"cpp-sbom-builder/internal/scanner"
	"cpp-sbom-builder/internal/scanner/manifest"
)

func TestCMake_FindPackageWithVersion(t *testing.T) {
	dir := t.TempDir()
	writefile(t, dir, "CMakeLists.txt", `
cmake_minimum_required(VERSION 3.20)
project(myapp)
find_package(Boost 1.82 REQUIRED COMPONENTS filesystem)
find_package(OpenSSL REQUIRED)
`)

	deps := runCMake(t, dir)
	assertContains(t, deps, "Boost", "1.82")
	assertContains(t, deps, "OpenSSL", "")
}

func TestCMake_FetchContentWithGITTag(t *testing.T) {
	dir := t.TempDir()
	writefile(t, dir, "CMakeLists.txt", `
include(FetchContent)
FetchContent_Declare(
  zlib
  GIT_REPOSITORY https://github.com/madler/zlib.git
  GIT_TAG        v1.3
)
FetchContent_MakeAvailable(zlib)
`)

	deps := runCMake(t, dir)
	assertContains(t, deps, "zlib", "v1.3")
}

func TestCMake_ExternalProjectWithGITTag(t *testing.T) {
	dir := t.TempDir()
	writefile(t, dir, "CMakeLists.txt", `
include(ExternalProject)
ExternalProject_Add(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG        v1.14.0
)
`)

	deps := runCMake(t, dir)
	assertContains(t, deps, "googletest", "v1.14.0")
}

func TestCMake_NonCMakeFilesIgnored(t *testing.T) {
	dir := t.TempDir()
	// Write a conanfile, not CMakeLists.txt — should be ignored by cmake strategy
	writefile(t, dir, "conanfile.txt", `[requires]
boost/1.82.0
`)

	idx := &scanner.FileIndex{ManifestFiles: []string{filepath.Join(dir, "conanfile.txt")}}
	s := manifest.NewCMake()
	deps, err := s.Analyze(context.Background(), dir, idx, emptyRegistry{})
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) != 0 {
		t.Errorf("expected 0 deps, got %d", len(deps))
	}
}

// helpers

func runCMake(t *testing.T, dir string) []scanner.Dependency {
	t.Helper()
	idx := &scanner.FileIndex{ManifestFiles: []string{filepath.Join(dir, "CMakeLists.txt")}}
	s := manifest.NewCMake()
	deps, err := s.Analyze(context.Background(), dir, idx, emptyRegistry{})
	if err != nil {
		t.Fatal(err)
	}
	return deps
}

func writefile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
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
