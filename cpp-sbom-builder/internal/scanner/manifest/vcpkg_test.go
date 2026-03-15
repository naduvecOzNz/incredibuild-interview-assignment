package manifest_test

import (
	"context"
	"path/filepath"
	"testing"

	"cpp-sbom-builder/internal/scanner"
	"cpp-sbom-builder/internal/scanner/manifest"
)

func TestVcpkg_StringAndObjectDependencies(t *testing.T) {
	dir := t.TempDir()
	writefile(t, dir, "vcpkg.json", `{
  "name": "myapp",
  "dependencies": [
    "boost",
    { "name": "openssl", "version-string": "3.1.0" }
  ]
}`)

	deps := runVcpkg(t, dir, "vcpkg.json")
	assertContains(t, deps, "boost", "")      // no version in manifest
	assertContains(t, deps, "openssl", "3.1.0")
}

func TestVcpkg_ConfigurationOverridesVersion(t *testing.T) {
	dir := t.TempDir()
	writefile(t, dir, "vcpkg.json", `{
  "dependencies": ["boost"]
}`)
	writefile(t, dir, "vcpkg-configuration.json", `{
  "overrides": [
    { "name": "boost", "version": "1.82.0" }
  ]
}`)

	deps := runVcpkg(t, dir, "vcpkg.json", "vcpkg-configuration.json")
	assertContains(t, deps, "boost", "1.82.0")
}

func TestVcpkg_VersionObjectField(t *testing.T) {
	dir := t.TempDir()
	writefile(t, dir, "vcpkg.json", `{
  "dependencies": [
    { "name": "zlib", "version": "1.3.1" }
  ]
}`)

	deps := runVcpkg(t, dir, "vcpkg.json")
	assertContains(t, deps, "zlib", "1.3.1")
}

// helpers

func runVcpkg(t *testing.T, dir string, filenames ...string) []scanner.Dependency {
	t.Helper()
	var paths []string
	for _, f := range filenames {
		paths = append(paths, filepath.Join(dir, f))
	}
	idx := &scanner.FileIndex{ManifestFiles: paths}
	s := manifest.NewVcpkg()
	deps, err := s.Analyze(context.Background(), dir, idx, emptyRegistry{})
	if err != nil {
		t.Fatal(err)
	}
	return deps
}
