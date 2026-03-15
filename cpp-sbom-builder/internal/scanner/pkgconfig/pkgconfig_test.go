package pkgconfig_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"cpp-sbom-builder/internal/scanner"
	"cpp-sbom-builder/internal/scanner/pkgconfig"
)

func TestPkgConfig_NameAndVersion(t *testing.T) {
	dir := t.TempDir()
	writefile(t, dir, "libpng.pc", `prefix=/usr
exec_prefix=${prefix}
libdir=${exec_prefix}/lib
includedir=${prefix}/include/libpng16

Name: libpng
Description: Loads and saves PNG files
Version: 1.6.37
Libs: -L${libdir} -lpng16
Cflags: -I${includedir}
`)

	deps := runPkgConfig(t, dir, "libpng.pc")
	assertContains(t, deps, "libpng", "1.6.37", "pkg:generic/libpng@1.6.37")
}

func TestPkgConfig_FallbackToFilenameWhenNoNameField(t *testing.T) {
	dir := t.TempDir()
	writefile(t, dir, "zlib.pc", `prefix=/usr
Version: 1.3.1
Libs: -lz
`)

	deps := runPkgConfig(t, dir, "zlib.pc")
	if len(deps) == 0 {
		t.Fatal("expected at least one dep")
	}
	d := deps[0]
	if d.Name != "zlib" {
		t.Errorf("expected name %q, got %q", "zlib", d.Name)
	}
	if d.Version != "1.3.1" {
		t.Errorf("expected version %q, got %q", "1.3.1", d.Version)
	}
}

func TestPkgConfig_MultipleFiles(t *testing.T) {
	dir := t.TempDir()
	writefile(t, dir, "openssl.pc", "Name: openssl\nVersion: 3.1.0\n")
	writefile(t, dir, "zlib.pc", "Name: zlib\nVersion: 1.3\n")

	deps := runPkgConfig(t, dir, "openssl.pc", "zlib.pc")
	assertContains(t, deps, "openssl", "3.1.0", "pkg:generic/openssl@3.1.0")
	assertContains(t, deps, "zlib", "1.3", "pkg:generic/zlib@1.3")
}

// helpers

func writefile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func runPkgConfig(t *testing.T, dir string, filenames ...string) []scanner.Dependency {
	t.Helper()
	var paths []string
	for _, f := range filenames {
		paths = append(paths, filepath.Join(dir, f))
	}
	idx := &scanner.FileIndex{PkgConfigFiles: paths}
	s := pkgconfig.New()
	deps, err := s.Analyze(context.Background(), dir, idx, emptyRegistry{})
	if err != nil {
		t.Fatal(err)
	}
	return deps
}

func assertContains(t *testing.T, deps []scanner.Dependency, name, version, purl string) {
	t.Helper()
	for _, d := range deps {
		if d.Name == name {
			if d.Version != version {
				t.Errorf("dep %q: want version %q, got %q", name, version, d.Version)
			}
			if purl != "" && d.PURL != purl {
				t.Errorf("dep %q: want PURL %q, got %q", name, purl, d.PURL)
			}
			return
		}
	}
	t.Errorf("dep %q not found in %v", name, deps)
}

type emptyRegistry struct{}

func (emptyRegistry) Get(_ string) (scanner.Dependency, bool) { return scanner.Dependency{}, false }
func (emptyRegistry) All() []scanner.Dependency               { return nil }
