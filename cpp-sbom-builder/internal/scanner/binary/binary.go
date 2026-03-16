// Package binary detects third-party dependencies from compiled binary files (.so, .dll, .dylib, .a).
// It reads ELF SONAME or Mach-O install-name metadata when available, and falls back to parsing
// the version from the filename. High-confidence: if a library is linked, it shows up here.
package binary

import (
	"context"
	"debug/elf"
	"debug/macho"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"cpp-sbom-builder/internal/scanner"
)

var (
	// libname.so.1.2.3 or libname-1.2.3.so  or libname.1.2.3.dylib
	reLibVersioned = regexp.MustCompile(`^lib([\w\-+]+?)[-.](\d[\d.]*)\.(?:so|a|dylib|lib)`)
	// libname.so / libname.a / libname.dylib / libname.lib (no version)
	reLibPlain = regexp.MustCompile(`^lib([\w\-+]+)\.(?:so|a|dylib|lib)$`)
	// name-1.2.3.dll  (Windows, no lib prefix)
	reDLLVersioned = regexp.MustCompile(`^([\w\-+]+?)[-.](\d[\d.]*)\.dll$`)
	// name.dll (no version)
	reDLLPlain = regexp.MustCompile(`^([\w\-+]+)\.dll$`)
	// libname.so.1.2.3 — SO version suffix
	reSOSuffix = regexp.MustCompile(`^lib([\w\-+]+)\.so\.(\d[\d.]*)`)
)

type binaryStrategy struct{}

// New returns a strategy that infers dependencies from binary filenames and ELF/Mach-O metadata.
func New() scanner.DependenciesDetectionStrategy { return &binaryStrategy{} }

func (s *binaryStrategy) Name() string { return "binary-analysis" }

func (s *binaryStrategy) Analyze(_ context.Context, _ string, idx *scanner.FileIndex, _ scanner.ReadOnlyRegistry) ([]scanner.Dependency, error) {
	if len(idx.BinaryFiles) == 0 {
		fmt.Printf("strategy %q: no relevant files found\n", s.Name())
		return nil, nil
	}
	seen := map[string]bool{}
	var deps []scanner.Dependency

	for _, path := range idx.BinaryFiles {
		d := analyzeFile(path)
		if d.Name == "" {
			continue
		}
		key := d.Name + "@" + d.Version
		if seen[key] {
			continue
		}
		seen[key] = true
		deps = append(deps, d)
	}
	return deps, nil
}

func analyzeFile(path string) scanner.Dependency {
	base := filepath.Base(path)
	ext := strings.ToLower(filepath.Ext(base))

	// Try reading richer metadata from the binary first
	switch ext {
	case ".so":
		if d, ok := fromELF(path); ok {
			return d
		}
	case ".dylib":
		if d, ok := fromMachO(path); ok {
			return d
		}
	}

	// Fall back to filename parsing
	return fromFilename(base)
}

// fromELF reads the DT_SONAME entry from an ELF shared library.
func fromELF(path string) (scanner.Dependency, bool) {
	f, err := elf.Open(path)
	if err != nil {
		return scanner.Dependency{}, false
	}
	defer f.Close()

	sonames, err := f.DynString(elf.DT_SONAME)
	if err != nil || len(sonames) == 0 {
		return scanner.Dependency{}, false
	}
	return fromFilename(sonames[0]), true
}

// fromMachO reads the install name from a Mach-O dynamic library.
func fromMachO(path string) (scanner.Dependency, bool) {
	f, err := macho.Open(path)
	if err != nil {
		return scanner.Dependency{}, false
	}
	defer f.Close()

	for _, load := range f.Loads {
		if dylib, ok := load.(*macho.Dylib); ok {
			// Install name looks like /usr/lib/libssl.3.dylib or libssl.dylib
			base := filepath.Base(dylib.Name)
			d := fromFilename(base)
			if d.Name != "" {
				return d, true
			}
		}
	}
	return scanner.Dependency{}, false
}

// fromFilename parses a binary filename to extract library name and version.
func fromFilename(base string) scanner.Dependency {
	lower := strings.ToLower(base)

	// libname.so.1.2.3
	if m := reSOSuffix.FindStringSubmatch(lower); m != nil {
		return makeBinaryDep(m[1], m[2])
	}
	// libname-1.2.3.so or libname.1.2.3.dylib etc.
	if m := reLibVersioned.FindStringSubmatch(lower); m != nil {
		return makeBinaryDep(m[1], m[2])
	}
	// libname.so (no version)
	if m := reLibPlain.FindStringSubmatch(lower); m != nil {
		return makeBinaryDep(m[1], "")
	}
	// name-1.2.3.dll
	if m := reDLLVersioned.FindStringSubmatch(lower); m != nil {
		return makeBinaryDep(m[1], m[2])
	}
	// name.dll
	if m := reDLLPlain.FindStringSubmatch(lower); m != nil {
		return makeBinaryDep(m[1], "")
	}
	// Unrecognised — use stem without extension
	stem := strings.TrimSuffix(base, filepath.Ext(base))
	if stem != "" {
		return makeBinaryDep(stem, "")
	}
	return scanner.Dependency{}
}

func makeBinaryDep(name, version string) scanner.Dependency {
	purl := "pkg:generic/" + name
	if version != "" {
		purl += "@" + version
	}
	return scanner.Dependency{Name: name, Version: version, PURL: purl}
}
