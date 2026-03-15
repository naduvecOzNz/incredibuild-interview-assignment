package pkgconfig

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"cpp-sbom-builder/internal/scanner"
)

type pkgConfigStrategy struct{}

// New returns a strategy that parses .pc (pkg-config) files for dependency metadata.
func New() scanner.DependenciesDetectionStrategy { return &pkgConfigStrategy{} }

func (s *pkgConfigStrategy) Name() string { return "pkg-config" }

func (s *pkgConfigStrategy) Analyze(_ context.Context, _ string, idx *scanner.FileIndex, _ scanner.ReadOnlyRegistry) ([]scanner.Dependency, error) {
	seen := map[string]bool{}
	var deps []scanner.Dependency

	for _, path := range idx.PkgConfigFiles {
		d, err := parsePCFile(path)
		if err != nil {
			return nil, fmt.Errorf("pkg-config: parse %s: %w", path, err)
		}
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

// parsePCFile reads a .pc file and extracts the Name and Version fields.
func parsePCFile(path string) (scanner.Dependency, error) {
	f, err := os.Open(path)
	if err != nil {
		return scanner.Dependency{}, err
	}
	defer f.Close()

	var name, version string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if n, ok := parseField(line, "Name"); ok {
			name = n
		} else if v, ok := parseField(line, "Version"); ok {
			version = v
		}
	}
	if err := sc.Err(); err != nil {
		return scanner.Dependency{}, err
	}

	// Fall back to filename stem if Name field is absent
	if name == "" {
		stem := filepath.Base(path)
		stem = strings.TrimSuffix(stem, filepath.Ext(stem))
		name = stem
	}

	purl := "pkg:generic/" + name
	if version != "" {
		purl += "@" + version
	}
	return scanner.Dependency{Name: name, Version: version, PURL: purl}, nil
}

// parseField extracts the value from a "Key: value" line.
func parseField(line, key string) (string, bool) {
	prefix := key + ":"
	if !strings.HasPrefix(line, prefix) {
		return "", false
	}
	return strings.TrimSpace(line[len(prefix):]), true
}
