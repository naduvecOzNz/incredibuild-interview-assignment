package manifest

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"cpp-sbom-builder/internal/scanner"
)

var (
	// matches "name/version" in requires lines or string literals
	reConanRef = regexp.MustCompile(`([\w][\w\-+.]*)\/([\d][\d.]*)`)
)

type conanStrategy struct{}

// NewConan returns a strategy that parses conanfile.txt and conanfile.py.
func NewConan() scanner.DependenciesDetectionStrategy { return &conanStrategy{} }

func (s *conanStrategy) Name() string { return "conan-manifest" }

func (s *conanStrategy) Analyze(_ context.Context, _ string, idx *scanner.FileIndex, _ scanner.ReadOnlyRegistry) ([]scanner.Dependency, error) {
	var deps []scanner.Dependency
	seen := map[string]bool{}

	for _, path := range idx.ManifestFiles {
		base := strings.ToLower(filepath.Base(path))
		if base != "conanfile.txt" && base != "conanfile.py" {
			continue
		}

		var found []scanner.Dependency
		var err error
		if base == "conanfile.txt" {
			found, err = parseConanTxt(path)
		} else {
			found, err = parseConanPy(path)
		}
		if err != nil {
			return nil, fmt.Errorf("conan: parse %s: %w", path, err)
		}
		for _, d := range found {
			key := d.Name + "@" + d.Version
			if !seen[key] {
				seen[key] = true
				deps = append(deps, d)
			}
		}
	}
	return deps, nil
}

// parseConanTxt parses a conanfile.txt, collecting entries from the [requires] section.
func parseConanTxt(path string) ([]scanner.Dependency, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var deps []scanner.Dependency
	inRequires := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "[") {
			inRequires = strings.EqualFold(line, "[requires]")
			continue
		}
		if !inRequires || line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if m := reConanRef.FindStringSubmatch(line); m != nil {
			deps = append(deps, conanDep(m[1], m[2]))
		}
	}
	return deps, sc.Err()
}

// parseConanPy parses a conanfile.py for requires references.
func parseConanPy(path string) ([]scanner.Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var deps []scanner.Dependency
	seen := map[string]bool{}
	for _, m := range reConanRef.FindAllStringSubmatch(string(data), -1) {
		key := m[1] + "@" + m[2]
		if !seen[key] {
			seen[key] = true
			deps = append(deps, conanDep(m[1], m[2]))
		}
	}
	return deps, nil
}

func conanDep(name, version string) scanner.Dependency {
	return scanner.Dependency{
		Name:    name,
		Version: version,
		PURL:    "pkg:conan/" + name + "@" + version,
	}
}
