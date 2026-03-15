package manifest

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"cpp-sbom-builder/internal/scanner"
)

type vcpkgStrategy struct{}

// NewVcpkg returns a strategy that parses vcpkg.json and vcpkg-configuration.json.
func NewVcpkg() scanner.DependenciesDetectionStrategy { return &vcpkgStrategy{} }

func (s *vcpkgStrategy) Name() string { return "vcpkg-manifest" }

func (s *vcpkgStrategy) Analyze(_ context.Context, _ string, idx *scanner.FileIndex, _ scanner.ReadOnlyRegistry) ([]scanner.Dependency, error) {
	// Collect deps from vcpkg.json files, then enrich from vcpkg-configuration.json overrides.
	// Key: lowercase name → Dependency
	byName := map[string]scanner.Dependency{}
	order := []string{}

	for _, path := range idx.ManifestFiles {
		base := strings.ToLower(filepath.Base(path))
		switch base {
		case "vcpkg.json":
			found, err := parseVcpkgJSON(path)
			if err != nil {
				return nil, fmt.Errorf("vcpkg: parse %s: %w", path, err)
			}
			for _, d := range found {
				key := strings.ToLower(d.Name)
				if _, exists := byName[key]; !exists {
					order = append(order, key)
				}
				byName[key] = d
			}
		case "vcpkg-configuration.json":
			overrides, err := parseVcpkgConfiguration(path)
			if err != nil {
				return nil, fmt.Errorf("vcpkg: parse %s: %w", path, err)
			}
			for name, version := range overrides {
				key := strings.ToLower(name)
				if existing, exists := byName[key]; exists && existing.Version == "" {
					existing.Version = version
					existing.PURL = vcpkgPURL(existing.Name, version)
					byName[key] = existing
				}
			}
		}
	}

	deps := make([]scanner.Dependency, 0, len(order))
	for _, key := range order {
		deps = append(deps, byName[key])
	}
	return deps, nil
}

// vcpkgDependency represents a single entry in the vcpkg.json dependencies array.
// It can be either a plain string or an object.
type vcpkgDependency struct {
	Name          string
	VersionString string
}

func (d *vcpkgDependency) UnmarshalJSON(data []byte) error {
	// Try string first
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		d.Name = s
		return nil
	}
	// Try object
	var obj struct {
		Name          string `json:"name"`
		VersionString string `json:"version-string"`
		Version       string `json:"version"`
	}
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}
	d.Name = obj.Name
	d.VersionString = obj.VersionString
	if d.VersionString == "" {
		d.VersionString = obj.Version
	}
	return nil
}

func parseVcpkgJSON(path string) ([]scanner.Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var manifest struct {
		Dependencies []vcpkgDependency `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, err
	}
	var deps []scanner.Dependency
	for _, dep := range manifest.Dependencies {
		if dep.Name == "" {
			continue
		}
		deps = append(deps, scanner.Dependency{
			Name:    dep.Name,
			Version: dep.VersionString,
			PURL:    vcpkgPURL(dep.Name, dep.VersionString),
		})
	}
	return deps, nil
}

func parseVcpkgConfiguration(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg struct {
		Overrides []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"overrides"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	result := make(map[string]string, len(cfg.Overrides))
	for _, o := range cfg.Overrides {
		if o.Name != "" && o.Version != "" {
			result[o.Name] = o.Version
		}
	}
	return result, nil
}

func vcpkgPURL(name, version string) string {
	purl := "pkg:generic/" + name
	if version != "" {
		purl += "@" + version
	}
	return purl
}
