// Package manifest detects third-party dependencies from build system manifest files.
// The CMake strategy parses CMakeLists.txt for find_package(), FetchContent_Declare(), and
// ExternalProject_Add() calls — the highest-confidence source since developers explicitly
// declare these dependencies by name and often by version.
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
	// find_package(Name [VERSION] ...) — captures name and optional version
	reFindPackage = regexp.MustCompile(`(?i)find_package\s*\(\s*(\w+)(?:\s+(\d[\d.]*))?`)
	// FetchContent_Declare(name ... GIT_TAG tag) — captures name and tag
	reFetchContentName = regexp.MustCompile(`(?i)FetchContent_Declare\s*\(\s*(\w+)`)
	// ExternalProject_Add(name ... GIT_TAG tag) — captures name
	reExternalProjectName = regexp.MustCompile(`(?i)ExternalProject_Add\s*\(\s*(\w+)`)
	// GIT_TAG value on any line
	reGITTag = regexp.MustCompile(`(?i)GIT_TAG\s+(\S+)`)
)

type cmakeStrategy struct{}

// NewCMake returns a strategy that parses CMakeLists.txt for third-party dependencies.
func NewCMake() scanner.DependenciesDetectionStrategy { return &cmakeStrategy{} }

func (s *cmakeStrategy) Name() string { return "cmake-manifest" }

func (s *cmakeStrategy) Analyze(_ context.Context, _ string, idx *scanner.FileIndex, _ scanner.ReadOnlyRegistry) ([]scanner.Dependency, error) {
	var deps []scanner.Dependency
	seen := map[string]bool{}

	for _, path := range idx.ManifestFiles {
		if strings.ToLower(filepath.Base(path)) != "cmakelists.txt" {
			continue
		}
		found, err := parseCMakeFile(path)
		if err != nil {
			return nil, fmt.Errorf("cmake: parse %s: %w", path, err)
		}
		for _, d := range found {
			if !seen[d.Name] {
				seen[d.Name] = true
				deps = append(deps, d)
			}
		}
	}
	return deps, nil
}

func parseCMakeFile(path string) ([]scanner.Dependency, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Read full content for multi-line block detection
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}

	content := strings.Join(lines, "\n")
	var deps []scanner.Dependency

	// find_package(Name [VERSION] ...)
	for _, m := range reFindPackage.FindAllStringSubmatch(content, -1) {
		name := m[1]
		version := ""
		if len(m) > 2 {
			version = m[2]
		}
		deps = append(deps, makeDep(name, version))
	}

	// FetchContent_Declare / ExternalProject_Add — capture name, then scan ahead for GIT_TAG
	deps = append(deps, parseBlockDeps(content, reFetchContentName)...)
	deps = append(deps, parseBlockDeps(content, reExternalProjectName)...)

	return deps, nil
}

// parseBlockDeps finds blocks started by nameRe (matched against full content so \s spans newlines)
// and looks for GIT_TAG within the next 500 characters after the match.
func parseBlockDeps(content string, nameRe *regexp.Regexp) []scanner.Dependency {
	var deps []scanner.Dependency
	locs := nameRe.FindAllStringSubmatchIndex(content, -1)
	for _, loc := range locs {
		name := content[loc[2]:loc[3]]
		version := ""
		// Search within the next 500 bytes for GIT_TAG
		windowStart := loc[1]
		windowEnd := windowStart + 500
		if windowEnd > len(content) {
			windowEnd = len(content)
		}
		if tm := reGITTag.FindStringSubmatch(content[windowStart:windowEnd]); tm != nil {
			version = tm[1]
		}
		deps = append(deps, makeDep(name, version))
	}
	return deps
}

func makeDep(name, version string) scanner.Dependency {
	purl := "pkg:generic/" + name
	if version != "" {
		purl += "@" + version
	}
	return scanner.Dependency{Name: name, Version: version, PURL: purl}
}
