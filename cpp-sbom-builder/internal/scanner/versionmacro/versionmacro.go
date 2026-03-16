// Package versionmacro enriches already-found dependencies with version information
// by scanning project-internal C/C++ header files for #define VERSION macros.
// It is designed to run as a final layer after all other detection strategies,
// operating only on dependencies that have an empty version field.
package versionmacro

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"cpp-sbom-builder/internal/scanner"
)

// Compiled regexes for version macro patterns.
var (
	// patternA matches: #define FOO_VERSION "2.4.1"
	rePatternA = regexp.MustCompile(`#\s*define\s+(\w+)\s+"([0-9][^"]*)"`)

	// patternB matches: #define FOO_VERSION_MAJOR 2  (integer, no hex)
	rePatternB = regexp.MustCompile(`#\s*define\s+(\w+)\s+([0-9]+)\s*$`)

	// patternC matches: #define FMT_VERSION 120100  (4–6 digit combined integer)
	rePatternC = regexp.MustCompile(`#\s*define\s+(\w+)\s+([0-9]{4,6})\s*$`)
)

type versionMacroStrategy struct{}

// New returns a strategy that enriches versionless dependencies by scanning
// project-internal header files for #define VERSION macros.
func New() scanner.DependenciesDetectionStrategy { return &versionMacroStrategy{} }

func (s *versionMacroStrategy) Name() string { return "version-macro" }

func (s *versionMacroStrategy) Analyze(_ context.Context, _ string, idx *scanner.FileIndex, reg scanner.ReadOnlyRegistry) ([]scanner.Dependency, error) {
	if len(idx.HeaderFiles) == 0 {
		fmt.Printf("strategy %q: no relevant files found\n", s.Name())
		return nil, nil
	}
	candidates := collectCandidatesWithoutVersion(reg)
	if len(candidates) == 0 {
		return nil, nil
	}

	var deps []scanner.Dependency
	for _, dep := range candidates {
		headers := findHeadersForDependency(dep.Name, idx.HeaderFiles)
		version := resolveVersion(dep.Name, headers)
		if version == "" {
			continue
		}
		deps = append(deps, scanner.Dependency{
			Name:    dep.Name,
			Version: version,
			PURL:    "pkg:generic/" + dep.Name + "@" + version,
		})
	}
	return deps, nil
}

// collectCandidatesWithoutVersion returns all registry deps that have an empty version.
func collectCandidatesWithoutVersion(reg scanner.ReadOnlyRegistry) []scanner.Dependency {
	var out []scanner.Dependency
	for _, d := range reg.All() {
		if d.Version == "" {
			out = append(out, d)
		}
	}
	return out
}

// findHeadersForDependency filters headerFiles to those whose path contains the dep
// name as a path component (case-insensitive).
func findHeadersForDependency(depName string, headerFiles []string) []string {
	needle := strings.ToLower(depName)
	var out []string
	for _, h := range headerFiles {
		normalized := strings.ToLower(strings.ReplaceAll(h, "\\", "/"))
		// Match "/depname/" anywhere in path, or path starts with "depname/"
		if strings.Contains(normalized, "/"+needle+"/") ||
			strings.HasPrefix(normalized, needle+"/") {
			out = append(out, h)
		}
	}
	return out
}

// resolveVersion searches the given header files for a version macro whose
// name contains the dep name. Priority: quoted-string > separate MAJOR/MINOR/PATCH > combined integer.
func resolveVersion(depName string, headerFiles []string) string {
	for _, h := range headerFiles {
		lines, err := readLines(h)
		if err != nil {
			continue
		}
		if v := matchQuotedStringPattern(depName, lines); v != "" {
			return v
		}
		if v := matchSeperateSemanticVersioningPattern(depName, lines); v != "" {
			return v
		}
		if v := matchCombinedIntegerPattern(depName, lines); v != "" {
			return v
		}
	}
	return ""
}

// matchQuotedStringPattern scans lines for a quoted-string version macro whose define
// name contains both the dep name and "VERSION" (case-insensitive).
// Example: #define FOO_VERSION "2.4.1"
func matchQuotedStringPattern(depName string, lines []string) string {
	normDep := normalizeIdent(depName)
	for _, line := range lines {
		m := rePatternA.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		defineName := normalizeIdent(m[1])
		if strings.Contains(defineName, normDep) && strings.Contains(defineName, "version") {
			return m[2]
		}
	}
	return ""
}

// matchSeperateSemanticVersioningPattern scans lines for separate MAJOR / MINOR / PATCH integer macros
// whose names contain the dep name and a version-part keyword. Reconstructs
// as "MAJOR.MINOR.PATCH" only when all three parts are found.
// Example: #define FOO_VERSION_MAJOR 2 / _MINOR 4 / _PATCH 1 → "2.4.1"
func matchSeperateSemanticVersioningPattern(depName string, lines []string) string {
	normDep := normalizeIdent(depName)
	major, minor, patch := -1, -1, -1

	for _, line := range lines {
		m := rePatternB.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		defineName := normalizeIdent(m[1])
		if !strings.Contains(defineName, normDep) {
			continue
		}
		val, err := strconv.Atoi(m[2])
		if err != nil {
			continue
		}
		switch {
		case strings.Contains(defineName, "major"):
			major = val
		case strings.Contains(defineName, "minor"):
			minor = val
		case strings.Contains(defineName, "patch") || strings.Contains(defineName, "micro"):
			patch = val
		}
	}

	if major >= 0 && minor >= 0 && patch >= 0 {
		return fmt.Sprintf("%d.%d.%d", major, minor, patch)
	}
	return ""
}

// matchCombinedIntegerPattern scans lines for a single combined integer version macro
// whose define name contains both the dep name and "VERSION". Decodes using the standard
// major*10000 + minor*100 + patch formula, accepting only results where minor < 100
// and patch < 100 as a sanity check against unrelated integer constants.
// Example: #define FMT_VERSION 120100 → "12.1.0"
func matchCombinedIntegerPattern(depName string, lines []string) string {
	normDep := normalizeIdent(depName)
	for _, line := range lines {
		m := rePatternC.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		defineName := normalizeIdent(m[1])
		if !strings.Contains(defineName, normDep) || !strings.Contains(defineName, "version") {
			continue
		}
		val, err := strconv.Atoi(m[2])
		if err != nil {
			continue
		}
		patch := val % 100
		minor := (val / 100) % 100
		major := val / 10000
		if minor >= 100 || patch >= 100 {
			continue
		}
		return fmt.Sprintf("%d.%d.%d", major, minor, patch)
	}
	return ""
}

// normalizeIdent lowercases and strips non-alphanumeric characters so that
// "nlohmann-json", "NLOHMANN_JSON", and "nlohmannjson" all compare equal.
func normalizeIdent(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// readLines opens a file and returns all its lines.
func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	return lines, sc.Err()
}
