package headerinclude

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

var regexInclude = regexp.MustCompile(`#\s*include\s*[<"]([^>"]+)[>"]`)

type headerIncludeStrategy struct{}

// New returns a strategy that infers third-party dependencies from #include directives.
func New() scanner.DependenciesDetectionStrategy { return &headerIncludeStrategy{} }

func (s *headerIncludeStrategy) Name() string { return "header-include-analysis" }

func (s *headerIncludeStrategy) Analyze(_ context.Context, projectRoot string, idx *scanner.FileIndex, reg scanner.ReadOnlyRegistry) ([]scanner.Dependency, error) {
	// Build a set of internal header basenames for fast lookup
	internalHeaders := buildInternalHeaderSet(projectRoot, idx.HeaderFiles)

	// Collect all third-party top-level namespaces
	namespaces := map[string]bool{}

	files := append(idx.SourceFiles, idx.HeaderFiles...)
	for _, path := range files {
		includes, err := extractIncludes(path)
		if err != nil {
			return nil, fmt.Errorf("header-include: scan %s: %w", path, err)
		}
		for _, inc := range includes {
			ns := classifyInclude(inc, projectRoot, internalHeaders)
			if ns != "" {
				namespaces[ns] = true
			}
		}
	}

	// Build a name → version map from the registry for fast lookup
	registeredWithVersion := map[string]bool{}
	for _, d := range reg.All() {
		if d.Version != "" {
			registeredWithVersion[d.Name] = true
		}
	}

	// Convert namespaces to deps, skipping those already in the registry with a version
	var deps []scanner.Dependency
	for ns := range namespaces {
		if registeredWithVersion[ns] {
			continue
		}
		deps = append(deps, scanner.Dependency{
			Name:    ns,
			Version: "",
			PURL:    "pkg:generic/" + ns,
		})
	}
	return deps, nil
}

// buildInternalHeaderSet returns a set of paths and basenames of project-owned headers.
func buildInternalHeaderSet(projectRoot string, headerFiles []string) map[string]bool {
	internalHeadersSet := map[string]bool{}
	absRoot, _ := filepath.Abs(projectRoot)
	for _, header := range headerFiles {
		absHeader, err := filepath.Abs(header)
		if err != nil {
			continue
		}
		internalHeadersSet[absHeader] = true
		// Also index by relative path from root (normalised with forward slashes)
		if relative, err := filepath.Rel(absRoot, absHeader); err == nil {
			internalHeadersSet[filepath.ToSlash(relative)] = true
		}
		// And by basename alone for simple quoted includes like "myheader.h"
		internalHeadersSet[filepath.Base(header)] = true
	}
	return internalHeadersSet
}

// extractIncludes scans a file and returns all #include paths.
func extractIncludes(sourcePath string) ([]string, error) {
	sourceFile, err := os.Open(sourcePath)
	if err != nil {
		return nil, err
	}
	defer sourceFile.Close()

	var includes []string
	sc := bufio.NewScanner(sourceFile)
	for sc.Scan() {
		m := regexInclude.FindStringSubmatch(sc.Text())
		if m != nil {
			includes = append(includes, m[1])
		}
	}
	return includes, sc.Err()
}

// classifyInclude returns the top-level namespace for a third-party include, or "" to skip.
func classifyInclude(include, projectRoot string, internalHeaders map[string]bool) string {
	// Strip leading/trailing whitespace
	include = strings.TrimSpace(include)
	if include == "" {
		return ""
	}
	// Check standard library
	if isStandardLibHeader(include) {
		return ""
	}
	// Check if it's an internal project header
	if isInternalHeader(include, internalHeaders) {
		return ""
	}

	return identifyNamespaceFromInclude(include)
}

func isStandardLibHeader(include string) bool {
	if _, isStd := stdHeaders[include]; isStd {
		return true
	}
	// Also check top-level name (e.g. "vector" is in the set directly)
	topLevel := strings.SplitN(include, "/", 2)[0]
	if _, isStd := stdHeaders[topLevel]; isStd {
		return true
	}
	return false
}

func isInternalHeader(include string, internalHeaders map[string]bool) bool {
	if internalHeaders[include] {
		return true
	}
	// Also check basename
	if internalHeaders[filepath.Base(include)] {
		return true
	}
	// Check as path relative to project root
	if internalHeaders[filepath.ToSlash(include)] {
		return true
	}
	return false
}

// identifyNamespaceFromInclude derives a library name from an include path.
// "boost/filesystem.hpp"  → "boost"
// "nlohmann/json.hpp"     → "nlohmann/json"  (two-segment for known single-header libs)
// "Eigen/Dense"           → "Eigen"
// "gtest/gtest.h"         → "gtest"
func identifyNamespaceFromInclude(include string) string {
	segments := strings.Split(filepath.ToSlash(include), "/")
	if len(segments) == 0 {
		return ""
	}
	if len(segments) == 1 {
		return identifyNamespaceFromSingleSegment(segments[0])
	}
	return identifyNamespaceFromMultiSegment(segments)
}

func identifyNamespaceFromSingleSegment(segment string) string {
	// Single-file header-only libraries are identified by their filename stem
	return strings.TrimSuffix(segment, filepath.Ext(segment))
}

func identifyNamespaceFromMultiSegment(segments []string) string {
	// Multi-segment: use the top-level directory as the library name
	return segments[0]
}
