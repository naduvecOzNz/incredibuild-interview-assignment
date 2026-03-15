package compiledb

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"cpp-sbom-builder/internal/scanner"
)

var (
	// -lfoo or -l foo
	reLinkedLib = regexp.MustCompile(`-l\s*(\S+)`)
	// -I/path or -I /path
	reIncludePath = regexp.MustCompile(`-I\s*(\S+)`)
)

type compileDBStrategy struct{}

// New returns a strategy that parses compile_commands.json for linked libraries and include paths.
func New() scanner.DependenciesDetectionStrategy { return &compileDBStrategy{} }

func (s *compileDBStrategy) Name() string { return "compile-commands-db" }

type compileEntry struct {
	Directory string `json:"directory"`
	Command   string `json:"command"`
	File      string `json:"file"`
}

func (s *compileDBStrategy) Analyze(_ context.Context, projectRoot string, idx *scanner.FileIndex, _ scanner.ReadOnlyRegistry) ([]scanner.Dependency, error) {
	seen := map[string]bool{}
	var deps []scanner.Dependency

	for _, path := range idx.CompileCommandFiles {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("compile-commands: read %s: %w", path, err)
		}
		var entries []compileEntry
		if err := json.Unmarshal(data, &entries); err != nil {
			return nil, fmt.Errorf("compile-commands: parse %s: %w", path, err)
		}

		for _, entry := range entries {
			found := extractDepsFromCommand(entry.Command, projectRoot)
			for _, d := range found {
				key := d.Name + "@" + d.Version
				if seen[key] {
					continue
				}
				seen[key] = true
				deps = append(deps, d)
			}
		}
	}
	return deps, nil
}

func extractDepsFromCommand(command, projectRoot string) []scanner.Dependency {
	var deps []scanner.Dependency

	// Linked libraries via -l flags
	for _, m := range reLinkedLib.FindAllStringSubmatch(command, -1) {
		name := m[1]
		deps = append(deps, makeCompileDep(name, ""))
	}

	// External include paths via -I flags
	absRoot, _ := filepath.Abs(projectRoot)
	for _, m := range reIncludePath.FindAllStringSubmatch(command, -1) {
		incPath := m[1]
		absInc, err := filepath.Abs(incPath)
		if err != nil {
			continue
		}
		// Only consider paths outside the project root
		if strings.HasPrefix(absInc, absRoot) {
			continue
		}
		// Use the last path segment as library name hint
		name := filepath.Base(absInc)
		if name == "" || name == "." {
			continue
		}
		deps = append(deps, makeCompileDep(name, ""))
	}

	return deps
}

func makeCompileDep(name, version string) scanner.Dependency {
	purl := "pkg:generic/" + name
	if version != "" {
		purl += "@" + version
	}
	return scanner.Dependency{Name: name, Version: version, PURL: purl}
}
