package compiledb_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"cpp-sbom-builder/internal/scanner"
	"cpp-sbom-builder/internal/scanner/compiledb"
)

func TestCompileDB_LinkedLibraries(t *testing.T) {
	projectRoot := t.TempDir()
	writeCompileCommands(t, projectRoot, []map[string]string{
		{
			"directory": projectRoot,
			"file":      "main.cpp",
			"command":   "g++ -o main main.cpp -lz -lopencv_core -I/usr/local/include",
		},
	})

	deps := runCompileDB(t, projectRoot)
	assertContains(t, deps, "z", "")
	assertContains(t, deps, "opencv_core", "")
}

func TestCompileDB_ExternalIncludePath(t *testing.T) {
	projectRoot := t.TempDir()
	writeCompileCommands(t, projectRoot, []map[string]string{
		{
			"directory": projectRoot,
			"file":      "main.cpp",
			"command":   "g++ -o main main.cpp -I/usr/local/include/opencv4",
		},
	})

	deps := runCompileDB(t, projectRoot)
	assertContains(t, deps, "opencv4", "")
}

func TestCompileDB_InternalIncludePathIgnored(t *testing.T) {
	projectRoot := t.TempDir()
	internalInclude := filepath.Join(projectRoot, "include")
	writeCompileCommands(t, projectRoot, []map[string]string{
		{
			"directory": projectRoot,
			"file":      "main.cpp",
			"command":   "g++ -o main main.cpp -I" + internalInclude,
		},
	})

	deps := runCompileDB(t, projectRoot)
	if len(deps) != 0 {
		t.Errorf("expected 0 deps for internal include, got %d: %v", len(deps), deps)
	}
}

func TestCompileDB_Deduplication(t *testing.T) {
	projectRoot := t.TempDir()
	writeCompileCommands(t, projectRoot, []map[string]string{
		{"directory": projectRoot, "file": "a.cpp", "command": "g++ -lboost_system a.cpp"},
		{"directory": projectRoot, "file": "b.cpp", "command": "g++ -lboost_system b.cpp"},
	})

	deps := runCompileDB(t, projectRoot)
	count := 0
	for _, d := range deps {
		if d.Name == "boost_system" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 1 occurrence of boost_system, got %d", count)
	}
}

// helpers

func writeCompileCommands(t *testing.T, dir string, entries []map[string]string) {
	t.Helper()
	data, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "compile_commands.json"), data, 0644); err != nil {
		t.Fatal(err)
	}
}

func runCompileDB(t *testing.T, projectRoot string) []scanner.Dependency {
	t.Helper()
	idx := &scanner.FileIndex{
		CompileCommandFiles: []string{filepath.Join(projectRoot, "compile_commands.json")},
	}
	s := compiledb.New()
	deps, err := s.Analyze(context.Background(), projectRoot, idx, emptyRegistry{})
	if err != nil {
		t.Fatal(err)
	}
	return deps
}

func assertContains(t *testing.T, deps []scanner.Dependency, name, version string) {
	t.Helper()
	for _, d := range deps {
		if d.Name == name {
			if d.Version != version {
				t.Errorf("dep %q: want version %q, got %q", name, version, d.Version)
			}
			return
		}
	}
	t.Errorf("dep %q not found in %v", name, deps)
}

type emptyRegistry struct{}

func (emptyRegistry) Get(_ string) (scanner.Dependency, bool) { return scanner.Dependency{}, false }
func (emptyRegistry) All() []scanner.Dependency               { return nil }
