package scanner

import (
	"os"
	"path/filepath"
	"strings"
)

// FileIndex is built once by Index() and shared read-only across all strategies.
// Strategies query it instead of walking the filesystem themselves.
type FileIndex struct {
	ManifestFiles       []string // CMakeLists.txt, conanfile.*, vcpkg.json, …
	CompileCommandFiles []string // compile_commands.json
	PkgConfigFiles      []string // *.pc
	BinaryFiles         []string // *.so, *.a, *.dll, *.lib, *.dylib
	HeaderFiles         []string // *.h, *.hpp, *.hxx, *.hh
	SourceFiles         []string // *.cpp, *.cc, *.c, *.cxx
}

// Index walks root once and categorises every file into the returned FileIndex.
func Index(root string) (*FileIndex, error) {
	idx := &FileIndex{}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		base := strings.ToLower(filepath.Base(path))
		ext := strings.ToLower(filepath.Ext(path))
		switch {
		case base == "cmakelists.txt" ||
			base == "conanfile.txt" || base == "conanfile.py" ||
			base == "vcpkg.json" || base == "vcpkg-configuration.json":
			idx.ManifestFiles = append(idx.ManifestFiles, path)
		case base == "compile_commands.json":
			idx.CompileCommandFiles = append(idx.CompileCommandFiles, path)
		case ext == ".pc":
			idx.PkgConfigFiles = append(idx.PkgConfigFiles, path)
		case ext == ".h" || ext == ".hpp" || ext == ".hxx" || ext == ".hh":
			idx.HeaderFiles = append(idx.HeaderFiles, path)
		case ext == ".cpp" || ext == ".cc" || ext == ".c" || ext == ".cxx":
			idx.SourceFiles = append(idx.SourceFiles, path)
		case ext == ".so" || ext == ".a" || ext == ".dll" || ext == ".lib" || ext == ".dylib":
			idx.BinaryFiles = append(idx.BinaryFiles, path)
		}
		return nil
	})
	return idx, err
}
