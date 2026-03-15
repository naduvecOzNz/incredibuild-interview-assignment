package orchestrator

import (
	"cpp-sbom-builder/internal/scanner"
	"cpp-sbom-builder/internal/scanner/binary"
	"cpp-sbom-builder/internal/scanner/compiledb"
	"cpp-sbom-builder/internal/scanner/headerinclude"
	"cpp-sbom-builder/internal/scanner/manifest"
	"cpp-sbom-builder/internal/scanner/pkgconfig"
)

// New constructs the default Orchestrator with all configured detection layers.
// Layer assignment and strategy selection live here; callers remain unaware of both.
func New() *scanner.Orchestrator {
	return scanner.NewOrchestrator(
		[]scanner.DependenciesDetectionStrategy{manifest.NewCMake(), manifest.NewVcpkg()},
		[]scanner.DependenciesDetectionStrategy{binary.New(), compiledb.New()},
		[]scanner.DependenciesDetectionStrategy{pkgconfig.New()},
		[]scanner.DependenciesDetectionStrategy{headerinclude.New()},
	)
}
