package output

import "cpp-sbom-builder/internal/scanner"

// SbomGenerator is the format-agnostic interface for producing SBOM documents.
// Each output format (SPDX, CycloneDX, …) provides its own implementation.
type SbomGenerator interface {
	// Format returns a short identifier for the format, e.g. "spdx", "cyclonedx".
	Format() string
	// Generate produces a serialised SBOM document from the given project name and components.
	Generate(projectName string, components []scanner.Component) ([]byte, error)
}
