package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"cpp-sbom-builder/internal/output"
	"cpp-sbom-builder/internal/output/spdx"
	"cpp-sbom-builder/internal/scanner"
)

// generators is the registry of supported output formats.
// The first entry is always used; add new generators here when new formats are supported.
var generators = []output.SbomGenerator{
	spdx.SbomGenerator{},
}

// run parses args, executes the scan and generation, and writes output to stdout.
// Returns the exit code. stderr receives error and usage messages.
func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("cpp-sbom-builder", flag.ContinueOnError)
	fs.SetOutput(stderr)

	targetDir := fs.String("target", "", "path to C++ project root directory (required)")
	outputFile := fs.String("output", "", "write SBOM to this file instead of stdout")

	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: cpp-sbom-builder --target <dir> [--output <file>]")
		fmt.Fprintln(stderr)
		fmt.Fprintln(stderr, "Flags:")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return 1
	}

	if *targetDir == "" {
		fmt.Fprintln(stderr, "error: --target is required")
		fs.Usage()
		return 1
	}

	info, err := os.Stat(*targetDir)
	if err != nil || !info.IsDir() {
		fmt.Fprintf(stderr, "error: --target %q is not a valid directory\n", *targetDir)
		return 1
	}

	gen := generators[0]

	s := scanner.New() // strategies registered here as they are implemented
	components, err := s.Scan(*targetDir)
	if err != nil {
		fmt.Fprintf(stderr, "scan failed: %v\n", err)
		return 1
	}

	projectName := filepath.Base(filepath.Clean(*targetDir))
	data, err := gen.Generate(projectName, components)
	if err != nil {
		fmt.Fprintf(stderr, "generate failed: %v\n", err)
		return 1
	}

	w := stdout
	if *outputFile != "" {
		f, err := os.Create(*outputFile)
		if err != nil {
			log.Fatalf("failed to create output file: %v", err)
		}
		defer f.Close()
		w = f
	}

	fmt.Fprintln(w, string(data))
	return 0
}
