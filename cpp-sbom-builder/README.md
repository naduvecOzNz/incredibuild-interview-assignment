# cpp-sbom-builder

A CLI tool that scans a C++ project directory and produces a Software Bill of Materials (SBOM) in [SPDX 2.3](https://spdx.github.io/spdx-spec/v2.3/) JSON format.

## Prerequisites

- [Go 1.21+](https://go.dev/dl/)

## Running in a local environment

```bash
# Clone the repository
git clone <repo-url>
cd cpp-sbom-builder

# Build the binary
make build
# Binary is produced at: bin/cpp-sbom-builder

# Or build manually
go build -o bin/cpp-sbom-builder ./cmd/sbom
```

### Usage

```
cpp-sbom-builder --target <dir> [--output <file>] [--format spdx]

Flags:
  --target   path to the C++ project root directory (required)
  --output   write the SBOM to this file instead of stdout
  --format   output format (default: spdx)
```

## Executing against the sample project

A sample C++ project is provided under `sample-projects/` for quick verification.
Its an open source project from: https://github.com/gabime/spdlog
chosen since it was said to have 3rd party dependencies that enlisted only in headers.

```bash
# Output to stdout
./bin/cpp-sbom-builder --target sample-projects/spdlog

# Write to a file
./bin/cpp-sbom-builder --target sample-projects/spdlog --output sbom.json

# Inspect the result
cat sbom.json
```

Expected output is a valid SPDX 2.3 JSON document:

```json
{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  ...
}
```

## Running the test suite

```bash
# Run all tests
make test

# Or directly
go test ./...

# Run with verbose output
go test -v ./...
```

The test suite verifies:
- SPDX 2.3 output format correctness (required fields, valid JSON structure)
- CLI flag validation
