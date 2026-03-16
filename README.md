# incredibuild-interview-assignment
## cpp-sbom-builder

A CLI tool that scans a C++ project directory and produces a Software Bill of Materials (SBOM) in [SPDX 2.3](https://spdx.github.io/spdx-spec/v2.3/) JSON format.

### Prerequisites

- [Go 1.21+](https://go.dev/dl/)

### Running in a local environment

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
cpp-sbom-builder --target <dir> [--output <file>]

Flags:
  --target   path to the C++ project root directory (required)
  --output   write the SBOM to this file instead of stdout
```

### Executing against the sample project

2 sample C++ projects are provided under `sample-projects/` for quick verification.
1. spdlog - Its an open source project from: https://github.com/gabime/spdlog
chosen since it was said to have 3rd party dependencies that enlisted only in headers.

2. crow - also used open source project https://github.com/CrowCpp/Crow, since strategies vcpkg-manifest and binary-analysis worked on it and not spdlog.

commited both to `sample-projects/`. since I worked on a specific commit, was not sure a git submodule would produce the same outputs.

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

### Running the test suite

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
- each strategy


## Notes

1. I tried different strategies - and removed 2 that were not successfull in finding anything in the 2 sample projects. those were:

- Compiler Build Log Analysis - analyze compile_commands.json for -I, -L flags. thought powerful because it reflects what the compiler actually saw during the build.
- pkg-config metadata, about what installed via system package managers or local builds.

2. I created layered orchertration of strategies. to allow strategies to be more effient (for exp in versionmacro), and to allow conceptual seperation, for example for more relaible strategies.