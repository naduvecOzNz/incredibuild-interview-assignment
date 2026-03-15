package spdx

import (
	"encoding/json"
	"strings"
	"testing"

	"cpp-sbom-builder/internal/scanner"
)

func TestNewSpdxSbom_RequiredFields(t *testing.T) {
	doc := NewSpdxSbom("my-project", nil)

	if doc.SPDXVersion != "SPDX-2.3" {
		t.Errorf("spdxVersion: want %q, got %q", "SPDX-2.3", doc.SPDXVersion)
	}
	if doc.DataLicense != "CC0-1.0" {
		t.Errorf("dataLicense: want %q, got %q", "CC0-1.0", doc.DataLicense)
	}
	if doc.SPDXID != "SPDXRef-DOCUMENT" {
		t.Errorf("SPDXID: want %q, got %q", "SPDXRef-DOCUMENT", doc.SPDXID)
	}
	if doc.Name != "my-project" {
		t.Errorf("name: want %q, got %q", "my-project", doc.Name)
	}
	if doc.DocumentNamespace == "" {
		t.Error("documentNamespace must not be empty")
	}
	if !strings.HasPrefix(doc.DocumentNamespace, "https://cpp-sbom-builder/") {
		t.Errorf("documentNamespace must start with https://cpp-sbom-builder/, got %q", doc.DocumentNamespace)
	}
	if doc.CreationInfo.Created == "" {
		t.Error("creationInfo.created must not be empty")
	}
	if len(doc.CreationInfo.Creators) == 0 {
		t.Error("creationInfo.creators must not be empty")
	}
}

func TestNewSpdxSbom_DocumentNamespaceIsUnique(t *testing.T) {
	doc1 := NewSpdxSbom("proj", nil)
	doc2 := NewSpdxSbom("proj", nil)

	if doc1.DocumentNamespace == doc2.DocumentNamespace {
		t.Error("documentNamespace should be unique across documents")
	}
}

func TestNewSpdxSbom_PackageFields(t *testing.T) {
	components := []scanner.Dependency{
		{
			Name:    "fmt",
			Version: "9.1.0",
			PURL:    "pkg:github/fmtlib/fmt@9.1.0",
		},
	}

	doc := NewSpdxSbom("test-project", components)

	if len(doc.Packages) != 1 {
		t.Fatalf("expected 1 package, got %d", len(doc.Packages))
	}

	pkg := doc.Packages[0]

	if pkg.Name != "fmt" {
		t.Errorf("package name: want %q, got %q", "fmt", pkg.Name)
	}
	if pkg.Version != "9.1.0" {
		t.Errorf("package version: want %q, got %q", "9.1.0", pkg.Version)
	}
	if !strings.HasPrefix(pkg.SPDXID, "SPDXRef-") {
		t.Errorf("package SPDXID must start with SPDXRef-, got %q", pkg.SPDXID)
	}
	if pkg.DownloadLocation != "NOASSERTION" {
		t.Errorf("downloadLocation: want %q, got %q", "NOASSERTION", pkg.DownloadLocation)
	}
	if pkg.FilesAnalyzed {
		t.Error("filesAnalyzed must be false")
	}
	if pkg.CopyrightText != "NOASSERTION" {
		t.Errorf("copyrightText: want %q, got %q", "NOASSERTION", pkg.CopyrightText)
	}
	if pkg.LicenseConcluded != "NOASSERTION" {
		t.Errorf("licenseConcluded: want %q, got %q", "NOASSERTION", pkg.LicenseConcluded)
	}
	if pkg.LicenseDeclared != "NOASSERTION" {
		t.Errorf("licenseDeclared: want %q, got %q", "NOASSERTION", pkg.LicenseDeclared)
	}
	if len(pkg.ExternalRefs) != 1 {
		t.Fatalf("expected 1 external ref, got %d", len(pkg.ExternalRefs))
	}
	ref := pkg.ExternalRefs[0]
	if ref.ReferenceCategory != "PACKAGE-MANAGER" {
		t.Errorf("referenceCategory: want %q, got %q", "PACKAGE-MANAGER", ref.ReferenceCategory)
	}
	if ref.ReferenceType != "purl" {
		t.Errorf("referenceType: want %q, got %q", "purl", ref.ReferenceType)
	}
	if ref.ReferenceLocator != "pkg:github/fmtlib/fmt@9.1.0" {
		t.Errorf("referenceLocator: want %q, got %q", "pkg:github/fmtlib/fmt@9.1.0", ref.ReferenceLocator)
	}
}

func TestNewSpdxSbom_NoPURLOmitsExternalRefs(t *testing.T) {
	components := []scanner.Dependency{
		{Name: "somelib", Version: "1.0.0"},
	}
	doc := NewSpdxSbom("proj", components)

	if len(doc.Packages[0].ExternalRefs) != 0 {
		t.Error("expected no external refs when PURL is empty")
	}
}

func TestGenerate_ValidJSON(t *testing.T) {
	doc := NewSpdxSbom("my-project", nil)
	data, err := GenerateSpdxSbom(doc)

	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}
	if !json.Valid(data) {
		t.Errorf("Generate did not produce valid JSON: %s", string(data))
	}
}

func TestGenerate_JSONContainsRequiredFields(t *testing.T) {
	doc := NewSpdxSbom("my-project", nil)
	data, err := GenerateSpdxSbom(doc)
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}

	for _, field := range []string{"spdxVersion", "dataLicense", "SPDXID", "name", "documentNamespace", "creationInfo", "packages"} {
		if _, ok := parsed[field]; !ok {
			t.Errorf("required field %q missing from JSON output", field)
		}
	}
}

