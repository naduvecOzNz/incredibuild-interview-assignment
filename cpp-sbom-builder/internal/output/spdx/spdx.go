package spdx

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"regexp"
	"time"

	"cpp-sbom-builder/internal/scanner"
)

// SpdxCreationInfo mirrors the SPDX 2.3 creationInfo object.
type SpdxCreationInfo struct {
	Created  string   `json:"created"`  // RFC3339 UTC timestamp
	Creators []string `json:"creators"` // e.g. ["Tool: cpp-sbom-builder"]
}

// SpdxExternalRef holds a reference attached to an SpdxPackage (e.g. a PURL).
type SpdxExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"` // "PACKAGE-MANAGER"
	ReferenceType     string `json:"referenceType"`     // "purl"
	ReferenceLocator  string `json:"referenceLocator"`  // the PURL string
}

// SpdxPackage mirrors the SPDX 2.3 package element.
type SpdxPackage struct {
	SPDXID           string            `json:"SPDXID"`
	Name             string            `json:"name"`
	Version          string            `json:"versionInfo,omitempty"`
	DownloadLocation string            `json:"downloadLocation"`
	FilesAnalyzed    bool              `json:"filesAnalyzed"`
	ExternalRefs     []SpdxExternalRef `json:"externalRefs,omitempty"`
	LicenseConcluded string            `json:"licenseConcluded"`
	LicenseDeclared  string            `json:"licenseDeclared"`
	CopyrightText    string            `json:"copyrightText"`
	Comment          string            `json:"comment,omitempty"`
}

// SpdxSbom is the top-level SPDX 2.3 document structure.
type SpdxSbom struct {
	SPDXVersion       string           `json:"spdxVersion"`
	DataLicense       string           `json:"dataLicense"`
	SPDXID            string           `json:"SPDXID"`
	Name              string           `json:"name"`
	DocumentNamespace string           `json:"documentNamespace"`
	CreationInfo      SpdxCreationInfo `json:"creationInfo"`
	Packages          []SpdxPackage    `json:"packages"`
}

var nonAlphanumeric = regexp.MustCompile(`[^a-zA-Z0-9]`)

func sanitizeSPDXID(s string) string {
	return nonAlphanumeric.ReplaceAllString(s, "-")
}

func newUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func dependencyToSpdxPackage(d scanner.Dependency, usedIDs map[string]int) SpdxPackage {
	spdxID := generateSPDXID(d, usedIDs)

	pkg := SpdxPackage{
		SPDXID:           spdxID,
		Name:             d.Name,
		Version:          d.Version,
		DownloadLocation: "NOASSERTION",
		FilesAnalyzed:    false,
		LicenseConcluded: "NOASSERTION",
		LicenseDeclared:  "NOASSERTION",
		CopyrightText:    "NOASSERTION",
	}

	if d.PURL != "" {
		pkg.ExternalRefs = []SpdxExternalRef{
			{
				ReferenceCategory: "PACKAGE-MANAGER",
				ReferenceType:     "purl",
				ReferenceLocator:  d.PURL,
			},
		}
	}

	return pkg
}

// also consider used ids - if collide, create a new one with index
func generateSPDXID(d scanner.Dependency, usedIDs map[string]int) string {
	base := "SPDXRef-" + sanitizeSPDXID(d.Name+"-"+d.Version)
	usedIDs[base]++
	spdxID := base
	if usedIDs[base] > 1 {
		spdxID = fmt.Sprintf("%s-%d", base, usedIDs[base])
	}
	return spdxID
}

// NewSpdxSbom constructs a valid SPDX 2.3 SpdxSbom from a project name and dependencies.
func NewSpdxSbom(projectName string, components []scanner.Dependency) *SpdxSbom {
	usedIDs := map[string]int{}
	packages := make([]SpdxPackage, 0, len(components))
	for _, c := range components {
		packages = append(packages, dependencyToSpdxPackage(c, usedIDs))
	}

	return &SpdxSbom{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXID:            "SPDXRef-DOCUMENT",
		Name:              projectName,
		DocumentNamespace: fmt.Sprintf("https://cpp-sbom-builder/%s-%s", sanitizeSPDXID(projectName), newUUID()),
		CreationInfo: SpdxCreationInfo{
			Created:  time.Now().UTC().Format(time.RFC3339),
			Creators: []string{"Tool: cpp-sbom-builder"},
		},
		Packages: packages,
	}
}

// GenerateSpdxSbom serialises doc to indented JSON.
func GenerateSpdxSbom(doc *SpdxSbom) ([]byte, error) {
	return json.MarshalIndent(doc, "", "  ")
}

// SbomFormatter implements output.SbomFormatter for SPDX 2.3.
type SbomFormatter struct{}

func (SbomFormatter) Format() string { return "spdx" }

func (SbomFormatter) Generate(projectName string, components []scanner.Dependency) ([]byte, error) {
	return GenerateSpdxSbom(NewSpdxSbom(projectName, components))
}
