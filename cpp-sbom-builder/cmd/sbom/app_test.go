package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestRun_MissingTarget(t *testing.T) {
	var stderr bytes.Buffer
	code := run([]string{}, &bytes.Buffer{}, &stderr)

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
	if !bytes.Contains(stderr.Bytes(), []byte("--target is required")) {
		t.Errorf("expected --target error in stderr, got: %s", stderr.String())
	}
}

func TestRun_TargetNotADirectory(t *testing.T) {
	tmp, err := os.CreateTemp(t.TempDir(), "notadir-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	tmp.Close()

	var stderr bytes.Buffer
	code := run([]string{"--target", tmp.Name()}, &bytes.Buffer{}, &stderr)

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
	if !bytes.Contains(stderr.Bytes(), []byte("not a valid directory")) {
		t.Errorf("expected directory error in stderr, got: %s", stderr.String())
	}
}

func TestRun_TargetNonExistent(t *testing.T) {
	var stderr bytes.Buffer
	code := run([]string{"--target", "/nonexistent/path/xyz"}, &bytes.Buffer{}, &stderr)

	if code != 1 {
		t.Errorf("expected exit code 1, got %d", code)
	}
	if !bytes.Contains(stderr.Bytes(), []byte("not a valid directory")) {
		t.Errorf("expected directory error in stderr, got: %s", stderr.String())
	}
}

func TestRun_ValidTargetProducesOutput(t *testing.T) {
	dir := t.TempDir()

	var stdout bytes.Buffer
	code := run([]string{"--target", dir}, &stdout, &bytes.Buffer{})

	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
	if stdout.Len() == 0 {
		t.Error("expected non-empty stdout output")
	}
}

func TestRun_OutputWrittenToFile(t *testing.T) {
	dir := t.TempDir()
	outFile := filepath.Join(dir, "sbom.json")

	code := run([]string{"--target", dir, "--output", outFile}, &bytes.Buffer{}, &bytes.Buffer{})

	if code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("output file not created: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty output file")
	}
}
