.PHONY: build run test clean

build:
	go build -o bin/cpp-sbom-builder ./cmd/sbom

run:
	go run ./cmd/sbom --target .

test:
	go test ./...

clean:
	rm -rf bin/
