package scanner

import (
	"context"
	"fmt"
	"sync"
)

// Dependency represents a discovered third-party dependency.
type Dependency struct {
	Name    string
	Version string // empty if unknown
	PURL    string // primary deduplication key
}

// DependenciesDetectionStrategy is the interface each dependency-detection mechanism must implement.
// Concrete implementations are added separately; strategies are layer-agnostic.
type DependenciesDetectionStrategy interface {
	// Name returns a human-readable label used in error messages and logging.
	Name() string
	// Analyze inspects projectRoot using the file index and a read-only registry
	// snapshot, and returns new or enriched dependencies.
	Analyze(ctx context.Context, projectRoot string, idx *FileIndex, reg ReadOnlyRegistry) ([]Dependency, error)
}

// Orchestrator runs detection strategies in layers sequentially,
// executing all strategies within a layer concurrently.
type Orchestrator struct {
	layers [][]DependenciesDetectionStrategy
}

// NewOrchestrator is the generic constructor used by New() and tests.
// Each argument is a layer; layers execute in order, strategies within a layer run concurrently.
func NewOrchestrator(layers ...[]DependenciesDetectionStrategy) *Orchestrator {
	return &Orchestrator{layers: layers}
}

// New constructs the default Orchestrator with all configured detection layers.
// Layer assignment and strategy selection live here; callers remain unaware of both.
func New() *Orchestrator {
	return NewOrchestrator(
		[]DependenciesDetectionStrategy{ /* L1: manifest strategies (CMake, Conan, vcpkg) */ },
		[]DependenciesDetectionStrategy{ /* L2: binary + compile_commands strategies — run in parallel */ },
		[]DependenciesDetectionStrategy{ /* L3: pkg-config strategies */ },
		[]DependenciesDetectionStrategy{ /* L4: header include strategies */ },
	)
}

// Run indexes the project filesystem once, then executes each layer in order.
// Strategies within a layer run concurrently; each layer receives the registry
// state accumulated by all prior layers.
func (o *Orchestrator) Run(ctx context.Context, projectRoot string) ([]Dependency, error) {
	idx, err := Index(projectRoot)
	if err != nil {
		return nil, fmt.Errorf("file index: %w", err)
	}

	registry := newRegistry()

	for _, layer := range o.layers {
		if len(layer) == 0 {
			continue
		}

		snapshot := registry.ReadOnly()

		type result struct {
			deps []Dependency
			err  error
			name string
		}
		ch := make(chan result, len(layer))

		var wg sync.WaitGroup
		for _, strategy := range layer {
			wg.Go(func() {
				deps, err := strategy.Analyze(ctx, projectRoot, idx, snapshot)
				ch <- result{deps: deps, err: err, name: strategy.Name()}
			})
		}
		wg.Wait()
		close(ch)

		for r := range ch {
			if r.err != nil {
				return nil, fmt.Errorf("strategy %q: %w", r.name, r.err)
			}
			registry.Merge(r.deps)
		}
	}

	return registry.All(), nil
}
