package scanner

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
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


// logStrategyResult logs the names of dependencies found by a strategy.
func logStrategyResult(strategyName string, deps []Dependency) {
	names := make([]string, len(deps))
	for i, d := range deps {
		names[i] = d.Name
	}
	fmt.Printf("strategy %q found %d dependencies: %v\n", strategyName, len(deps), names)
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
			logStrategyResult(r.name, r.deps)
			registry.Merge(r.deps)
		}
	}

	projectName := filepath.Base(filepath.Clean(projectRoot))
	return filterSelfReference(registry.All(), projectName), nil
}

// filterSelfReference removes any dependency whose name matches the project name (case-insensitive),
// preventing the project from listing itself as its own dependency.
func filterSelfReference(deps []Dependency, projectName string) []Dependency {
	var out []Dependency
	for _, d := range deps {
		if !strings.EqualFold(d.Name, projectName) {
			out = append(out, d)
		}
	}
	return out
}
