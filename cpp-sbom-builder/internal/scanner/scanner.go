package scanner

import "fmt"

// Component represents a single discovered third-party dependency.
type Component struct {
	Name        string
	Version     string
	PURL        string // Package URL — primary deduplication key
	Description string
}

// Strategy is the interface each dependency-detection mechanism must implement.
// Concrete implementations (e.g. CMake parser, vcpkg parser) are added separately.
type Strategy interface {
	// Name returns a human-readable label used in error messages and logging.
	Name() string
	// Scan walks dir and returns all Components it can discover.
	Scan(dir string) ([]Component, error)
}

// Scanner orchestrates one or more Strategy implementations.
type Scanner struct {
	strategies []Strategy
}

// New constructs a Scanner with the given strategies.
func New(strategies ...Strategy) *Scanner {
	return &Scanner{strategies: strategies}
}

// Scan runs every registered strategy against dir, collects results,
// deduplicates by PURL (fallback key: "Name@Version" when PURL is empty),
// and returns a stable-ordered slice.
func (s *Scanner) Scan(dir string) ([]Component, error) {
	seen := make(map[string]Component)
	order := make([]string, 0)

	for _, strategy := range s.strategies {
		components, err := strategy.Scan(dir)
		if err != nil {
			return nil, fmt.Errorf("strategy %q: %w", strategy.Name(), err)
		}
		for _, c := range components {
			key := c.PURL
			if key == "" {
				key = c.Name + "@" + c.Version
			}
			if _, exists := seen[key]; !exists {
				order = append(order, key)
			}
			seen[key] = c
		}
	}

	result := make([]Component, 0, len(order))
	for _, key := range order {
		result = append(result, seen[key])
	}
	return result, nil
}
