package scanner

import "sync"

// ReadOnlyRegistry is the read-only view of the registry passed to each strategy.
type ReadOnlyRegistry interface {
	Get(key string) (Dependency, bool)
	All() []Dependency
}

// registrySnapshot is an immutable snapshot implementing ReadOnlyRegistry.
type registrySnapshot struct {
	data  map[string]Dependency
	order []string
}

func (s *registrySnapshot) Get(key string) (Dependency, bool) {
	d, ok := s.data[key]
	return d, ok
}

func (s *registrySnapshot) All() []Dependency {
	out := make([]Dependency, 0, len(s.order))
	for _, k := range s.order {
		out = append(out, s.data[k])
	}
	return out
}

// Registry is the mutable accumulator; only the Orchestrator writes to it.
type Registry struct {
	mu    sync.Mutex
	seen  map[string]Dependency
	order []string
}

func newRegistry() *Registry {
	return &Registry{seen: make(map[string]Dependency)}
}

func depKey(d Dependency) string {
	if d.PURL != "" {
		return d.PURL
	}
	return d.Name + "@" + d.Version
}

// Merge upserts deps into the registry.
// New deps are added; existing deps are enriched with any missing Version or PURL.
func (r *Registry) Merge(deps []Dependency) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, d := range deps {
		key := depKey(d)
		existing, exists := r.seen[key]
		if !exists {
			r.order = append(r.order, key)
			r.seen[key] = d
			continue
		}
		if existing.Version == "" {
			existing.Version = d.Version
		}
		if existing.PURL == "" {
			existing.PURL = d.PURL
		}
		r.seen[key] = existing
	}
}

// ReadOnly returns an immutable snapshot of the current registry state.
func (r *Registry) ReadOnly() ReadOnlyRegistry {
	r.mu.Lock()
	defer r.mu.Unlock()
	snap := &registrySnapshot{
		data:  make(map[string]Dependency, len(r.seen)),
		order: make([]string, len(r.order)),
	}
	copy(snap.order, r.order)
	for k, v := range r.seen {
		snap.data[k] = v
	}
	return snap
}

// All returns all dependencies in stable insertion order.
func (r *Registry) All() []Dependency {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Dependency, 0, len(r.order))
	for _, k := range r.order {
		out = append(out, r.seen[k])
	}
	return out
}
