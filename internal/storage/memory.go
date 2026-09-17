package storage

import (
	"context"
	"sort"
	"sync"
)

// Memory holds values in process memory only. It is the backend for
// session-scoped secrets and the recommended choice for CI runners.
type Memory struct {
	mu      sync.Mutex
	entries map[string]memoryEntry
}

type memoryEntry struct {
	value []byte
	meta  Metadata
}

// NewMemory creates an empty memory backend.
func NewMemory() *Memory {
	return &Memory{entries: map[string]memoryEntry{}}
}

func (m *Memory) Name() string { return "memory" }

func (m *Memory) Probe(context.Context) Probe {
	return Probe{Available: true, Reason: "process memory; cleared when the process exits", Rank: 10}
}

func (m *Memory) Put(_ context.Context, name string, value []byte, meta Metadata) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	if len(value) > MaxValueBytes {
		return ErrTooLarge
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if old, ok := m.entries[name]; ok {
		Zero(old.value)
	}
	meta.Name = name
	meta.Backend = m.Name()
	meta.SizeBytes = len(value)
	m.entries[name] = memoryEntry{value: append([]byte(nil), value...), meta: meta}
	return nil
}

func (m *Memory) Get(_ context.Context, name string) ([]byte, Metadata, error) {
	if err := ValidateName(name); err != nil {
		return nil, Metadata{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.entries[name]
	if !ok {
		return nil, Metadata{}, ErrNotFound
	}
	return append([]byte(nil), e.value...), e.meta, nil
}

func (m *Memory) Delete(_ context.Context, name string) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.entries[name]
	if !ok {
		return ErrNotFound
	}
	Zero(e.value)
	delete(m.entries, name)
	return nil
}

func (m *Memory) List(context.Context) ([]Metadata, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Metadata, 0, len(m.entries))
	for _, e := range m.entries {
		out = append(out, e.meta)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Name < out[b].Name })
	return out, nil
}

// Close zeroes and drops every value.
func (m *Memory) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range m.entries {
		Zero(e.value)
	}
	m.entries = map[string]memoryEntry{}
}
