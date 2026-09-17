package storage

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"
)

// Manager applies retention policies over one persistent backend plus a
// memory backend for session-scoped secrets, and keeps the local index in
// step with what was stored.
type Manager struct {
	persistent Backend
	session    *Memory
	index      *Index
	now        func() time.Time
}

// NewManager wires a persistent backend, an index, and a clock (nil means
// time.Now).
func NewManager(persistent Backend, index *Index, now func() time.Time) *Manager {
	if now == nil {
		now = time.Now
	}
	return &Manager{persistent: persistent, session: NewMemory(), index: index, now: now}
}

// Persistent returns the configured persistent backend.
func (m *Manager) Persistent() Backend { return m.persistent }

// Put stores a value according to meta.Retention. It fills in the timestamps,
// the expiry, and the backend name.
func (m *Manager) Put(ctx context.Context, name string, value []byte, meta Metadata) (Metadata, error) {
	if err := ValidateName(name); err != nil {
		return Metadata{}, err
	}
	if len(value) > MaxValueBytes {
		return Metadata{}, ErrTooLarge
	}
	now := m.now().UTC().Truncate(time.Second)
	expires, err := ParseRetention(meta.Retention, now)
	if err != nil {
		return Metadata{}, err
	}
	meta.Name = name
	meta.CreatedAt = now
	meta.ExpiresAt = expires
	meta.SizeBytes = len(value)
	if meta.Source == "" {
		meta.Source = SourceDrop
	}
	if meta.Retention == RetentionSession {
		meta.Backend = m.session.Name()
		if err := m.session.Put(ctx, name, value, meta); err != nil {
			return Metadata{}, err
		}
		// A session secret shadows any persistent one with the same name.
		return meta, nil
	}
	meta.Backend = m.persistent.Name()
	if err := m.persistent.Put(ctx, name, value, meta); err != nil {
		return Metadata{}, err
	}
	if err := m.index.Put(meta); err != nil {
		return Metadata{}, fmt.Errorf("stored, but could not update the index: %w", err)
	}
	return meta, nil
}

// Get returns a value, checking session storage first. Expired entries are
// deleted and reported as not found.
func (m *Manager) Get(ctx context.Context, name string) ([]byte, Metadata, error) {
	if err := ValidateName(name); err != nil {
		return nil, Metadata{}, err
	}
	if value, meta, err := m.session.Get(ctx, name); err == nil {
		if meta.Expired(m.now()) {
			_ = m.session.Delete(ctx, name)
			return nil, Metadata{}, ErrNotFound
		}
		return value, meta, nil
	}
	value, meta, err := m.persistent.Get(ctx, name)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			_ = m.index.Delete(name)
		}
		return nil, Metadata{}, err
	}
	if meta.Expired(m.now()) {
		Zero(value)
		_ = m.persistent.Delete(ctx, name)
		_ = m.index.Delete(name)
		return nil, Metadata{}, ErrNotFound
	}
	return value, meta, nil
}

// Delete removes a secret from wherever it lives. It succeeds if the secret
// was removed from at least one place.
func (m *Manager) Delete(ctx context.Context, name string) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	sessionErr := m.session.Delete(ctx, name)
	persistentErr := m.persistent.Delete(ctx, name)
	indexErr := m.index.Delete(name)
	if indexErr != nil {
		return indexErr
	}
	if sessionErr == nil || persistentErr == nil {
		return nil
	}
	if errors.Is(persistentErr, ErrNotFound) {
		return ErrNotFound
	}
	return persistentErr
}

// List returns metadata for every known secret: session entries plus the
// index, with expired entries purged first.
func (m *Manager) List(ctx context.Context) ([]Metadata, error) {
	if _, err := m.PurgeExpired(ctx); err != nil {
		return nil, err
	}
	session, err := m.session.List(ctx)
	if err != nil {
		return nil, err
	}
	indexed, err := m.index.List()
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool, len(session))
	out := make([]Metadata, 0, len(session)+len(indexed))
	for _, s := range session {
		seen[s.Name] = true
		out = append(out, s)
	}
	for _, i := range indexed {
		if !seen[i.Name] {
			out = append(out, i)
		}
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Name < out[b].Name })
	return out, nil
}

// PurgeExpired deletes every entry whose retention date has passed.
func (m *Manager) PurgeExpired(ctx context.Context) (int, error) {
	now := m.now()
	n := 0
	session, err := m.session.List(ctx)
	if err != nil {
		return 0, err
	}
	for _, s := range session {
		if s.Expired(now) {
			if err := m.session.Delete(ctx, s.Name); err == nil {
				n++
			}
		}
	}
	indexed, err := m.index.List()
	if err != nil {
		return n, err
	}
	for _, i := range indexed {
		if i.Expired(now) {
			if err := m.persistent.Delete(ctx, i.Name); err != nil && !errors.Is(err, ErrNotFound) {
				return n, err
			}
			if err := m.index.Delete(i.Name); err != nil {
				return n, err
			}
			n++
		}
	}
	return n, nil
}

// Close clears session secrets.
func (m *Manager) Close() { m.session.Close() }
