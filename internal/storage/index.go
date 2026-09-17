package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// Index is the local list of secret names and metadata. It never holds
// values. It exists because most backends cannot enumerate what they store
// (a keychain cannot be listed by prefix, a vendor CLI may not support
// filtering), and because listing must not require touching every value.
type Index struct {
	path string
	mu   sync.Mutex
}

type indexFile struct {
	V       int                 `json:"v"`
	Entries map[string]Metadata `json:"entries"`
}

// OpenIndex uses the file at path, creating its directory if needed.
func OpenIndex(path string) (*Index, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("storage: index directory: %w", err)
	}
	return &Index{path: path}, nil
}

// Path returns the index file location.
func (i *Index) Path() string { return i.path }

func (i *Index) load() (indexFile, error) {
	f := indexFile{V: 1, Entries: map[string]Metadata{}}
	b, err := os.ReadFile(i.path)
	if errors.Is(err, os.ErrNotExist) {
		return f, nil
	}
	if err != nil {
		return f, fmt.Errorf("storage: read index: %w", err)
	}
	if err := json.Unmarshal(b, &f); err != nil {
		return f, fmt.Errorf("storage: index is corrupt: %w", err)
	}
	if f.Entries == nil {
		f.Entries = map[string]Metadata{}
	}
	return f, nil
}

func (i *Index) save(f indexFile) error {
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(i.path, b, 0o600)
}

// Put records metadata for a name.
func (i *Index) Put(meta Metadata) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	f, err := i.load()
	if err != nil {
		return err
	}
	f.Entries[meta.Name] = meta
	return i.save(f)
}

// Get returns the metadata for a name.
func (i *Index) Get(name string) (Metadata, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	f, err := i.load()
	if err != nil {
		return Metadata{}, err
	}
	m, ok := f.Entries[name]
	if !ok {
		return Metadata{}, ErrNotFound
	}
	return m, nil
}

// Delete removes a name. Removing an unknown name is not an error.
func (i *Index) Delete(name string) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	f, err := i.load()
	if err != nil {
		return err
	}
	if _, ok := f.Entries[name]; !ok {
		return nil
	}
	delete(f.Entries, name)
	return i.save(f)
}

// List returns every entry sorted by name.
func (i *Index) List() ([]Metadata, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	f, err := i.load()
	if err != nil {
		return nil, err
	}
	out := make([]Metadata, 0, len(f.Entries))
	for _, m := range f.Entries {
		out = append(out, m)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Name < out[b].Name })
	return out, nil
}

// writeFileAtomic writes data to a temporary file in the same directory and
// renames it into place, so a crash never leaves a half-written file.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if err := tmp.Chmod(perm); err != nil && !errors.Is(err, os.ErrPermission) {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return err
	}
	return nil
}
