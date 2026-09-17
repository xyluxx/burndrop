package agent

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Audit appends one JSON line per event to a file with owner-only
// permissions. Entries carry names, identifiers, and outcomes, never values.
type Audit struct {
	path string
	mu   sync.Mutex
	now  func() time.Time
}

// Event is one audit entry.
type Event struct {
	Time   time.Time         `json:"time"`
	Event  string            `json:"event"`
	Name   string            `json:"name,omitempty"`
	DropID string            `json:"drop_id,omitempty"`
	Result string            `json:"result,omitempty"`
	Detail string            `json:"detail,omitempty"`
	Fields map[string]string `json:"fields,omitempty"`
}

const maxAuditBytes = 8 << 20

// NewAudit opens (creating if needed) the log at path. An empty path yields
// a disabled log that discards events.
func NewAudit(path string, now func() time.Time) (*Audit, error) {
	if now == nil {
		now = time.Now
	}
	if path == "" || path == "off" {
		return &Audit{now: now}, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	_ = f.Close()
	return &Audit{path: path, now: now}, nil
}

// Path returns the log location, empty when disabled.
func (a *Audit) Path() string { return a.path }

// Log appends an event. Failures are returned but callers treat them as
// non-fatal: an audit failure must not lose a secret already received.
func (a *Audit) Log(e Event) error {
	if a == nil || a.path == "" {
		return nil
	}
	e.Time = a.now().UTC().Truncate(time.Millisecond)
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if info, err := os.Stat(a.path); err == nil && info.Size() > maxAuditBytes {
		// Keep one previous generation; the log is a convenience, not a ledger.
		_ = os.Remove(a.path + ".1")
		_ = os.Rename(a.path, a.path+".1")
	}
	f, err := os.OpenFile(a.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(b, '\n'))
	return err
}

// Read returns the last n events, oldest first.
func (a *Audit) Read(n int) ([]Event, error) {
	if a == nil || a.path == "" {
		return nil, nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	b, err := os.ReadFile(a.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var events []Event
	dec := json.NewDecoder(bytesReader(b))
	for dec.More() {
		var e Event
		if err := dec.Decode(&e); err != nil {
			break
		}
		events = append(events, e)
	}
	if n > 0 && len(events) > n {
		events = events[len(events)-n:]
	}
	return events, nil
}
