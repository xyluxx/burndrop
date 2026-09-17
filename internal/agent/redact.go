package agent

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"sort"
	"strings"
	"sync"
)

// Redactor replaces known secret values, and their common encodings, in
// text that is about to leave the process: command output, error messages,
// tool results. It is a safety net behind the rule that values are never
// put into model-facing output on purpose.
type Redactor struct {
	mu    sync.RWMutex
	forms []redactForm
}

type redactForm struct {
	name  string
	bytes []byte
}

// minRedactLen keeps very short values from masking ordinary text.
const minRedactLen = 6

// NewRedactor returns an empty redactor.
func NewRedactor() *Redactor { return &Redactor{} }

// Add registers a value under a name. Encoded forms are registered too:
// standard and URL-safe base64 (with and without padding), hex, URL query
// escaping, and JSON string escaping when it differs from the raw bytes.
func (r *Redactor) Add(name string, value []byte) {
	if len(value) < minRedactLen {
		return
	}
	forms := [][]byte{
		value,
		[]byte(base64.StdEncoding.EncodeToString(value)),
		[]byte(base64.RawStdEncoding.EncodeToString(value)),
		[]byte(base64.URLEncoding.EncodeToString(value)),
		[]byte(base64.RawURLEncoding.EncodeToString(value)),
		[]byte(hex.EncodeToString(value)),
		[]byte(url.QueryEscape(string(value))),
		[]byte(url.PathEscape(string(value))),
	}
	if js, err := json.Marshal(string(value)); err == nil && len(js) > 2 {
		forms = append(forms, js[1:len(js)-1])
	}
	trimmed := bytes.TrimSpace(value)
	if len(trimmed) != len(value) && len(trimmed) > 0 {
		forms = append(forms, trimmed)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	seen := map[string]bool{}
	for _, f := range r.forms {
		seen[string(f.bytes)] = true
	}
	for _, f := range forms {
		if len(f) < minRedactLen || seen[string(f)] {
			continue
		}
		seen[string(f)] = true
		r.forms = append(r.forms, redactForm{name: name, bytes: append([]byte(nil), f...)})
	}
	// Longest first so a longer encoding is replaced before a substring of it.
	sort.SliceStable(r.forms, func(i, j int) bool { return len(r.forms[i].bytes) > len(r.forms[j].bytes) })
}

// Remove forgets every form registered under name.
func (r *Redactor) Remove(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	kept := r.forms[:0]
	for _, f := range r.forms {
		if f.name != name {
			kept = append(kept, f)
		}
	}
	r.forms = kept
}

// Redact returns s with every known form replaced by [redacted:<name>].
func (r *Redactor) Redact(s string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if len(r.forms) == 0 || s == "" {
		return s
	}
	out := s
	for _, f := range r.forms {
		if strings.Contains(out, string(f.bytes)) {
			out = strings.ReplaceAll(out, string(f.bytes), "[redacted:"+f.name+"]")
		}
	}
	return out
}

// RedactBytes is Redact for byte slices.
func (r *Redactor) RedactBytes(b []byte) []byte {
	return []byte(r.Redact(string(b)))
}

// Count reports how many forms are registered; for tests and diagnostics.
func (r *Redactor) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.forms)
}
