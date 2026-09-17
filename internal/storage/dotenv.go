package storage

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"
)

// Dotenv writes secrets to a .env file with mode 0600. It is the weakest
// backend and is opt-in: the file must be ignored by git when it sits inside
// a repository, and the operator is told so at probe time.
//
// Each entry is one metadata comment followed by a KEY="value" line. Other
// lines in the file are preserved verbatim. Names map to environment keys
// by upper-casing and replacing every other character with an underscore.
type Dotenv struct {
	path string
	mu   sync.Mutex
	look func(string) (string, error)
}

// NewDotenv uses the file at path.
func NewDotenv(path string) *Dotenv {
	return &Dotenv{path: path, look: exec.LookPath}
}

func (d *Dotenv) Name() string { return "dotenv" }

// Path returns the file location.
func (d *Dotenv) Path() string { return d.path }

func (d *Dotenv) Probe(context.Context) Probe {
	if err := d.safe(); err != nil {
		return Probe{Reason: err.Error()}
	}
	return Probe{Available: true, Reason: "plain file " + d.path + " (weakest option; readable by any process running as you)", Rank: 1}
}

// safe refuses a location that git would commit.
func (d *Dotenv) safe() error {
	dir := filepath.Dir(d.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("%w: %v", ErrPermission, err)
	}
	root, inRepo := gitRoot(dir)
	if !inRepo {
		return nil
	}
	ignored, err := gitIgnored(d.look, root, d.path)
	if err != nil {
		return err
	}
	if !ignored {
		return fmt.Errorf("%w: %s is inside a git repository and is not ignored; add it to .gitignore first", ErrPermission, d.path)
	}
	return nil
}

// gitRoot walks up from dir looking for a .git entry.
func gitRoot(dir string) (string, bool) {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return "", false
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return dir, true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false
		}
		dir = parent
	}
}

// gitIgnored asks git when it is installed and otherwise reads the
// repository's top-level .gitignore for a rule that covers the file.
func gitIgnored(look func(string) (string, error), root, path string) (bool, error) {
	if _, err := look("git"); err == nil {
		cmd := exec.Command("git", "-C", root, "check-ignore", "-q", "--", path)
		err := cmd.Run()
		if err == nil {
			return true, nil
		}
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() == 1 {
			return false, nil
		}
		// Fall through to the file scan on any other failure.
	}
	b, err := os.ReadFile(filepath.Join(root, ".gitignore"))
	if err != nil {
		return false, nil
	}
	base := filepath.Base(path)
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		line = strings.TrimPrefix(line, "/")
		if line == base || line == ".env*" || line == "*.env" && strings.HasSuffix(base, ".env") || line == ".env.*" && strings.HasPrefix(base, ".env.") {
			return true, nil
		}
		if ok, _ := filepath.Match(line, base); ok {
			return true, nil
		}
	}
	return false, nil
}

// EnvKey converts a secret name to an environment variable name.
func EnvKey(name string) string {
	var sb strings.Builder
	for _, r := range strings.ToUpper(name) {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			sb.WriteRune(r)
		} else {
			sb.WriteByte('_')
		}
	}
	return sb.String()
}

type dotenvEntry struct {
	Name     string   `json:"name"`
	Meta     Metadata `json:"meta"`
	Encoding string   `json:"encoding,omitempty"` // "" for text, "base64" for binary
}

const dotenvMarker = "# burndrop: "

// file is the parsed form: entries by name plus the other lines in order.
type dotenvFile struct {
	entries map[string]dotenvRecord
	others  []string
}

type dotenvRecord struct {
	entry dotenvEntry
	value []byte
}

func (d *Dotenv) load() (*dotenvFile, error) {
	f := &dotenvFile{entries: map[string]dotenvRecord{}}
	b, err := os.ReadFile(d.path)
	if errors.Is(err, os.ErrNotExist) {
		return f, nil
	}
	if err != nil {
		return nil, fmt.Errorf("storage: read %s: %w", d.path, err)
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 64*1024), 4*MaxValueBytes)
	var pending *dotenvEntry
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, dotenvMarker) {
			var e dotenvEntry
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, dotenvMarker)), &e); err == nil && ValidateName(e.Name) == nil {
				pending = &e
				continue
			}
		}
		if pending != nil {
			key := EnvKey(pending.Name)
			if raw, ok := strings.CutPrefix(line, key+"="); ok {
				value, err := dotenvUnquote(raw)
				if err == nil && pending.Encoding == "base64" {
					value, err = base64.StdEncoding.DecodeString(string(value))
				}
				if err == nil {
					f.entries[pending.Name] = dotenvRecord{entry: *pending, value: value}
					pending = nil
					continue
				}
			}
			// The marker was not followed by our line; keep it as a plain line.
			f.others = append(f.others, dotenvMarker+mustJSON(pending))
			pending = nil
		}
		f.others = append(f.others, line)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("storage: read %s: %w", d.path, err)
	}
	return f, nil
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func (d *Dotenv) save(f *dotenvFile) error {
	var sb strings.Builder
	for _, line := range f.others {
		sb.WriteString(line)
		sb.WriteByte('\n')
	}
	names := make([]string, 0, len(f.entries))
	for n := range f.entries {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		r := f.entries[n]
		sb.WriteString(dotenvMarker)
		sb.WriteString(mustJSON(r.entry))
		sb.WriteByte('\n')
		sb.WriteString(EnvKey(n))
		sb.WriteByte('=')
		if r.entry.Encoding == "base64" {
			sb.WriteString(dotenvQuote(base64.StdEncoding.EncodeToString(r.value)))
		} else {
			sb.WriteString(dotenvQuote(string(r.value)))
		}
		sb.WriteByte('\n')
	}
	return writeFileAtomic(d.path, []byte(sb.String()), 0o600)
}

// dotenvQuote produces a double-quoted value with the escapes most dotenv
// parsers understand.
func dotenvQuote(s string) string {
	var sb strings.Builder
	sb.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			sb.WriteString(`\"`)
		case '\\':
			sb.WriteString(`\\`)
		case '\n':
			sb.WriteString(`\n`)
		case '\r':
			sb.WriteString(`\r`)
		case '\t':
			sb.WriteString(`\t`)
		case '$':
			sb.WriteString(`\$`)
		default:
			sb.WriteRune(r)
		}
	}
	sb.WriteByte('"')
	return sb.String()
}

func dotenvUnquote(raw string) ([]byte, error) {
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return nil, errors.New("value is not quoted")
	}
	body := raw[1 : len(raw)-1]
	var out []byte
	for i := 0; i < len(body); i++ {
		c := body[i]
		if c != '\\' {
			out = append(out, c)
			continue
		}
		i++
		if i >= len(body) {
			return nil, errors.New("dangling escape")
		}
		switch body[i] {
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case '"', '\\', '$':
			out = append(out, body[i])
		default:
			return nil, errors.New("unknown escape")
		}
	}
	return out, nil
}

// textual reports whether a value can be stored as a plain quoted string.
func textual(v []byte) bool {
	if !utf8.Valid(v) {
		return false
	}
	for _, r := range string(v) {
		if r < 0x20 && r != '\n' && r != '\r' && r != '\t' {
			return false
		}
	}
	return true
}

func (d *Dotenv) Put(_ context.Context, name string, value []byte, meta Metadata) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	if len(value) > MaxValueBytes {
		return ErrTooLarge
	}
	if err := d.safe(); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	f, err := d.load()
	if err != nil {
		return err
	}
	meta.Name = name
	meta.Backend = d.Name()
	meta.SizeBytes = len(value)
	e := dotenvEntry{Name: name, Meta: meta}
	if !textual(value) {
		e.Encoding = "base64"
	}
	for other := range f.entries {
		if other != name && EnvKey(other) == EnvKey(name) {
			return fmt.Errorf("%w: %q and %q both map to %s", ErrInvalidName, name, other, EnvKey(name))
		}
	}
	f.entries[name] = dotenvRecord{entry: e, value: append([]byte(nil), value...)}
	return d.save(f)
}

func (d *Dotenv) Get(_ context.Context, name string) ([]byte, Metadata, error) {
	if err := ValidateName(name); err != nil {
		return nil, Metadata{}, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	f, err := d.load()
	if err != nil {
		return nil, Metadata{}, err
	}
	r, ok := f.entries[name]
	if !ok {
		return nil, Metadata{}, ErrNotFound
	}
	return r.value, r.entry.Meta, nil
}

func (d *Dotenv) Delete(_ context.Context, name string) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	f, err := d.load()
	if err != nil {
		return err
	}
	if _, ok := f.entries[name]; !ok {
		return ErrNotFound
	}
	delete(f.entries, name)
	return d.save(f)
}

func (d *Dotenv) List(context.Context) ([]Metadata, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	f, err := d.load()
	if err != nil {
		return nil, err
	}
	out := make([]Metadata, 0, len(f.entries))
	for _, r := range f.entries {
		out = append(out, r.entry.Meta)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Name < out[b].Name })
	return out, nil
}
