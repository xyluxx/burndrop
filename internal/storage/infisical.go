package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
)

// The Infisical backend drives the Infisical CLI. It was written against
// infisical v0.43.132 (September 2026),
// https://infisical.com/docs/cli/commands/secrets,
// https://infisical.com/docs/cli/commands/export and the command sources in
// github.com/Infisical/cli (packages/cmd/secrets.go and export.go).
//
// "infisical secrets set" takes KEY=VALUE arguments only and has no stdin
// mode, but a value of the form @<path> makes the CLI read the value from
// that file. The record is therefore written to a temporary file with mode
// 0600 in os.TempDir() and removed as soon as the command returns; only the
// path reaches argv. "infisical secrets get --plain" prints the value; for
// a missing key it prints nothing and exits 0, which maps to ErrNotFound.

// InfisicalOptions configures the Infisical backend.
type InfisicalOptions struct {
	// ProjectID is passed as --projectId. Empty relies on the .infisical.json
	// written by "infisical init" in the working directory.
	ProjectID string
	// Environment is passed as --env (for example dev, staging, prod). Empty
	// uses the CLI default.
	Environment string
	// Path is the folder passed as --path. Empty uses the CLI default "/".
	Path string
	// Runner executes infisical. Nil means ExecRunner{}.
	Runner Runner
}

// Infisical stores each secret under the key "BURNDROP_<NAME>" (the name
// upper-cased, other characters replaced by underscores, as EnvKey does)
// with the JSON record as the value. The record keeps the original name,
// and reads refuse a record whose name differs from the one requested.
type Infisical struct {
	opts InfisicalOptions
	mu   sync.Mutex // serializes writers so a collision check and its write are not interleaved
}

// NewInfisical returns a backend using opts.
func NewInfisical(opts InfisicalOptions) *Infisical {
	if opts.Runner == nil {
		opts.Runner = ExecRunner{}
	}
	return &Infisical{opts: opts}
}

const infisicalKeyPrefix = "BURNDROP_"

func (i *Infisical) Name() string { return "infisical" }

// infisicalKey maps a secret name to its Infisical key.
func infisicalKey(name string) string { return infisicalKeyPrefix + EnvKey(name) }

// run executes infisical with the configured scope flags. Values are never
// in args; --silent keeps tips out of the output.
func (i *Infisical) run(ctx context.Context, args ...string) ([]byte, error) {
	if i.opts.Environment != "" {
		args = append(args, "--env", i.opts.Environment)
	}
	if i.opts.ProjectID != "" {
		args = append(args, "--projectId", i.opts.ProjectID)
	}
	if i.opts.Path != "" {
		args = append(args, "--path", i.opts.Path)
	}
	args = append(args, "--silent")
	return i.opts.Runner.Run(ctx, "infisical", args, nil, []string{"INFISICAL_DISABLE_UPDATE_CHECK=true"})
}

// scope describes the configured project, environment and path.
func (i *Infisical) scope() string {
	parts := []string{"the project in .infisical.json"}
	if i.opts.ProjectID != "" {
		parts[0] = "project " + i.opts.ProjectID
	}
	if i.opts.Environment != "" {
		parts = append(parts, "environment "+i.opts.Environment)
	} else {
		parts = append(parts, "the default environment")
	}
	if i.opts.Path != "" {
		parts = append(parts, "path "+i.opts.Path)
	}
	return strings.Join(parts, ", ")
}

func (i *Infisical) Probe(ctx context.Context) Probe {
	if _, err := i.opts.Runner.LookPath("infisical"); err != nil {
		return Probe{Reason: "Infisical CLI (infisical) is not installed; install it from https://infisical.com/docs/cli/overview and run infisical login"}
	}
	// Listing folders proves the login and the project scope without
	// reading any value.
	if _, err := i.run(ctx, "secrets", "folders", "get"); err != nil {
		return Probe{Reason: "infisical cannot read " + i.scope() + " (" + infisicalErrText(err) + "); run infisical login or set INFISICAL_TOKEN, and run infisical init or pass a project ID"}
	}
	return Probe{Available: true, Reason: "authenticated for " + i.scope(), Rank: 92}
}

// fetch reads the raw value stored under key. found is false when the key
// does not exist: the CLI prints nothing for it in plain mode.
func (i *Infisical) fetch(ctx context.Context, key string) (raw []byte, found bool, err error) {
	out, err := i.run(ctx, "secrets", "get", key, "--plain", "--expand=false", "--include-imports=false")
	if err != nil {
		return nil, false, infisicalClassify(err)
	}
	out = bytes.TrimRight(out, "\r\n")
	if len(out) == 0 {
		return nil, false, nil
	}
	return out, true, nil
}

func infisicalNotRecord(key string) error {
	return fmt.Errorf("storage: infisical: %s holds a value that is not a burndrop record; remove it or choose another name", key)
}

func (i *Infisical) Put(ctx context.Context, name string, value []byte, meta Metadata) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	meta.Name = name
	meta.Backend = i.Name()
	meta.SizeBytes = len(value)
	rec, err := encodeRecord(meta, value)
	if err != nil {
		return err
	}
	defer Zero(rec)
	key := infisicalKey(name)
	i.mu.Lock()
	defer i.mu.Unlock()
	raw, found, err := i.fetch(ctx, key)
	if err != nil {
		return err
	}
	if found {
		v, other, err := decodeRecord(raw)
		Zero(v)
		Zero(raw)
		if err != nil {
			return infisicalNotRecord(key)
		}
		if other.Name != name {
			return fmt.Errorf("%w: %q and %q both map to %s", ErrInvalidName, name, other.Name, key)
		}
	}
	path, err := infisicalTempFile(rec)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(path) }()
	_, err = i.run(ctx, "secrets", "set", key+"=@"+path)
	return infisicalClassify(err)
}

// infisicalTempFile writes rec to a new file in os.TempDir() that only the
// current user can read (os.CreateTemp uses mode 0600) and returns its path.
func infisicalTempFile(rec []byte) (string, error) {
	f, err := os.CreateTemp("", "burndrop-*.json")
	if err != nil {
		return "", fmt.Errorf("storage: infisical: temporary file: %w", err)
	}
	_, werr := f.Write(rec)
	cerr := f.Close()
	if werr != nil || cerr != nil {
		_ = os.Remove(f.Name())
		return "", fmt.Errorf("storage: infisical: temporary file: %w", errors.Join(werr, cerr))
	}
	return f.Name(), nil
}

func (i *Infisical) Get(ctx context.Context, name string) ([]byte, Metadata, error) {
	if err := ValidateName(name); err != nil {
		return nil, Metadata{}, err
	}
	key := infisicalKey(name)
	raw, found, err := i.fetch(ctx, key)
	if err != nil {
		return nil, Metadata{}, err
	}
	if !found {
		return nil, Metadata{}, ErrNotFound
	}
	value, meta, err := decodeRecord(raw)
	Zero(raw)
	if err != nil {
		return nil, Metadata{}, infisicalNotRecord(key)
	}
	if meta.Name != name {
		Zero(value)
		return nil, Metadata{}, fmt.Errorf("%w: %s holds the record of %q, not %q", ErrNotFound, key, meta.Name, name)
	}
	return value, meta, nil
}

func (i *Infisical) Delete(ctx context.Context, name string) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	key := infisicalKey(name)
	i.mu.Lock()
	defer i.mu.Unlock()
	raw, found, err := i.fetch(ctx, key)
	if err != nil {
		return err
	}
	if !found {
		return ErrNotFound
	}
	v, meta, err := decodeRecord(raw)
	Zero(v)
	Zero(raw)
	if err != nil {
		return infisicalNotRecord(key)
	}
	if meta.Name != name {
		return fmt.Errorf("%w: %s holds the record of %q, not %q", ErrNotFound, key, meta.Name, name)
	}
	_, err = i.run(ctx, "secrets", "delete", key)
	return infisicalClassify(err)
}

// List exports the scope as JSON and decodes each BURNDROP_ record for its
// metadata. Values are decoded in memory and discarded.
func (i *Infisical) List(ctx context.Context) ([]Metadata, error) {
	out, err := i.run(ctx, "export", "--format=json", "--expand=false", "--include-imports=false")
	if err != nil {
		return nil, infisicalClassify(err)
	}
	defer Zero(out)
	var envs []struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}
	if trimmed := bytes.TrimSpace(out); len(trimmed) > 0 {
		if err := json.Unmarshal(trimmed, &envs); err != nil {
			return nil, fmt.Errorf("storage: infisical: unexpected output from infisical export: %w", err)
		}
	}
	list := make([]Metadata, 0, len(envs))
	for _, e := range envs {
		if !strings.HasPrefix(e.Key, infisicalKeyPrefix) {
			continue
		}
		value, meta, err := decodeRecord([]byte(e.Value))
		Zero(value)
		if err != nil || infisicalKey(meta.Name) != e.Key {
			continue // not a burndrop record; leave it alone
		}
		list = append(list, meta)
	}
	sort.Slice(list, func(a, b int) bool { return list[a].Name < list[b].Name })
	return list, nil
}

// infisicalClassify maps CLI failures onto the storage errors. Without a
// login or token the CLI prints "You must be logged in to run this command.
// To login, run [infisical login]".
func infisicalClassify(err error) error {
	if err == nil {
		return nil
	}
	var exit *ExitError
	if errors.As(err, &exit) {
		low := strings.ToLower(exit.Stderr)
		for _, hint := range []string{"must be logged in", "not logged in", "unauthorized", "unauthenticated", "invalid token", "token expired", "expired token", "invalid access token", "forbidden"} {
			if strings.Contains(low, hint) {
				return fmt.Errorf("%w: %v", ErrPermission, err)
			}
		}
	}
	return classifyExit(err, "secret not found", "not found")
}

// infisicalErrText returns the first line of the CLI's message, truncated.
func infisicalErrText(err error) string {
	var exit *ExitError
	if !errors.As(err, &exit) || exit.Stderr == "" {
		return shortErr(err)
	}
	s := strings.TrimPrefix(exit.Stderr, "error: ")
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return shortErr(errors.New(s))
}
