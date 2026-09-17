package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// The Doppler backend drives the Doppler CLI. It was written against
// doppler 3.76.5 (August 2026), https://docs.doppler.com/docs/cli,
// https://docs.doppler.com/docs/platform-limits and the command sources in
// github.com/DopplerHQ/cli (pkg/cmd/secrets.go, pkg/cmd/me.go and
// pkg/printer/enclave.go).
//
// "doppler secrets set KEY" with data on standard input reads the value from
// stdin (the CLI documents `echo "value" | doppler secrets set KEY`), so the
// record never appears in an argument. "doppler secrets get KEY --json"
// returns the raw value; a missing key fails with "Could not find requested
// secret", which maps to ErrNotFound.

// DopplerOptions configures the Doppler backend.
type DopplerOptions struct {
	// Project and Config are passed as --project and --config. Empty relies
	// on the "doppler setup" configuration for the working directory or on
	// DOPPLER_PROJECT and DOPPLER_CONFIG in the environment.
	Project string
	Config  string
	// Runner executes doppler. Nil means ExecRunner{}.
	Runner Runner
}

// DopplerMaxValueBytes is the largest value the backend accepts. Doppler
// caps a secret value at 50 KiB and the record adds base64 and metadata
// overhead on top of the value.
const DopplerMaxValueBytes = 36 * 1024

const (
	dopplerKeyPrefix  = "BURNDROP_"
	dopplerValueLimit = 50 * 1024 // bytes per secret value, from the platform limits page
)

// Doppler stores each secret under the key "BURNDROP_<NAME>" (the name
// upper-cased, other characters replaced by underscores, as EnvKey does)
// with the JSON record as the value. Doppler names allow only upper-case
// letters, digits and underscores. The record keeps the original name, and
// reads refuse a record whose name differs from the one requested.
type Doppler struct {
	opts DopplerOptions
	mu   sync.Mutex // serializes writers so a collision check and its write are not interleaved
}

// NewDoppler returns a backend using opts.
func NewDoppler(opts DopplerOptions) *Doppler {
	if opts.Runner == nil {
		opts.Runner = ExecRunner{}
	}
	return &Doppler{opts: opts}
}

func (d *Doppler) Name() string { return "doppler" }

// dopplerKey maps a secret name to its Doppler secret name.
func dopplerKey(name string) string { return dopplerKeyPrefix + EnvKey(name) }

// run executes doppler. Commands under "doppler secrets" get the project
// and config flags; "doppler me" does not accept them.
func (d *Doppler) run(ctx context.Context, stdin []byte, scoped bool, args ...string) ([]byte, error) {
	if scoped {
		if d.opts.Project != "" {
			args = append(args, "--project", d.opts.Project)
		}
		if d.opts.Config != "" {
			args = append(args, "--config", d.opts.Config)
		}
	}
	args = append(args, "--no-check-version")
	return d.opts.Runner.Run(ctx, "doppler", args, stdin, nil)
}

func (d *Doppler) Probe(ctx context.Context) Probe {
	if _, err := d.opts.Runner.LookPath("doppler"); err != nil {
		return Probe{Reason: "Doppler CLI (doppler) is not installed; install it from https://docs.doppler.com/docs/install-cli and run doppler login"}
	}
	out, err := d.run(ctx, nil, false, "me", "--json")
	if err != nil {
		return Probe{Reason: "doppler is installed but not authenticated (" + dopplerErrText(err) + "); run doppler login or set DOPPLER_TOKEN"}
	}
	var me struct {
		Name      string `json:"name"`
		Type      string `json:"type"`
		Workplace struct {
			Name string `json:"name"`
		} `json:"workplace"`
	}
	_ = json.Unmarshal(out, &me)
	reason := "authenticated"
	if me.Name != "" {
		reason += " as " + me.Name
	}
	if me.Type != "" {
		reason += " (" + me.Type + ")"
	}
	if me.Workplace.Name != "" {
		reason += " in workplace " + me.Workplace.Name
	}
	if d.opts.Project != "" {
		reason += ", project " + d.opts.Project
	}
	if d.opts.Config != "" {
		reason += ", config " + d.opts.Config
	}
	return Probe{Available: true, Reason: reason, Rank: 92}
}

// fetch reads the raw values of keys with one "doppler secrets get". A key
// that does not exist makes the whole call fail with ErrNotFound.
func (d *Doppler) fetch(ctx context.Context, keys ...string) (map[string][]byte, error) {
	args := append([]string{"secrets", "get"}, keys...)
	out, err := d.run(ctx, nil, true, append(args, "--json")...)
	if err != nil {
		return nil, dopplerClassify(err)
	}
	defer Zero(out)
	var parsed map[string]struct {
		Raw *string `json:"raw"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		return nil, fmt.Errorf("storage: doppler: unexpected output from doppler secrets get: %w", err)
	}
	values := make(map[string][]byte, len(parsed))
	for k, v := range parsed {
		if v.Raw != nil {
			values[k] = []byte(*v.Raw)
		}
	}
	return values, nil
}

// lookup returns the raw record under key, or ErrNotFound.
func (d *Doppler) lookup(ctx context.Context, key string) ([]byte, error) {
	values, err := d.fetch(ctx, key)
	if err != nil {
		return nil, err
	}
	raw, ok := values[key]
	if !ok {
		return nil, fmt.Errorf("%w: %s has no readable value for this token (restricted visibility)", ErrPermission, key)
	}
	return raw, nil
}

func dopplerNotRecord(key string) error {
	return fmt.Errorf("storage: doppler: %s holds a value that is not a burndrop record; remove it or choose another name", key)
}

func (d *Doppler) Put(ctx context.Context, name string, value []byte, meta Metadata) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	if len(value) > DopplerMaxValueBytes {
		return fmt.Errorf("%w: doppler secrets hold at most %d bytes per value", ErrTooLarge, DopplerMaxValueBytes)
	}
	meta.Name = name
	meta.Backend = d.Name()
	meta.SizeBytes = len(value)
	rec, err := encodeRecord(meta, value)
	if err != nil {
		return err
	}
	defer Zero(rec)
	if len(rec) > dopplerValueLimit {
		return fmt.Errorf("%w: the record is %d bytes and Doppler allows %d per secret value", ErrTooLarge, len(rec), dopplerValueLimit)
	}
	key := dopplerKey(name)
	d.mu.Lock()
	defer d.mu.Unlock()
	raw, err := d.lookup(ctx, key)
	switch {
	case errors.Is(err, ErrNotFound):
	case err != nil:
		return err
	default:
		v, other, derr := decodeRecord(raw)
		Zero(v)
		Zero(raw)
		if derr != nil {
			return dopplerNotRecord(key)
		}
		if other.Name != name {
			return fmt.Errorf("%w: %q and %q both map to %s", ErrInvalidName, name, other.Name, key)
		}
	}
	_, err = d.run(ctx, rec, true, "secrets", "set", key, "--no-interactive", "--silent")
	return dopplerClassify(err)
}

func (d *Doppler) Get(ctx context.Context, name string) ([]byte, Metadata, error) {
	if err := ValidateName(name); err != nil {
		return nil, Metadata{}, err
	}
	key := dopplerKey(name)
	raw, err := d.lookup(ctx, key)
	if err != nil {
		return nil, Metadata{}, err
	}
	value, meta, err := decodeRecord(raw)
	Zero(raw)
	if err != nil {
		return nil, Metadata{}, dopplerNotRecord(key)
	}
	if meta.Name != name {
		Zero(value)
		return nil, Metadata{}, fmt.Errorf("%w: %s holds the record of %q, not %q", ErrNotFound, key, meta.Name, name)
	}
	return value, meta, nil
}

func (d *Doppler) Delete(ctx context.Context, name string) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	key := dopplerKey(name)
	d.mu.Lock()
	defer d.mu.Unlock()
	raw, err := d.lookup(ctx, key)
	if err != nil {
		return err
	}
	v, meta, err := decodeRecord(raw)
	Zero(v)
	Zero(raw)
	if err != nil {
		return dopplerNotRecord(key)
	}
	if meta.Name != name {
		return fmt.Errorf("%w: %s holds the record of %q, not %q", ErrNotFound, key, meta.Name, name)
	}
	_, err = d.run(ctx, nil, true, "secrets", "delete", key, "--yes", "--silent")
	return dopplerClassify(err)
}

// List reads the secret names (no values), then fetches only the BURNDROP_
// keys and decodes each record for its metadata. Values are decoded in
// memory and discarded.
func (d *Doppler) List(ctx context.Context) ([]Metadata, error) {
	out, err := d.run(ctx, nil, true, "secrets", "--only-names", "--json")
	if err != nil {
		return nil, dopplerClassify(err)
	}
	var names map[string]json.RawMessage
	if err := json.Unmarshal(out, &names); err != nil {
		return nil, fmt.Errorf("storage: doppler: unexpected output from doppler secrets --only-names: %w", err)
	}
	keys := make([]string, 0, len(names))
	for k := range names {
		if strings.HasPrefix(k, dopplerKeyPrefix) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	list := make([]Metadata, 0, len(keys))
	if len(keys) == 0 {
		return list, nil
	}
	values, err := d.fetch(ctx, keys...)
	if err != nil {
		return nil, err
	}
	for _, k := range keys {
		raw, ok := values[k]
		if !ok {
			continue
		}
		value, meta, err := decodeRecord(raw)
		Zero(value)
		Zero(raw)
		if err != nil || dopplerKey(meta.Name) != k {
			continue // not a burndrop record; leave it alone
		}
		list = append(list, meta)
	}
	sort.Slice(list, func(a, b int) bool { return list[a].Name < list[b].Name })
	return list, nil
}

// dopplerClassify maps CLI failures onto the storage errors. The CLI prints
// "Doppler Error: Could not find requested secret: KEY" for a missing key,
// "you must provide a token" without a login and the API's "Invalid Auth
// token" for a bad one.
func dopplerClassify(err error) error {
	if err == nil {
		return nil
	}
	var exit *ExitError
	if errors.As(err, &exit) {
		low := strings.ToLower(exit.Stderr)
		for _, hint := range []string{"invalid auth token", "invalid token", "you must provide a token", "not authorized", "unauthorized", "unauthenticated", "unable to authenticate", "invalid credentials"} {
			if strings.Contains(low, hint) {
				return fmt.Errorf("%w: %v", ErrPermission, err)
			}
		}
	}
	return classifyExit(err, "could not find requested secret")
}

// dopplerErrText returns the first line of the CLI's message without the
// "Doppler Error:" prefix, truncated.
func dopplerErrText(err error) string {
	var exit *ExitError
	if !errors.As(err, &exit) || exit.Stderr == "" {
		return shortErr(err)
	}
	s := strings.TrimSpace(strings.TrimPrefix(exit.Stderr, "Doppler Error:"))
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return shortErr(errors.New(s))
}
