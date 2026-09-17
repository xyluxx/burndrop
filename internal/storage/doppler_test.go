package storage

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
)

// dopplerFake simulates the Doppler CLI commands the backend uses with an
// in-memory config. "secrets set KEY" reads the value from stdin line by
// line as the CLI does, "secrets get --json" prints the map of name to
// {raw, computed, ...}, "secrets --only-names --json" prints a map of names
// to empty objects and "me --json" prints the actor info.
type dopplerFake struct {
	t        *testing.T
	mu       sync.Mutex
	loggedIn bool
	secrets  map[string]string
	project  string // when set, every secrets command must carry --project and --config
	config   string
}

var dopplerFakeName = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)

func newDopplerFake(t *testing.T) *dopplerFake {
	return &dopplerFake{t: t, loggedIn: true, secrets: map[string]string{}}
}

func (f *dopplerFake) keys() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	keys := make([]string, 0, len(f.secrets))
	for k := range f.secrets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// dopplerFakeArgs splits args into positionals and flags; flags in the
// valued set consume the next argument.
func dopplerFakeArgs(args []string) ([]string, map[string]string) {
	valued := map[string]bool{"project": true, "config": true, "token": true, "scope": true, "configuration": true, "config-dir": true, "api-host": true, "dashboard-host": true, "timeout": true, "attempts": true, "visibility": true}
	short := map[string]string{"-p": "project", "-c": "config", "-t": "token"}
	var pos []string
	flags := map[string]string{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "-y" {
			flags["yes"] = "true"
			continue
		}
		if name, ok := short[a]; ok && i+1 < len(args) {
			flags[name] = args[i+1]
			i++
			continue
		}
		if !strings.HasPrefix(a, "--") {
			pos = append(pos, a)
			continue
		}
		name, val, hasEq := strings.Cut(strings.TrimPrefix(a, "--"), "=")
		switch {
		case hasEq:
			flags[name] = val
		case valued[name] && i+1 < len(args):
			flags[name] = args[i+1]
			i++
		default:
			flags[name] = "true"
		}
	}
	return pos, flags
}

func (f *dopplerFake) handle(call fakeCall) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if call.Name != "doppler" {
		return nil, exitError(call.Name, 127, "fake doppler: unexpected command "+call.Name)
	}
	pos, flags := dopplerFakeArgs(call.Args)
	if flags["no-check-version"] == "" {
		f.t.Errorf("doppler invoked without --no-check-version: %v", call.Args)
	}
	if !f.loggedIn {
		return nil, exitError("doppler", 1, "Doppler Error: you must provide a token")
	}
	if len(pos) == 0 {
		return nil, exitError("doppler", 1, "fake doppler: no command")
	}
	switch pos[0] {
	case "me":
		if flags["project"] != "" || flags["config"] != "" {
			return nil, exitError("doppler", 1, "Error: unknown flag: --project")
		}
		if flags["json"] == "" {
			return []byte("NAME      TYPE      WORKPLACE\nJane Doe  personal  Acme (acme)\n"), nil
		}
		return []byte(`{"workplace":{"name":"Acme","slug":"acme"},"type":"personal","token_preview":"dp.pt.abcd...","slug":"jane-doe","created_at":"2026-01-01T00:00:00.000Z","name":"Jane Doe","last_seen_at":"2026-09-17T09:00:00.000Z"}` + "\n"), nil
	case "secrets":
		if f.project != "" && (flags["project"] != f.project || flags["config"] != f.config) {
			f.t.Errorf("secrets command without the project and config flags: %v", call.Args)
		}
		if len(pos) == 1 {
			return f.list(flags)
		}
		switch pos[1] {
		case "get":
			return f.get(pos[2:], flags)
		case "set":
			return f.set(pos[2:], flags, call.Stdin)
		case "delete":
			return f.remove(pos[2:], flags)
		}
	}
	return nil, exitError("doppler", 1, "fake doppler does not implement: "+strings.Join(call.Args, " "))
}

func (f *dopplerFake) sorted() []string {
	keys := make([]string, 0, len(f.secrets))
	for k := range f.secrets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func (f *dopplerFake) entry(name string) map[string]any {
	v := f.secrets[name]
	return map[string]any{
		"raw": v, "computed": v, "note": "", "rawVisibility": "masked", "computedVisibility": "masked",
		"rawValueType": map[string]string{"type": "string"}, "computedValueType": map[string]string{"type": "string"},
	}
}

func (f *dopplerFake) list(flags map[string]string) ([]byte, error) {
	switch {
	case flags["only-names"] != "" && flags["json"] != "":
		out := map[string]map[string]string{}
		for _, k := range f.sorted() {
			out[k] = map[string]string{}
		}
		b, _ := json.Marshal(out)
		return append(b, '\n'), nil
	case flags["json"] != "":
		out := map[string]any{}
		for _, k := range f.sorted() {
			out[k] = f.entry(k)
		}
		b, _ := json.Marshal(out)
		return append(b, '\n'), nil
	}
	var sb strings.Builder
	sb.WriteString("NAME\tVALUE\n")
	for _, k := range f.sorted() {
		sb.WriteString(k + "\t" + f.secrets[k] + "\n")
	}
	return []byte(sb.String()), nil
}

func (f *dopplerFake) get(names []string, flags map[string]string) ([]byte, error) {
	var missing []string
	for _, n := range names {
		if _, ok := f.secrets[n]; !ok {
			missing = append(missing, n)
		}
	}
	if len(missing) > 0 && flags["no-exit-on-missing-secret"] == "" {
		word := "secret"
		if len(missing) > 1 {
			word = "secrets"
		}
		return nil, exitError("doppler", 1, "Doppler Error: Could not find requested "+word+": "+strings.Join(missing, ", "))
	}
	switch {
	case flags["json"] != "":
		out := map[string]any{}
		for _, n := range names {
			if _, ok := f.secrets[n]; ok {
				out[n] = f.entry(n)
			}
		}
		b, _ := json.Marshal(out)
		return append(b, '\n'), nil
	case flags["plain"] != "":
		var vals []string
		for _, n := range names {
			vals = append(vals, f.secrets[n])
		}
		return []byte(strings.Join(vals, "\n") + "\n"), nil
	}
	var sb strings.Builder
	sb.WriteString("NAME\tVALUE\n")
	for _, n := range names {
		sb.WriteString(n + "\t" + f.secrets[n] + "\n")
	}
	return []byte(sb.String()), nil
}

// set implements the three argument forms of the CLI. Only the single KEY
// form reads the value from stdin; the others carry it in argv.
func (f *dopplerFake) set(args []string, flags map[string]string, stdin []byte) ([]byte, error) {
	changes := map[string]string{}
	switch {
	case len(args) == 1 && !strings.Contains(args[0], "="):
		if len(stdin) == 0 {
			if flags["no-interactive"] != "" {
				return nil, exitError("doppler", 1, "Doppler Error: Secret value must be provided when using --no-interactive")
			}
			return nil, exitError("doppler", 1, "fake doppler: interactive input is not supported")
		}
		var lines []string
		sc := bufio.NewScanner(bytes.NewReader(stdin))
		for sc.Scan() {
			lines = append(lines, sc.Text())
		}
		if err := sc.Err(); err != nil {
			return nil, exitError("doppler", 1, "Doppler Error: Unable to read input from stdin\n"+err.Error())
		}
		changes[args[0]] = strings.Join(lines, "\n")
	case len(args) == 2 && !strings.Contains(args[0], "="):
		changes[args[0]] = args[1]
	default:
		for _, a := range args {
			k, v, _ := strings.Cut(a, "=")
			changes[k] = v
		}
	}
	for k, v := range changes {
		if !dopplerFakeName.MatchString(k) || len(k) > 200 {
			return nil, exitError("doppler", 1, "Doppler Error: Unable to set secrets\nInvalid secret name: "+k)
		}
		if len(v) > 50*1024 {
			return nil, exitError("doppler", 1, "Doppler Error: Unable to set secrets\nSecret value exceeds the maximum size of 50 KiB")
		}
	}
	for k, v := range changes {
		f.secrets[k] = v
	}
	if flags["silent"] != "" {
		return nil, nil
	}
	var sb strings.Builder
	sb.WriteString("NAME\tVALUE\n")
	for k := range changes {
		sb.WriteString(k + "\t" + f.secrets[k] + "\n")
	}
	return []byte(sb.String()), nil
}

func (f *dopplerFake) remove(names []string, flags map[string]string) ([]byte, error) {
	if flags["yes"] == "" {
		return nil, exitError("doppler", 1, "fake doppler: the confirmation prompt is not supported")
	}
	for _, n := range names {
		delete(f.secrets, n)
	}
	if flags["silent"] != "" {
		return nil, nil
	}
	return f.list(map[string]string{})
}

func TestDopplerBackend(t *testing.T) {
	type env struct {
		fake   *dopplerFake
		runner *fakeRunner
		b      *Doppler
	}
	newEnv := func(t *testing.T, opts DopplerOptions) env {
		f := newDopplerFake(t)
		r := newFakeRunner(f.handle)
		opts.Runner = r
		return env{fake: f, runner: r, b: NewDoppler(opts)}
	}
	ctx := context.Background()
	meta := Metadata{Retention: RetentionUntilRevoked, Purpose: "test", Source: SourceDrop}
	value := []byte("sk-live-doppler-secret")

	runBackendSuite(t, func(t *testing.T) Backend { return newEnv(t, DopplerOptions{}).b }, DopplerMaxValueBytes)

	t.Run("value travels on stdin", func(t *testing.T) {
		e := newEnv(t, DopplerOptions{})
		if err := e.b.Put(ctx, "api-key", value, meta); err != nil {
			t.Fatal(err)
		}
		if v, m, err := e.b.Get(ctx, "api-key"); err != nil || !bytes.Equal(v, value) || m.Name != "api-key" {
			t.Fatalf("get: %v %q", err, v)
		}
		e.runner.assertNoSecretInArgs(t, value)
		b64 := []byte(base64.StdEncoding.EncodeToString(value))
		var set, get int
		for _, c := range e.runner.Calls() {
			if len(c.Args) < 3 || c.Args[0] != "secrets" {
				continue
			}
			switch c.Args[1] {
			case "set":
				set++
				if c.Args[2] != "BURNDROP_API_KEY" || !slices.Contains(c.Args, "--no-interactive") {
					t.Fatalf("set must name the key alone and refuse to prompt: %v", c.Args)
				}
				if !bytes.Contains(c.Stdin, b64) || bytes.ContainsRune(c.Stdin, '\n') {
					t.Fatalf("set must receive the record on stdin as a single line")
				}
			case "get":
				get++
				if !slices.Contains(c.Args, "--json") {
					t.Fatalf("get must ask for JSON: %v", c.Args)
				}
			}
		}
		if set != 1 || get < 1 {
			t.Fatalf("want one set and at least one get, got %d and %d", set, get)
		}
		if keys := e.fake.keys(); len(keys) != 1 || keys[0] != "BURNDROP_API_KEY" {
			t.Fatalf("stored keys: %v", keys)
		}
	})

	t.Run("binary missing", func(t *testing.T) {
		e := newEnv(t, DopplerOptions{})
		e.runner.setMissing("doppler", true)
		if p := e.b.Probe(ctx); p.Available || !strings.Contains(p.Reason, "install") {
			t.Fatalf("probe: %+v", p)
		}
	})

	t.Run("not authenticated", func(t *testing.T) {
		e := newEnv(t, DopplerOptions{})
		e.fake.loggedIn = false
		if p := e.b.Probe(ctx); p.Available || !strings.Contains(p.Reason, "doppler login") {
			t.Fatalf("probe: %+v", p)
		}
		if err := e.b.Put(ctx, "k", value, meta); !errors.Is(err, ErrPermission) {
			t.Fatalf("put: %v", err)
		}
		if _, _, err := e.b.Get(ctx, "k"); !errors.Is(err, ErrPermission) {
			t.Fatalf("get: %v", err)
		}
		if _, err := e.b.List(ctx); !errors.Is(err, ErrPermission) {
			t.Fatalf("list: %v", err)
		}
		e.runner.assertNoSecretInArgs(t, value)
		if err := dopplerClassify(exitError("doppler", 1, "Doppler Error: Unable to fetch secrets\nInvalid Auth token")); !errors.Is(err, ErrPermission) {
			t.Fatalf("api token mapping: %v", err)
		}
	})

	t.Run("not found", func(t *testing.T) {
		e := newEnv(t, DopplerOptions{})
		if _, _, err := e.b.Get(ctx, "missing"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("get: %v", err)
		}
		if err := e.b.Delete(ctx, "missing"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("delete: %v", err)
		}
		if err := dopplerClassify(exitError("doppler", 1, "Doppler Error: Could not find requested secrets: A, B")); !errors.Is(err, ErrNotFound) {
			t.Fatalf("mapping: %v", err)
		}
	})

	t.Run("project and config flags", func(t *testing.T) {
		e := newEnv(t, DopplerOptions{Project: "backend", Config: "prd"})
		e.fake.project, e.fake.config = "backend", "prd"
		if p := e.b.Probe(ctx); !p.Available || p.Rank != 86 || !strings.Contains(p.Reason, "Jane Doe") || !strings.Contains(p.Reason, "backend") {
			t.Fatalf("probe: %+v", p)
		}
		if err := e.b.Put(ctx, "db", value, meta); err != nil {
			t.Fatal(err)
		}
		if v, _, err := e.b.Get(ctx, "db"); err != nil || !bytes.Equal(v, value) {
			t.Fatalf("get: %v", err)
		}
		if list, err := e.b.List(ctx); err != nil || len(list) != 1 || list[0].Name != "db" {
			t.Fatalf("list: %v %+v", err, list)
		}
		if err := e.b.Delete(ctx, "db"); err != nil {
			t.Fatal(err)
		}
		for _, c := range e.runner.Calls() {
			_, flags := dopplerFakeArgs(c.Args)
			switch c.Args[0] {
			case "secrets":
				if flags["project"] != "backend" || flags["config"] != "prd" {
					t.Fatalf("scope flags missing: %v", c.Args)
				}
			case "me":
				if flags["project"] != "" {
					t.Fatalf("me does not take --project: %v", c.Args)
				}
			}
		}
	})

	t.Run("key collisions", func(t *testing.T) {
		e := newEnv(t, DopplerOptions{})
		if err := e.b.Put(ctx, "api-key", value, meta); err != nil {
			t.Fatal(err)
		}
		if err := e.b.Put(ctx, "api_key", []byte("other"), meta); !errors.Is(err, ErrInvalidName) {
			t.Fatalf("collision accepted: %v", err)
		}
		if _, _, err := e.b.Get(ctx, "api_key"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("get through a colliding name: %v", err)
		}
		if err := e.b.Delete(ctx, "api_key"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("delete through a colliding name: %v", err)
		}
		if v, _, err := e.b.Get(ctx, "api-key"); err != nil || !bytes.Equal(v, value) {
			t.Fatalf("original lost: %v", err)
		}
		if keys := e.fake.keys(); len(keys) != 1 {
			t.Fatalf("stored keys: %v", keys)
		}
	})

	t.Run("limits", func(t *testing.T) {
		e := newEnv(t, DopplerOptions{})
		if err := e.b.Put(ctx, "big", make([]byte, DopplerMaxValueBytes+1), meta); !errors.Is(err, ErrTooLarge) {
			t.Fatalf("over the value cap: %v", err)
		}
		long := meta
		long.Purpose = strings.Repeat("p", 30*1024)
		if err := e.b.Put(ctx, "verbose", make([]byte, 30*1024), long); !errors.Is(err, ErrTooLarge) {
			t.Fatalf("record over the 50 KiB cap: %v", err)
		}
		if len(e.runner.Calls()) != 0 {
			t.Fatal("oversized records must be refused before calling doppler")
		}
	})

	t.Run("list fetches only burndrop keys", func(t *testing.T) {
		e := newEnv(t, DopplerOptions{})
		e.fake.secrets["DATABASE_URL"] = "postgres://user:pw@host/db"
		e.fake.secrets["BURNDROP_FOREIGN"] = "hello"
		for _, n := range []string{"b", "a"} {
			if err := e.b.Put(ctx, n, []byte(n), meta); err != nil {
				t.Fatal(err)
			}
		}
		list, err := e.b.List(ctx)
		if err != nil || len(list) != 2 || list[0].Name != "a" || list[1].Name != "b" {
			t.Fatalf("list: %v %+v", err, list)
		}
		calls := e.runner.Calls()
		names, get := calls[len(calls)-2], calls[len(calls)-1]
		if !slices.Contains(names.Args, "--only-names") || !slices.Contains(names.Args, "--json") {
			t.Fatalf("list must start with the names call: %v", names.Args)
		}
		if get.Args[1] != "get" || slices.Contains(get.Args, "DATABASE_URL") || !slices.Contains(get.Args, "BURNDROP_A") {
			t.Fatalf("list must fetch only burndrop keys: %v", get.Args)
		}
		if _, _, err := e.b.Get(ctx, "foreign"); err == nil || errors.Is(err, ErrNotFound) {
			t.Fatalf("foreign value decoded: %v", err)
		}
		if err := e.b.Put(ctx, "foreign", value, meta); err == nil || !strings.Contains(err.Error(), "not a burndrop record") {
			t.Fatalf("foreign value overwritten: %v", err)
		}
	})
}
