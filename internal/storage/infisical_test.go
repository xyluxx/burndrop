package storage

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"unicode"
)

// infisicalFake simulates the Infisical CLI commands the backend uses with
// an in-memory secret map. It reads KEY=@path values from disk the way the
// CLI does, prints masked tables for set, plain values for get --plain
// (nothing for a missing key) and the export JSON array shape.
type infisicalFake struct {
	t        *testing.T
	mu       sync.Mutex
	loggedIn bool
	secrets  map[string]string
	want     map[string]string // scope flags every call must carry
	reads    []infisicalFakeRead
}

type infisicalFakeRead struct {
	path    string
	content []byte
}

func newInfisicalFake(t *testing.T) *infisicalFake {
	return &infisicalFake{t: t, loggedIn: true, secrets: map[string]string{}, want: map[string]string{}}
}

func (f *infisicalFake) fileReads() []infisicalFakeRead {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]infisicalFakeRead(nil), f.reads...)
}

func (f *infisicalFake) keys() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	keys := make([]string, 0, len(f.secrets))
	for k := range f.secrets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// infisicalFakeArgs splits args into positionals and flags; flags in the
// valued set consume the next argument.
func infisicalFakeArgs(args []string) ([]string, map[string]string) {
	valued := map[string]bool{"env": true, "projectId": true, "path": true, "token": true, "format": true, "type": true, "file": true, "tag": true, "tags": true, "domain": true, "output-file": true, "template": true, "log-level": true}
	var pos []string
	flags := map[string]string{}
	for i := 0; i < len(args); i++ {
		a := args[i]
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

func (f *infisicalFake) handle(call fakeCall) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if call.Name != "infisical" {
		return nil, exitError(call.Name, 127, "fake infisical: unexpected command "+call.Name)
	}
	pos, flags := infisicalFakeArgs(call.Args)
	if !slices.Contains(call.Env, "INFISICAL_DISABLE_UPDATE_CHECK=true") {
		f.t.Errorf("update check not disabled: %v", call.Env)
	}
	if flags["silent"] == "" {
		f.t.Errorf("infisical invoked without --silent: %v", call.Args)
	}
	for k, v := range f.want {
		if flags[k] != v {
			f.t.Errorf("infisical %v: flag --%s=%q, want %q", pos, k, flags[k], v)
		}
	}
	if !f.loggedIn {
		return nil, exitError("infisical", 1, "You must be logged in to run this command. To login, run [infisical login]")
	}
	switch {
	case len(pos) == 3 && pos[0] == "secrets" && pos[1] == "folders" && pos[2] == "get":
		return []byte("FOLDER NAME\n"), nil
	case len(pos) >= 2 && pos[0] == "secrets" && pos[1] == "set":
		return f.set(pos[2:])
	case len(pos) >= 2 && pos[0] == "secrets" && pos[1] == "get":
		return f.get(pos[2:], flags)
	case len(pos) >= 2 && pos[0] == "secrets" && pos[1] == "delete":
		return f.remove(pos[2:])
	case len(pos) == 1 && pos[0] == "export":
		return f.export(flags)
	}
	return nil, exitError("infisical", 1, "fake infisical does not implement: "+strings.Join(call.Args, " "))
}

func (f *infisicalFake) set(kvs []string) ([]byte, error) {
	if len(kvs) == 0 {
		return nil, exitError("infisical", 1, "error: at least one secret must be provided")
	}
	rows := []string{"SECRET NAME\tSECRET VALUE\tSTATUS"}
	for _, kv := range kvs {
		key, value, ok := strings.Cut(kv, "=")
		if !ok {
			return nil, exitError("infisical", 1, "error: invalid argument "+kv+", expected key=value")
		}
		switch {
		case strings.HasPrefix(value, `\@`):
			value = "@" + value[2:]
		case strings.HasPrefix(value, "@"):
			path := strings.TrimPrefix(value, "@")
			info, err := os.Stat(path)
			if err != nil {
				return nil, exitError("infisical", 1, "error: Unable to read file "+path+": "+err.Error())
			}
			if !isWindows() && info.Mode().Perm() != 0o600 {
				f.t.Errorf("temporary file %s has mode %v, want 0600", path, info.Mode().Perm())
			}
			content, err := os.ReadFile(path)
			if err != nil {
				return nil, exitError("infisical", 1, "error: Unable to read file "+path+": "+err.Error())
			}
			f.reads = append(f.reads, infisicalFakeRead{path: path, content: content})
			value = string(content)
		}
		if key == "" || unicode.IsDigit(rune(key[0])) {
			return nil, exitError("infisical", 1, fmt.Sprintf("error: secret key '%s' cannot start with a number", key))
		}
		if strings.Contains(key, " ") {
			return nil, exitError("infisical", 1, fmt.Sprintf("error: secret key '%s' cannot contain spaces", key))
		}
		status := "SECRET CREATED"
		if _, exists := f.secrets[key]; exists {
			status = "SECRET UPDATED"
		}
		f.secrets[key] = value
		rows = append(rows, key+"\t******\t"+status)
	}
	return []byte(strings.Join(rows, "\n") + "\n"), nil
}

// get prints values one per line with --plain, skipping missing keys; the
// table form shows "*not found*" instead.
func (f *infisicalFake) get(keys []string, flags map[string]string) ([]byte, error) {
	plain := flags["plain"] != ""
	var sb strings.Builder
	if !plain {
		sb.WriteString("SECRET NAME\tSECRET VALUE\tSECRET TYPE\n")
	}
	for _, k := range keys {
		v, ok := f.secrets[k]
		switch {
		case ok && plain:
			sb.WriteString(v + "\n")
		case ok:
			sb.WriteString(k + "\t" + v + "\tshared\n")
		case !plain:
			sb.WriteString(k + "\t*not found*\t*not found*\n")
		}
	}
	return []byte(sb.String()), nil
}

func (f *infisicalFake) remove(keys []string) ([]byte, error) {
	for _, k := range keys {
		if _, ok := f.secrets[k]; !ok {
			return nil, exitError("infisical", 1, "error: unable to process the delete request: secret with name '"+k+"' not found")
		}
		delete(f.secrets, k)
	}
	return nil, nil // the success line goes to stderr in the real CLI
}

// export prints the JSON array of SingleEnvironmentVariable objects.
func (f *infisicalFake) export(flags map[string]string) ([]byte, error) {
	if flags["format"] != "json" {
		return nil, exitError("infisical", 1, "fake infisical export supports --format=json only")
	}
	keys := make([]string, 0, len(f.secrets))
	for k := range f.secrets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := []map[string]any{}
	for i, k := range keys {
		out = append(out, map[string]any{
			"key": k, "workspace": "ws-1", "value": f.secrets[k], "type": "shared", "_id": fmt.Sprintf("id-%d", i),
			"secretPath": "/", "tags": []any{}, "comment": "", "Etag": "", "skipMultilineEncoding": false,
		})
	}
	b, _ := json.Marshal(out)
	return b, nil
}

func TestInfisicalBackend(t *testing.T) {
	type env struct {
		fake   *infisicalFake
		runner *fakeRunner
		b      *Infisical
	}
	newEnv := func(t *testing.T, opts InfisicalOptions) env {
		f := newInfisicalFake(t)
		r := newFakeRunner(f.handle)
		opts.Runner = r
		return env{fake: f, runner: r, b: NewInfisical(opts)}
	}
	ctx := context.Background()
	meta := Metadata{Retention: RetentionUntilRevoked, Purpose: "test", Source: SourceDrop}
	value := []byte("sk-live-infisical-secret")

	runBackendSuite(t, func(t *testing.T) Backend { return newEnv(t, InfisicalOptions{}).b }, 0)

	t.Run("value travels through a temporary file", func(t *testing.T) {
		e := newEnv(t, InfisicalOptions{})
		if err := e.b.Put(ctx, "api-key", value, meta); err != nil {
			t.Fatal(err)
		}
		if v, m, err := e.b.Get(ctx, "api-key"); err != nil || !bytes.Equal(v, value) || m.Name != "api-key" {
			t.Fatalf("get: %v %q", err, v)
		}
		e.runner.assertNoSecretInArgs(t, value)
		var set, get *fakeCall
		for _, c := range e.runner.Calls() {
			c := c
			if len(c.Args) < 3 || c.Args[0] != "secrets" {
				continue
			}
			switch c.Args[1] {
			case "set":
				set = &c
			case "get":
				get = &c
			}
		}
		if set == nil || get == nil {
			t.Fatal("expected a set and a get call")
		}
		path, ok := strings.CutPrefix(set.Args[2], "BURNDROP_API_KEY=@")
		if !ok || path == "" {
			t.Fatalf("set must reference the value by file path: %v", set.Args)
		}
		if len(set.Stdin) != 0 {
			t.Fatal("set has no stdin mode; nothing should be written to it")
		}
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("temporary file left behind at %s: %v", path, err)
		}
		reads := e.fake.fileReads()
		b64 := []byte(base64.StdEncoding.EncodeToString(value))
		if len(reads) != 1 || reads[0].path != path || !bytes.Contains(reads[0].content, b64) {
			t.Fatalf("the CLI did not read the record from %s: %+v", path, reads)
		}
		for _, want := range []string{"--plain", "--expand=false", "--include-imports=false"} {
			if !slices.Contains(get.Args, want) {
				t.Fatalf("get lacks %s: %v", want, get.Args)
			}
		}
		if keys := e.fake.keys(); len(keys) != 1 || keys[0] != "BURNDROP_API_KEY" {
			t.Fatalf("stored keys: %v", keys)
		}
	})

	t.Run("binary missing", func(t *testing.T) {
		e := newEnv(t, InfisicalOptions{})
		e.runner.setMissing("infisical", true)
		if p := e.b.Probe(ctx); p.Available || !strings.Contains(p.Reason, "install") {
			t.Fatalf("probe: %+v", p)
		}
	})

	t.Run("not logged in", func(t *testing.T) {
		e := newEnv(t, InfisicalOptions{})
		e.fake.loggedIn = false
		if p := e.b.Probe(ctx); p.Available || !strings.Contains(p.Reason, "infisical login") {
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
	})

	t.Run("not found", func(t *testing.T) {
		e := newEnv(t, InfisicalOptions{})
		if _, _, err := e.b.Get(ctx, "missing"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("get: %v", err)
		}
		if err := e.b.Delete(ctx, "missing"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("delete: %v", err)
		}
		if err := infisicalClassify(exitError("infisical", 1, "error: unable to process the delete request: secret with name 'X' not found")); !errors.Is(err, ErrNotFound) {
			t.Fatalf("mapping: %v", err)
		}
	})

	t.Run("scope flags", func(t *testing.T) {
		e := newEnv(t, InfisicalOptions{ProjectID: "proj-1", Environment: "prod", Path: "/apps"})
		e.fake.want = map[string]string{"env": "prod", "projectId": "proj-1", "path": "/apps"}
		if p := e.b.Probe(ctx); !p.Available || p.Rank != 86 || !strings.Contains(p.Reason, "proj-1") || !strings.Contains(p.Reason, "prod") {
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
	})

	t.Run("key collisions", func(t *testing.T) {
		e := newEnv(t, InfisicalOptions{})
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

	t.Run("foreign values", func(t *testing.T) {
		e := newEnv(t, InfisicalOptions{})
		e.fake.secrets["BURNDROP_FOREIGN"] = "hello"
		e.fake.secrets["DATABASE_URL"] = "postgres://x"
		if _, _, err := e.b.Get(ctx, "foreign"); err == nil || errors.Is(err, ErrNotFound) {
			t.Fatalf("foreign value decoded: %v", err)
		}
		if err := e.b.Put(ctx, "foreign", value, meta); err == nil || !strings.Contains(err.Error(), "not a burndrop record") {
			t.Fatalf("foreign value overwritten: %v", err)
		}
		if err := e.b.Put(ctx, "mine", value, meta); err != nil {
			t.Fatal(err)
		}
		list, err := e.b.List(ctx)
		if err != nil || len(list) != 1 || list[0].Name != "mine" {
			t.Fatalf("list: %v %+v", err, list)
		}
		e.runner.assertNoSecretInArgs(t, value)
	})
}
