package storage

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// gcpFake simulates the gcloud CLI: secrets create, versions add, versions
// access, describe, delete and list, plus auth list and config get-value.
// Errors follow gcloud's "ERROR: (gcloud.secrets.<cmd>) <STATUS>: ..." form
// on stderr with exit code 1; the raw payload comes back on stdout.
type gcpFake struct {
	mu       sync.Mutex
	signedIn bool
	project  string // the gcloud default project; "" means unset
	secrets  map[string]*gcpFakeSecret
}

type gcpFakeSecret struct {
	versions [][]byte
	labels   map[string]string
}

func newGCPFake() *gcpFake {
	return &gcpFake{signedIn: true, project: "my-project", secrets: map[string]*gcpFakeSecret{}}
}

// gcpParseArgs splits gcloud arguments into positionals and --flag=value
// pairs.
func gcpParseArgs(args []string) (pos []string, flags map[string]string) {
	flags = map[string]string{}
	for _, a := range args {
		switch {
		case !strings.HasPrefix(a, "--"):
			pos = append(pos, a)
		default:
			k, v, ok := strings.Cut(a, "=")
			if !ok {
				v = "true"
			}
			flags[k] = v
		}
	}
	return pos, flags
}

func (f *gcpFake) notFound(cmd, id string) error {
	return exitError("gcloud", 1, fmt.Sprintf("ERROR: (gcloud.secrets.%s) NOT_FOUND: Secret [projects/%s/secrets/%s] not found.", cmd, f.project, id))
}

func (f *gcpFake) resource(id string, s *gcpFakeSecret) map[string]any {
	return map[string]any{
		"createTime":  "2026-09-17T01:02:03.123456Z",
		"etag":        `"16a2b3c4d5e6f7"`,
		"labels":      s.labels,
		"name":        "projects/" + f.project + "/secrets/" + id,
		"replication": map[string]any{"automatic": map[string]any{}},
	}
}

func (f *gcpFake) handler(call fakeCall) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if call.Name != "gcloud" {
		return nil, fmt.Errorf("unexpected command %s", call.Name)
	}
	if len(call.Env) != 0 {
		return nil, fmt.Errorf("fake gcloud: unexpected environment %v", call.Env)
	}
	pos, flags := gcpParseArgs(call.Args)
	if len(pos) < 2 {
		return nil, errors.New("fake gcloud: missing command")
	}
	switch pos[0] + " " + pos[1] {
	case "auth list":
		if flags["--format"] != "json" {
			return nil, errors.New("fake gcloud: --format=json expected")
		}
		if !f.signedIn {
			return []byte("[]\n"), nil
		}
		return []byte(`[{"account": "dev@example.com", "status": "ACTIVE"}]` + "\n"), nil
	case "config get-value":
		if len(pos) < 3 || pos[2] != "project" {
			return nil, errors.New("fake gcloud: unknown property")
		}
		if f.project == "" {
			return []byte(""), nil
		}
		return []byte(f.project + "\n"), nil
	}
	if pos[0] != "secrets" {
		return nil, fmt.Errorf("fake gcloud: unknown command %v", pos)
	}
	cmd := pos[1]
	if !f.signedIn {
		return nil, exitError("gcloud", 1, "ERROR: (gcloud.secrets."+cmd+") You do not currently have an active account selected.\nPlease run:\n\n  $ gcloud auth login\n\nto obtain new credentials.")
	}
	if flags["--project"] == "" && f.project == "" {
		return nil, exitError("gcloud", 1, "ERROR: (gcloud.secrets."+cmd+") The required property [project] is not currently set.\nYou may set it for your current workspace by running:\n\n  $ gcloud config set project VALUE")
	}
	switch cmd {
	case "create":
		id := pos[2]
		if _, ok := f.secrets[id]; ok {
			return nil, exitError("gcloud", 1, fmt.Sprintf("ERROR: (gcloud.secrets.create) ALREADY_EXISTS: Secret [projects/%s/secrets/%s] already exists.", f.project, id))
		}
		if flags["--replication-policy"] != "automatic" {
			return nil, exitError("gcloud", 1, "ERROR: (gcloud.secrets.create) The replication policy must be set: use --replication-policy or the secrets/replication-policy property.")
		}
		if flags["--data-file"] != "-" {
			return nil, fmt.Errorf("fake gcloud: --data-file=- expected, got %q", flags["--data-file"])
		}
		if len(call.Stdin) > gcpMaxRecordBytes {
			return nil, exitError("gcloud", 1, "ERROR: (gcloud.secrets.create) INVALID_ARGUMENT: The secret payload must be at most 65536 bytes.")
		}
		labels := map[string]string{}
		for _, kv := range strings.Split(flags["--labels"], ",") {
			if k, v, ok := strings.Cut(kv, "="); ok {
				labels[k] = v
			}
		}
		f.secrets[id] = &gcpFakeSecret{versions: [][]byte{append([]byte(nil), call.Stdin...)}, labels: labels}
		return nil, nil
	case "versions":
		switch pos[2] {
		case "add":
			id := pos[3]
			s, ok := f.secrets[id]
			if !ok {
				return nil, f.notFound("versions.add", id)
			}
			if flags["--data-file"] != "-" {
				return nil, fmt.Errorf("fake gcloud: --data-file=- expected, got %q", flags["--data-file"])
			}
			if len(call.Stdin) > gcpMaxRecordBytes {
				return nil, exitError("gcloud", 1, "ERROR: (gcloud.secrets.versions.add) INVALID_ARGUMENT: The secret payload must be at most 65536 bytes.")
			}
			s.versions = append(s.versions, append([]byte(nil), call.Stdin...))
			return nil, nil
		case "access":
			id := flags["--secret"]
			s, ok := f.secrets[id]
			if !ok || pos[3] != "latest" {
				return nil, exitError("gcloud", 1, fmt.Sprintf("ERROR: (gcloud.secrets.versions.access) NOT_FOUND: Secret Version [projects/%s/secrets/%s/versions/%s] not found.", f.project, id, pos[3]))
			}
			return append([]byte(nil), s.versions[len(s.versions)-1]...), nil
		}
	case "describe":
		id := pos[2]
		s, ok := f.secrets[id]
		if !ok {
			return nil, f.notFound("describe", id)
		}
		return json.Marshal(f.resource(id, s))
	case "delete":
		id := pos[2]
		if flags["--quiet"] != "true" {
			return nil, errors.New("fake gcloud: delete would prompt without --quiet")
		}
		if _, ok := f.secrets[id]; !ok {
			return nil, f.notFound("delete", id)
		}
		delete(f.secrets, id)
		return nil, nil
	case "list":
		if flags["--format"] != "json" {
			return nil, errors.New("fake gcloud: --format=json expected")
		}
		key, want, _ := strings.Cut(strings.TrimPrefix(flags["--filter"], "labels."), "=")
		out := []map[string]any{}
		for id, s := range f.secrets {
			if s.labels[key] == want {
				out = append(out, f.resource(id, s))
			}
		}
		return json.Marshal(out)
	}
	return nil, fmt.Errorf("fake gcloud: unknown command %v", pos)
}

func TestGCPBackend(t *testing.T) {
	runBackendSuite(t, func(t *testing.T) Backend {
		return NewGCP(GCP{Runner: newFakeRunner(newGCPFake().handler)})
	}, gcpMaxValueBytes)

	ctx := context.Background()
	meta := Metadata{Retention: RetentionUntilRevoked, Purpose: "test"}

	t.Run("value only on stdin", func(t *testing.T) {
		fake := newGCPFake()
		runner := newFakeRunner(fake.handler)
		b := NewGCP(GCP{Runner: runner, Project: "other-project"})
		secret := []byte("sk-live-1234 with \x00 and \xff")
		if err := b.Put(ctx, "api-key", secret, meta); err != nil {
			t.Fatal(err)
		}
		if v, _, err := b.Get(ctx, "api-key"); err != nil || !bytes.Equal(v, secret) {
			t.Fatalf("get: %v", err)
		}
		runner.assertNoSecretInArgs(t, secret)
		runner.assertNoSecretInArgs(t, []byte(base64.StdEncoding.EncodeToString(secret)))
		var create *fakeCall
		for _, c := range runner.Calls() {
			c := c
			if c.Args[0] == "secrets" && !strings.Contains(strings.Join(c.Args, " "), "--project=other-project") {
				t.Fatalf("project flag missing: %v", c.Args)
			}
			if c.Args[1] == "create" {
				create = &c
			}
		}
		if create == nil || !bytes.Contains(create.Stdin, []byte(base64.StdEncoding.EncodeToString(secret))) {
			t.Fatalf("record did not travel on stdin: %+v", create)
		}
		if strings.Join(create.Args, " ") != "secrets create burndrop-api-key --data-file=- --replication-policy=automatic --labels=burndrop=1 --project=other-project" {
			t.Fatalf("create args: %v", create.Args)
		}
	})

	t.Run("overwrite adds a version", func(t *testing.T) {
		fake := newGCPFake()
		runner := newFakeRunner(fake.handler)
		b := NewGCP(GCP{Runner: runner})
		for _, v := range []string{"one", "two"} {
			if err := b.Put(ctx, "k", []byte(v), meta); err != nil {
				t.Fatal(err)
			}
		}
		var ops []string
		for _, c := range runner.Calls() {
			ops = append(ops, strings.Join(c.Args[1:3], " "))
		}
		if strings.Join(ops, ",") != "create burndrop-k,create burndrop-k,versions add" {
			t.Fatalf("operations: %v", ops)
		}
		if len(fake.secrets["burndrop-k"].versions) != 2 {
			t.Fatal("expected two versions")
		}
	})

	t.Run("name mapping", func(t *testing.T) {
		fake := newGCPFake()
		b := NewGCP(GCP{Runner: newFakeRunner(fake.handler)})
		for _, n := range []string{"prod.db_url", "prod-db_url", "plain_name-1"} {
			if err := b.Put(ctx, n, []byte(n), meta); err != nil {
				t.Fatal(err)
			}
		}
		if _, ok := fake.secrets["burndrop-plain_name-1"]; !ok {
			t.Fatalf("plain name rewritten: %v", fake.secrets)
		}
		if _, ok := fake.secrets["burndrop-prod-db_url"]; !ok {
			t.Fatalf("dash name rewritten: %v", fake.secrets)
		}
		mapped := regexp.MustCompile(`^burndrop-prod-db_url-[0-9a-f]{8}$`)
		found := 0
		for id := range fake.secrets {
			if mapped.MatchString(id) {
				found++
			}
		}
		if found != 1 {
			t.Fatalf("dotted name not mapped with a hash suffix: %v", fake.secrets)
		}
		for _, n := range []string{"prod.db_url", "prod-db_url"} {
			if v, m, err := b.Get(ctx, n); err != nil || string(v) != n || m.Name != n {
				t.Fatalf("%s: %v %q", n, err, v)
			}
		}
		list, err := b.List(ctx)
		if err != nil || len(list) != 3 || list[0].Name != "plain_name-1" || list[1].Name != "prod-db_url" || list[2].Name != "prod.db_url" {
			t.Fatalf("list: %+v %v", list, err)
		}
	})

	t.Run("binary missing", func(t *testing.T) {
		runner := newFakeRunner(newGCPFake().handler)
		runner.setMissing("gcloud", true)
		p := NewGCP(GCP{Runner: runner}).Probe(ctx)
		if p.Available || !strings.Contains(p.Reason, "install the Google Cloud CLI") {
			t.Fatalf("probe: %+v", p)
		}
	})

	t.Run("not signed in", func(t *testing.T) {
		fake := newGCPFake()
		fake.signedIn = false
		b := NewGCP(GCP{Runner: newFakeRunner(fake.handler)})
		if p := b.Probe(ctx); p.Available || !strings.Contains(p.Reason, "gcloud auth login") {
			t.Fatalf("probe: %+v", p)
		}
		if err := b.Put(ctx, "k", []byte("v"), meta); !errors.Is(err, ErrPermission) {
			t.Fatalf("put: %v", err)
		}
		if _, _, err := b.Get(ctx, "k"); !errors.Is(err, ErrPermission) {
			t.Fatalf("get: %v", err)
		}
	})

	t.Run("no project", func(t *testing.T) {
		fake := newGCPFake()
		fake.project = ""
		b := NewGCP(GCP{Runner: newFakeRunner(fake.handler)})
		if p := b.Probe(ctx); p.Available || !strings.Contains(p.Reason, "project") {
			t.Fatalf("probe: %+v", p)
		}
		if p := NewGCP(GCP{Runner: newFakeRunner(fake.handler), Project: "explicit"}).Probe(ctx); !p.Available || !strings.Contains(p.Reason, "explicit") {
			t.Fatalf("probe with explicit project: %+v", p)
		}
	})

	t.Run("probe reason", func(t *testing.T) {
		p := NewGCP(GCP{Runner: newFakeRunner(newGCPFake().handler)}).Probe(ctx)
		if !p.Available || p.Rank != 91 || !strings.Contains(p.Reason, "dev@example.com") || !strings.Contains(p.Reason, "my-project") {
			t.Fatalf("probe: %+v", p)
		}
	})

	t.Run("not found", func(t *testing.T) {
		runner := newFakeRunner(newGCPFake().handler)
		b := NewGCP(GCP{Runner: runner})
		if _, _, err := b.Get(ctx, "missing"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("get: %v", err)
		}
		if err := b.Delete(ctx, "missing"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("delete: %v", err)
		}
		for _, c := range runner.Calls() {
			if c.Args[1] == "delete" {
				t.Fatal("delete called for a missing secret")
			}
		}
	})

	t.Run("foreign or mismatched records", func(t *testing.T) {
		fake := newGCPFake()
		b := NewGCP(GCP{Runner: newFakeRunner(fake.handler)})
		if err := b.Put(ctx, "good", []byte("v"), meta); err != nil {
			t.Fatal(err)
		}
		rec, _ := encodeRecord(Metadata{Name: "other"}, []byte("v"))
		fake.secrets["burndrop-renamed"] = &gcpFakeSecret{versions: [][]byte{rec}, labels: map[string]string{"burndrop": "1"}}
		fake.secrets["burndrop-plain"] = &gcpFakeSecret{versions: [][]byte{[]byte("hunter2")}, labels: map[string]string{"burndrop": "1"}}
		fake.secrets["unrelated"] = &gcpFakeSecret{versions: [][]byte{[]byte("x")}, labels: map[string]string{}}
		if _, _, err := b.Get(ctx, "renamed"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("mismatched name: %v", err)
		}
		if _, _, err := b.Get(ctx, "plain"); err == nil || errors.Is(err, ErrNotFound) {
			t.Fatalf("foreign value: %v", err)
		}
		list, err := b.List(ctx)
		if err != nil || len(list) != 1 || list[0].Name != "good" {
			t.Fatalf("list: %+v %v", list, err)
		}
	})

	t.Run("limits", func(t *testing.T) {
		b := NewGCP(GCP{Runner: newFakeRunner(newGCPFake().handler)})
		if err := b.Put(ctx, "big", make([]byte, gcpMaxValueBytes+1), meta); !errors.Is(err, ErrTooLarge) {
			t.Fatalf("over the value limit: %v", err)
		}
		if err := b.Put(ctx, "fits", make([]byte, gcpMaxValueBytes), meta); err != nil {
			t.Fatalf("at the value limit: %v", err)
		}
		wide := meta
		wide.Purpose = strings.Repeat("p", 2000)
		if err := b.Put(ctx, "wide", make([]byte, gcpMaxValueBytes), wide); !errors.Is(err, ErrTooLarge) {
			t.Fatalf("record over the payload limit: %v", err)
		}
	})

	t.Run("prefix validation", func(t *testing.T) {
		b := NewGCP(GCP{Runner: newFakeRunner(newGCPFake().handler), Prefix: "bad.prefix-"})
		if p := b.Probe(ctx); p.Available {
			t.Fatalf("probe: %+v", p)
		}
		if err := b.Put(ctx, "k", []byte("v"), meta); !errors.Is(err, ErrInvalidName) {
			t.Fatalf("put: %v", err)
		}
	})
}
