package storage

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
)

// vaultFake is a small KV version 2 server: data and metadata endpoints
// under any mount, LIST on metadata, token lookup-self, and the status codes
// Vault uses (404 with {"errors":[]} for a missing path, 403 for a bad
// token, 503 when sealed, 204 for a metadata delete even when nothing was
// there).
type vaultFake struct {
	mu        sync.Mutex
	token     string
	sealed    bool
	denyWrite bool
	entries   map[string]*vaultFakeEntry // "<mount>/<path>"
	requests  []string                   // "<method> <path>" in order
	namespace []string                   // X-Vault-Namespace of each request
	server    *httptest.Server
}

type vaultFakeEntry struct {
	data    map[string]string
	version int
}

const vaultFakeTime = "2026-09-17T01:02:03.986212308Z"

func newVaultFake(t *testing.T, tls bool) *vaultFake {
	t.Helper()
	f := &vaultFake{token: "test-token", entries: map[string]*vaultFakeEntry{}}
	if tls {
		f.server = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	} else {
		f.server = httptest.NewServer(http.HandlerFunc(f.serve))
	}
	t.Cleanup(f.server.Close)
	return f
}

// backend returns a Vault client for the fake; the server's client trusts
// its test certificate.
func (f *vaultFake) backend() *Vault {
	return NewVault(Vault{Address: f.server.URL, Token: "test-token", HTTPClient: f.server.Client()})
}

func (f *vaultFake) set(fn func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn()
}

func (f *vaultFake) snapshot() (requests, namespaces []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.requests...), append([]string(nil), f.namespace...)
}

func vaultWrite(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if body != nil {
		_ = json.NewEncoder(w).Encode(body)
	}
}

func (f *vaultFake) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := strings.TrimPrefix(r.URL.Path, "/v1/")
	f.requests = append(f.requests, r.Method+" "+p)
	f.namespace = append(f.namespace, r.Header.Get("X-Vault-Namespace"))
	if f.sealed {
		vaultWrite(w, http.StatusServiceUnavailable, map[string]any{"errors": []string{"Vault is sealed"}})
		return
	}
	if r.Header.Get("X-Vault-Token") != f.token {
		vaultWrite(w, http.StatusForbidden, map[string]any{"errors": []string{"permission denied"}})
		return
	}
	if p == "auth/token/lookup-self" && r.Method == http.MethodGet {
		vaultWrite(w, http.StatusOK, map[string]any{"data": map[string]any{
			"accessor": "8609694a-cdbc-db9b-d345-e782dbb562ed", "creation_time": 1758070923, "display_name": "token-dev",
			"entity_id": "", "expire_time": nil, "id": f.token, "meta": nil, "num_uses": 0, "orphan": true,
			"path": "auth/token/create", "policies": []string{"default", "burndrop"}, "ttl": 0, "type": "service",
		}})
		return
	}
	parts := strings.SplitN(p, "/", 3)
	if len(parts) < 2 {
		vaultWrite(w, http.StatusNotFound, map[string]any{"errors": []string{}})
		return
	}
	mount, kind, rest := parts[0], parts[1], ""
	if len(parts) == 3 {
		rest = parts[2]
	}
	key := mount + "/" + rest
	notFound := func() { vaultWrite(w, http.StatusNotFound, map[string]any{"errors": []string{}}) }
	switch kind {
	case "data":
		switch r.Method {
		case http.MethodPost, http.MethodPut:
			if f.denyWrite {
				vaultWrite(w, http.StatusForbidden, map[string]any{"errors": []string{"1 error occurred:\n\t* permission denied\n\n"}})
				return
			}
			var body struct {
				Data map[string]string `json:"data"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Data == nil {
				vaultWrite(w, http.StatusBadRequest, map[string]any{"errors": []string{"no data provided"}})
				return
			}
			e := f.entries[key]
			if e == nil {
				e = &vaultFakeEntry{}
				f.entries[key] = e
			}
			e.data = body.Data
			e.version++
			vaultWrite(w, http.StatusOK, map[string]any{"data": map[string]any{"created_time": vaultFakeTime, "custom_metadata": nil, "deletion_time": "", "destroyed": false, "version": e.version}})
		case http.MethodGet:
			e, ok := f.entries[key]
			if !ok {
				notFound()
				return
			}
			vaultWrite(w, http.StatusOK, map[string]any{"data": map[string]any{"data": e.data, "metadata": map[string]any{"created_time": vaultFakeTime, "custom_metadata": nil, "deletion_time": "", "destroyed": false, "version": e.version}}})
		default:
			vaultWrite(w, http.StatusMethodNotAllowed, map[string]any{"errors": []string{"unsupported operation"}})
		}
	case "metadata":
		switch {
		case r.Method == "LIST" || (r.Method == http.MethodGet && r.URL.Query().Get("list") == "true"):
			prefix := key + "/"
			seen := map[string]bool{}
			var keys []string
			for k := range f.entries {
				if !strings.HasPrefix(k, prefix) {
					continue
				}
				child := strings.TrimPrefix(k, prefix)
				if i := strings.Index(child, "/"); i >= 0 {
					child = child[:i+1]
				}
				if !seen[child] {
					seen[child] = true
					keys = append(keys, child)
				}
			}
			if len(keys) == 0 {
				notFound()
				return
			}
			sort.Strings(keys)
			vaultWrite(w, http.StatusOK, map[string]any{"data": map[string]any{"keys": keys}})
		case r.Method == http.MethodGet:
			e, ok := f.entries[key]
			if !ok {
				notFound()
				return
			}
			vaultWrite(w, http.StatusOK, map[string]any{"data": map[string]any{"cas_required": false, "created_time": vaultFakeTime, "current_version": e.version, "custom_metadata": nil, "delete_version_after": "0s", "max_versions": 0, "oldest_version": 0, "updated_time": vaultFakeTime, "versions": map[string]any{}}})
		case r.Method == http.MethodDelete:
			delete(f.entries, key)
			w.WriteHeader(http.StatusNoContent)
		default:
			vaultWrite(w, http.StatusMethodNotAllowed, map[string]any{"errors": []string{"unsupported operation"}})
		}
	default:
		notFound()
	}
}

func TestVaultBackend(t *testing.T) {
	runBackendSuite(t, func(t *testing.T) Backend { return newVaultFake(t, false).backend() }, MaxValueBytes)

	ctx := context.Background()
	meta := Metadata{Retention: RetentionUntilRevoked, Purpose: "test"}

	t.Run("https end to end", func(t *testing.T) {
		fake := newVaultFake(t, true)
		if !strings.HasPrefix(fake.server.URL, "https://") {
			t.Fatalf("expected a TLS server, got %s", fake.server.URL)
		}
		b := fake.backend()
		p := b.Probe(ctx)
		if !p.Available || p.Rank != 85 || !strings.Contains(p.Reason, "token-dev") || !strings.Contains(p.Reason, "burndrop") || !strings.Contains(p.Reason, fake.server.URL) {
			t.Fatalf("probe: %+v", p)
		}
		secret := []byte("sk-live-1234")
		if err := b.Put(ctx, "api-key", secret, meta); err != nil {
			t.Fatal(err)
		}
		if v, m, err := b.Get(ctx, "api-key"); err != nil || !bytes.Equal(v, secret) || m.Backend != "vault" {
			t.Fatalf("get: %v %+v", err, m)
		}
	})

	t.Run("plain http only for localhost", func(t *testing.T) {
		b := NewVault(Vault{Address: "http://vault.example.com:8200", Token: "x"})
		if p := b.Probe(ctx); p.Available || !strings.Contains(p.Reason, "https") {
			t.Fatalf("probe: %+v", p)
		}
		if err := b.Put(ctx, "k", []byte("v"), meta); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("put: %v", err)
		}
		if _, _, err := b.Get(ctx, "k"); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("get: %v", err)
		}
		if err := b.Delete(ctx, "k"); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("delete: %v", err)
		}
		if _, err := b.List(ctx); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("list: %v", err)
		}
		for _, ok := range []string{"http://localhost:8200", "http://127.0.0.1:8200/", "http://[::1]:8200", "https://vault.example.com"} {
			if _, err := NewVault(Vault{Address: ok}).baseURL(); err != nil {
				t.Fatalf("%s should be accepted: %v", ok, err)
			}
		}
		t.Setenv("VAULT_ADDR", "")
		if p := NewVault(Vault{Token: "x"}).Probe(ctx); p.Available || !strings.Contains(p.Reason, "VAULT_ADDR") {
			t.Fatalf("probe without an address: %+v", p)
		}
	})

	t.Run("paths, body and headers", func(t *testing.T) {
		fake := newVaultFake(t, false)
		b := NewVault(Vault{Address: fake.server.URL, Token: "test-token", Namespace: "team-a", Mount: "kv/", Path: "/apps/burndrop/"})
		secret := []byte("sk-live-1234 with \x00 and \xff")
		if err := b.Put(ctx, "api-key", secret, meta); err != nil {
			t.Fatal(err)
		}
		fake.set(func() {
			e := fake.entries["kv/apps/burndrop/api-key"]
			if e == nil {
				t.Fatalf("entry not stored under the mount and path: %v", fake.entries)
			}
			rec := e.data["record"]
			if !strings.Contains(rec, base64.StdEncoding.EncodeToString(secret)) {
				t.Fatalf("record does not carry the value: %q", rec)
			}
			if v, m, err := decodeRecord([]byte(rec)); err != nil || !bytes.Equal(v, secret) || m.Name != "api-key" {
				t.Fatalf("stored record: %v %+v", err, m)
			}
		})
		if v, _, err := b.Get(ctx, "api-key"); err != nil || !bytes.Equal(v, secret) {
			t.Fatalf("get: %v", err)
		}
		if list, err := b.List(ctx); err != nil || len(list) != 1 || list[0].Name != "api-key" {
			t.Fatalf("list: %+v %v", list, err)
		}
		if err := b.Delete(ctx, "api-key"); err != nil {
			t.Fatal(err)
		}
		requests, namespaces := fake.snapshot()
		want := []string{
			"POST kv/data/apps/burndrop/api-key",
			"GET kv/data/apps/burndrop/api-key",
			"LIST kv/metadata/apps/burndrop",
			"GET kv/data/apps/burndrop/api-key",
			"GET kv/metadata/apps/burndrop/api-key",
			"DELETE kv/metadata/apps/burndrop/api-key",
		}
		if strings.Join(requests, "\n") != strings.Join(want, "\n") {
			t.Fatalf("requests:\n%s", strings.Join(requests, "\n"))
		}
		for _, ns := range namespaces {
			if ns != "team-a" {
				t.Fatalf("namespace header missing: %v", namespaces)
			}
		}
		fake2 := newVaultFake(t, false)
		if err := fake2.backend().Put(ctx, "k", []byte("v"), meta); err != nil {
			t.Fatal(err)
		}
		if _, namespaces := fake2.snapshot(); len(namespaces) != 1 || namespaces[0] != "" {
			t.Fatalf("namespace header sent without a namespace: %v", namespaces)
		}
	})

	t.Run("token from the environment and the token file", func(t *testing.T) {
		fake := newVaultFake(t, false)
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("USERPROFILE", home)
		t.Setenv("VAULT_TOKEN", "")
		t.Setenv("VAULT_ADDR", fake.server.URL)
		t.Setenv("VAULT_NAMESPACE", "from-env")
		b := NewVault(Vault{})
		if b.Address != fake.server.URL || b.Namespace != "from-env" || b.Mount != DefaultVaultMount || b.Path != DefaultVaultPath || b.HTTPClient == nil {
			t.Fatalf("defaults: %+v", b)
		}
		if p := b.Probe(ctx); p.Available || !strings.Contains(p.Reason, "VAULT_TOKEN") {
			t.Fatalf("probe without a token: %+v", p)
		}
		if err := b.Put(ctx, "k", []byte("v"), meta); !errors.Is(err, ErrPermission) {
			t.Fatalf("put without a token: %v", err)
		}
		if err := os.WriteFile(filepath.Join(home, ".vault-token"), []byte("test-token\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if p := b.Probe(ctx); !p.Available || !strings.Contains(p.Reason, "from-env") {
			t.Fatalf("probe with the token file: %+v", p)
		}
		if err := b.Put(ctx, "k", []byte("v"), meta); err != nil {
			t.Fatalf("put with the token file: %v", err)
		}
		t.Setenv("VAULT_TOKEN", "wrong")
		if _, _, err := b.Get(ctx, "k"); !errors.Is(err, ErrPermission) {
			t.Fatalf("the environment should win over the file: %v", err)
		}
		t.Setenv("VAULT_TOKEN", "test-token")
		if v, _, err := b.Get(ctx, "k"); err != nil || string(v) != "v" {
			t.Fatalf("get with the environment token: %v", err)
		}
		if _, namespaces := fake.snapshot(); namespaces[len(namespaces)-1] != "from-env" {
			t.Fatalf("namespace from the environment not sent: %v", namespaces)
		}
	})

	t.Run("status mapping", func(t *testing.T) {
		fake := newVaultFake(t, false)
		b := fake.backend()
		if _, _, err := b.Get(ctx, "missing"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("404 on get: %v", err)
		}
		if err := b.Delete(ctx, "missing"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("404 on delete: %v", err)
		}
		if list, err := b.List(ctx); err != nil || len(list) != 0 {
			t.Fatalf("404 on list should be an empty list: %v %v", list, err)
		}
		requests, _ := fake.snapshot()
		for _, r := range requests {
			if strings.HasPrefix(r, "DELETE ") {
				t.Fatalf("metadata deleted for a missing secret: %v", requests)
			}
		}
		if err := b.Put(ctx, "k", []byte("v"), meta); err != nil {
			t.Fatal(err)
		}
		fake.set(func() { fake.token = "rotated" })
		if p := b.Probe(ctx); p.Available || !strings.Contains(p.Reason, "permission denied") {
			t.Fatalf("probe with a rejected token: %+v", p)
		}
		if err := b.Put(ctx, "k", []byte("v"), meta); !errors.Is(err, ErrPermission) {
			t.Fatalf("403 on put: %v", err)
		}
		if _, _, err := b.Get(ctx, "k"); !errors.Is(err, ErrPermission) {
			t.Fatalf("403 on get: %v", err)
		}
		if err := b.Delete(ctx, "k"); !errors.Is(err, ErrPermission) {
			t.Fatalf("403 on delete: %v", err)
		}
		if _, err := b.List(ctx); !errors.Is(err, ErrPermission) {
			t.Fatalf("403 on list: %v", err)
		}
		fake.set(func() { fake.token = "test-token"; fake.denyWrite = true })
		if err := b.Put(ctx, "k", []byte("v"), meta); !errors.Is(err, ErrPermission) {
			t.Fatalf("403 on a write-only denial: %v", err)
		}
		if v, _, err := b.Get(ctx, "k"); err != nil || string(v) != "v" {
			t.Fatalf("read should still work: %v", err)
		}
		fake.set(func() { fake.denyWrite = false; fake.sealed = true })
		if _, _, err := b.Get(ctx, "k"); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("503 on get: %v", err)
		}
		if p := b.Probe(ctx); p.Available || !strings.Contains(p.Reason, "sealed") {
			t.Fatalf("probe while sealed: %+v", p)
		}
	})

	t.Run("foreign or mismatched records", func(t *testing.T) {
		fake := newVaultFake(t, false)
		b := fake.backend()
		if err := b.Put(ctx, "good", []byte("v"), meta); err != nil {
			t.Fatal(err)
		}
		rec, _ := encodeRecord(Metadata{Name: "other"}, []byte("v"))
		fake.set(func() {
			fake.entries["secret/burndrop/renamed"] = &vaultFakeEntry{data: map[string]string{"record": string(rec)}, version: 1}
			fake.entries["secret/burndrop/plain"] = &vaultFakeEntry{data: map[string]string{"password": "hunter2"}, version: 1}
			fake.entries["secret/burndrop/nested/child"] = &vaultFakeEntry{data: map[string]string{"password": "hunter2"}, version: 1}
		})
		if _, _, err := b.Get(ctx, "renamed"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("mismatched name: %v", err)
		}
		if _, _, err := b.Get(ctx, "plain"); err == nil || errors.Is(err, ErrNotFound) {
			t.Fatalf("foreign entry: %v", err)
		}
		list, err := b.List(ctx)
		if err != nil || len(list) != 1 || list[0].Name != "good" {
			t.Fatalf("list: %+v %v", list, err)
		}
	})

	t.Run("unreachable", func(t *testing.T) {
		fake := newVaultFake(t, false)
		b := fake.backend()
		fake.server.Close()
		if p := b.Probe(ctx); p.Available || !strings.Contains(p.Reason, "unreachable") {
			t.Fatalf("probe: %+v", p)
		}
		if _, _, err := b.Get(ctx, "k"); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("get: %v", err)
		}
	})
}
