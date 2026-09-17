package storage

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// azureFake simulates the az CLI: keyvault secret set, show, delete, purge
// and list, plus account show. Errors follow the CLI's "ERROR: (<Code>)
// <message>" form on stderr with exit code 1. Names compare
// case-insensitively and deletes are soft, as in Key Vault.
type azureFake struct {
	mu             sync.Mutex
	signedIn       bool
	forbidden      bool // signed in but without data plane rights
	purgeProtected bool
	vault          string
	secrets        map[string]*azureFakeSecret // keyed by lower-cased name
	deleted        map[string]*azureFakeSecret
	files          []string      // --file paths the CLI was pointed at
	modes          []os.FileMode // their permission bits when read
}

type azureFakeSecret struct {
	name  string
	value string
	tags  map[string]string
}

const azureFakeTime = "2026-09-17T01:02:03+00:00"

func newAzureFake() *azureFake {
	return &azureFake{signedIn: true, vault: "kv-burndrop", secrets: map[string]*azureFakeSecret{}, deleted: map[string]*azureFakeSecret{}}
}

// azureParseArgs splits az arguments into positionals and --flag values.
func azureParseArgs(args []string) (pos []string, flags map[string]string) {
	flags = map[string]string{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "--") {
			pos = append(pos, a)
			continue
		}
		if i+1 < len(args) && !strings.HasPrefix(args[i+1], "--") {
			flags[a] = args[i+1]
			i++
		} else {
			flags[a] = "true"
		}
	}
	return pos, flags
}

func (f *azureFake) notFound(name string) error {
	return exitError("az", 1, fmt.Sprintf("ERROR: (SecretNotFound) A secret with (name/id) %s was not found in this key vault. If you recently deleted this secret you may be able to recover it using the correct recovery command. For help resolving this issue, please see https://go.microsoft.com/fwlink/?linkid=2125182\nCode: SecretNotFound\nMessage: A secret with (name/id) %s was not found in this key vault.", name, name))
}

func (f *azureFake) item(s *azureFakeSecret, withValue bool) map[string]any {
	id := fmt.Sprintf("https://%s.vault.azure.net/secrets/%s", f.vault, s.name)
	if withValue {
		id += "/4f1c2e3d5a6b7c8d9e0f1a2b3c4d5e6f"
	}
	item := map[string]any{
		"attributes":  map[string]any{"created": azureFakeTime, "enabled": true, "expires": nil, "notBefore": nil, "recoverableDays": 90, "recoveryLevel": "Recoverable+Purgeable", "updated": azureFakeTime},
		"contentType": nil,
		"id":          id,
		"managed":     nil,
		"name":        s.name,
		"tags":        s.tags,
	}
	if withValue {
		item["kid"] = nil
		item["value"] = s.value
	}
	return item
}

func (f *azureFake) handler(call fakeCall) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if call.Name != "az" {
		return nil, fmt.Errorf("unexpected command %s", call.Name)
	}
	if call.Stdin != nil || len(call.Env) != 0 {
		return nil, errors.New("fake az: nothing is expected on stdin or in the environment")
	}
	pos, flags := azureParseArgs(call.Args)
	if flags["--output"] != "json" {
		return nil, errors.New("fake az: --output json is required")
	}
	if !f.signedIn {
		return nil, exitError("az", 1, "ERROR: Please run 'az login' to setup account.")
	}
	if len(pos) >= 2 && pos[0] == "account" && pos[1] == "show" {
		return []byte(`{"environmentName": "AzureCloud", "homeTenantId": "72f988bf-86f1-41af-91ab-2d7cd011db47", "id": "00000000-0000-0000-0000-000000000001", "isDefault": true, "managedByTenants": [], "name": "Pay-As-You-Go", "state": "Enabled", "tenantId": "72f988bf-86f1-41af-91ab-2d7cd011db47", "user": {"name": "dev@example.com", "type": "user"}}`), nil
	}
	if len(pos) < 3 || pos[0] != "keyvault" || pos[1] != "secret" {
		return nil, fmt.Errorf("fake az: unknown command %v", pos)
	}
	op := pos[2]
	if v := flags["--vault-name"]; v != f.vault {
		return nil, exitError("az", 1, fmt.Sprintf("ERROR: HTTPSConnectionPool(host='%s.vault.azure.net', port=443): Max retries exceeded with url: /secrets?api-version=7.4 (Caused by NameResolutionError: Failed to resolve '%s.vault.azure.net')", v, v))
	}
	if f.forbidden {
		return nil, exitError("az", 1, fmt.Sprintf("ERROR: (Forbidden) The user, group or application 'appid=04b07795-8ddb-461a-bbee-02f9e1bf7b46;oid=11111111-2222-3333-4444-555555555555;iss=https://sts.windows.net/72f988bf-86f1-41af-91ab-2d7cd011db47/' does not have secrets %s permission on key vault '%s;location=eastus'. For help resolving this issue, please see https://go.microsoft.com/fwlink/?linkid=2125287\nCode: Forbidden", op, f.vault))
	}
	name := flags["--name"]
	key := strings.ToLower(name)
	switch op {
	case "set":
		if flags["--value"] != "" {
			return nil, errors.New("fake az: --value carries the secret on the command line")
		}
		if _, ok := f.deleted[key]; ok {
			return nil, exitError("az", 1, fmt.Sprintf("ERROR: (Conflict) Secret %s is currently in a deleted but recoverable state, and its name cannot be reused; in this state, the secret can only be recovered or purged.\nCode: Conflict\nMessage: Secret %s is currently in a deleted but recoverable state, and its name cannot be reused; in this state, the secret can only be recovered or purged.", name, name))
		}
		path := flags["--file"]
		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		f.files = append(f.files, path)
		f.modes = append(f.modes, info.Mode().Perm())
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if len(b) > azureMaxRecordBytes {
			return nil, exitError("az", 1, "ERROR: (BadParameter) The secret value exceeds the maximum size of 25 KB.\nCode: BadParameter")
		}
		encoding := flags["--encoding"]
		if encoding == "" {
			encoding = "utf-8"
		}
		if encoding != "utf-8" {
			return nil, fmt.Errorf("fake az: unexpected encoding %q", encoding)
		}
		tags := map[string]string{}
		for _, kv := range strings.Fields(flags["--tags"]) {
			k, v, _ := strings.Cut(kv, "=")
			tags[k] = v
		}
		tags["file-encoding"] = encoding
		s := &azureFakeSecret{name: name, value: string(b), tags: tags}
		f.secrets[key] = s
		return json.Marshal(f.item(s, true))
	case "show":
		s, ok := f.secrets[key]
		if !ok {
			return nil, f.notFound(name)
		}
		return json.Marshal(f.item(s, true))
	case "delete":
		s, ok := f.secrets[key]
		if !ok {
			return nil, f.notFound(name)
		}
		delete(f.secrets, key)
		f.deleted[key] = s
		item := f.item(s, false)
		item["deletedDate"] = azureFakeTime
		item["recoveryId"] = fmt.Sprintf("https://%s.vault.azure.net/deletedsecrets/%s", f.vault, s.name)
		item["scheduledPurgeDate"] = "2026-12-16T01:02:03+00:00"
		return json.Marshal(item)
	case "purge":
		if _, ok := f.deleted[key]; !ok {
			return nil, exitError("az", 1, fmt.Sprintf("ERROR: (SecretNotFound) Deleted Secret not found: %s\nCode: SecretNotFound\nMessage: Deleted Secret not found: %s", name, name))
		}
		if f.purgeProtected {
			return nil, exitError("az", 1, "ERROR: (Forbidden) Operation \"purge\" is not allowed because purge protection is enabled for this vault.\nCode: Forbidden\nMessage: Operation \"purge\" is not allowed because purge protection is enabled for this vault.")
		}
		delete(f.deleted, key)
		return nil, nil
	case "list":
		query := flags["--query"]
		if query != "" && query != "[?tags.burndrop=='1']" {
			return nil, fmt.Errorf("fake az: unsupported query %q", query)
		}
		out := []map[string]any{}
		for _, s := range f.secrets {
			if query != "" && s.tags["burndrop"] != "1" {
				continue
			}
			out = append(out, f.item(s, false))
		}
		return json.Marshal(out)
	}
	return nil, fmt.Errorf("fake az: unknown operation %q", op)
}

func TestAzureBackend(t *testing.T) {
	newBackend := func(fake *azureFake, purge bool) *Azure {
		return NewAzure(Azure{VaultName: fake.vault, Purge: purge, Runner: newFakeRunner(fake.handler)})
	}
	runBackendSuite(t, func(t *testing.T) Backend { return newBackend(newAzureFake(), false) }, azureMaxValueBytes)
	runBackendSuite(t, func(t *testing.T) Backend { return newBackend(newAzureFake(), true) }, azureMaxValueBytes)

	ctx := context.Background()
	meta := Metadata{Retention: RetentionUntilRevoked, Purpose: "test"}

	t.Run("value only through a temporary file", func(t *testing.T) {
		fake := newAzureFake()
		runner := newFakeRunner(fake.handler)
		b := NewAzure(Azure{VaultName: fake.vault, Runner: runner})
		secret := []byte("sk-live-1234 with \x00 and \xff")
		if err := b.Put(ctx, "api-key", secret, meta); err != nil {
			t.Fatal(err)
		}
		if v, _, err := b.Get(ctx, "api-key"); err != nil || string(v) != string(secret) {
			t.Fatalf("get: %v", err)
		}
		runner.assertNoSecretInArgs(t, secret)
		runner.assertNoSecretInArgs(t, []byte(base64.StdEncoding.EncodeToString(secret)))
		if len(fake.files) != 1 {
			t.Fatalf("expected one temp file, saw %v", fake.files)
		}
		if _, err := os.Stat(fake.files[0]); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("temp file still exists: %v", err)
		}
		if filepath.Dir(fake.files[0]) != filepath.Clean(os.TempDir()) {
			t.Fatalf("temp file outside os.TempDir: %s", fake.files[0])
		}
		if runtime.GOOS != "windows" && fake.modes[0] != 0o600 {
			t.Fatalf("temp file mode %o, want 0600", fake.modes[0])
		}
		var set []string
		for _, c := range runner.Calls() {
			args := strings.Join(c.Args, " ")
			if !strings.Contains(args, "--vault-name kv-burndrop") || !strings.HasSuffix(args, "--output json --only-show-errors") {
				t.Fatalf("missing vault or output flags: %v", c.Args)
			}
			if c.Args[2] == "set" {
				set = c.Args
			}
		}
		joined := strings.Join(set, " ")
		if !strings.Contains(joined, "--file "+fake.files[0]) || !strings.Contains(joined, "--encoding utf-8") || !strings.Contains(joined, "--tags burndrop=1") || strings.Contains(joined, "--value") {
			t.Fatalf("set args: %v", set)
		}
		tags := fake.secrets["burndrop-api-key"].tags
		if tags["burndrop"] != "1" || tags["file-encoding"] != "utf-8" {
			t.Fatalf("tags: %v", tags)
		}
	})

	t.Run("name mapping", func(t *testing.T) {
		fake := newAzureFake()
		b := newBackend(fake, false)
		for _, n := range []string{"api-key", "API-KEY", "prod.db_url"} {
			if err := b.Put(ctx, n, []byte("value of "+n), meta); err != nil {
				t.Fatal(err)
			}
		}
		if len(fake.secrets) != 3 {
			t.Fatalf("expected three distinct Key Vault secrets: %v", fake.secrets)
		}
		if _, ok := fake.secrets["burndrop-api-key"]; !ok {
			t.Fatalf("plain name rewritten: %v", fake.secrets)
		}
		for _, want := range []string{`^burndrop-api-key-[0-9a-f]{8}$`, `^burndrop-prod-db-url-[0-9a-f]{8}$`} {
			re := regexp.MustCompile(want)
			found := 0
			for name := range fake.secrets {
				if re.MatchString(name) {
					found++
				}
			}
			if found != 1 {
				t.Fatalf("no secret matches %s: %v", want, fake.secrets)
			}
		}
		for _, n := range []string{"api-key", "API-KEY", "prod.db_url"} {
			if v, m, err := b.Get(ctx, n); err != nil || string(v) != "value of "+n || m.Name != n {
				t.Fatalf("%s: %v %q", n, err, v)
			}
		}
		list, err := b.List(ctx)
		if err != nil || len(list) != 3 || list[0].Name != "API-KEY" || list[1].Name != "api-key" || list[2].Name != "prod.db_url" {
			t.Fatalf("list: %+v %v", list, err)
		}
	})

	t.Run("binary missing", func(t *testing.T) {
		fake := newAzureFake()
		runner := newFakeRunner(fake.handler)
		runner.setMissing("az", true)
		p := NewAzure(Azure{VaultName: fake.vault, Runner: runner}).Probe(ctx)
		if p.Available || !strings.Contains(p.Reason, "install the Azure CLI") {
			t.Fatalf("probe: %+v", p)
		}
	})

	t.Run("vault name missing", func(t *testing.T) {
		b := NewAzure(Azure{Runner: newFakeRunner(newAzureFake().handler)})
		if p := b.Probe(ctx); p.Available || !strings.Contains(p.Reason, "VaultName") {
			t.Fatalf("probe: %+v", p)
		}
		if err := b.Put(ctx, "k", []byte("v"), meta); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("put: %v", err)
		}
		if _, err := b.List(ctx); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("list: %v", err)
		}
	})

	t.Run("not signed in", func(t *testing.T) {
		fake := newAzureFake()
		fake.signedIn = false
		b := newBackend(fake, false)
		if p := b.Probe(ctx); p.Available || !strings.Contains(p.Reason, "az login") {
			t.Fatalf("probe: %+v", p)
		}
		if err := b.Put(ctx, "k", []byte("v"), meta); !errors.Is(err, ErrPermission) {
			t.Fatalf("put: %v", err)
		}
		if _, _, err := b.Get(ctx, "k"); !errors.Is(err, ErrPermission) {
			t.Fatalf("get: %v", err)
		}
	})

	t.Run("forbidden on the vault", func(t *testing.T) {
		fake := newAzureFake()
		fake.forbidden = true
		b := newBackend(fake, false)
		if p := b.Probe(ctx); !p.Available {
			t.Fatalf("probe should pass on account show alone: %+v", p)
		}
		if err := b.Put(ctx, "k", []byte("v"), meta); !errors.Is(err, ErrPermission) {
			t.Fatalf("put: %v", err)
		}
		if _, _, err := b.Get(ctx, "k"); !errors.Is(err, ErrPermission) {
			t.Fatalf("get: %v", err)
		}
		if _, err := b.List(ctx); !errors.Is(err, ErrPermission) {
			t.Fatalf("list: %v", err)
		}
	})

	t.Run("probe reason", func(t *testing.T) {
		p := newBackend(newAzureFake(), false).Probe(ctx)
		if !p.Available || p.Rank != 91 || !strings.Contains(p.Reason, "kv-burndrop") || !strings.Contains(p.Reason, "dev@example.com") || !strings.Contains(p.Reason, "Pay-As-You-Go") {
			t.Fatalf("probe: %+v", p)
		}
	})

	t.Run("not found", func(t *testing.T) {
		b := newBackend(newAzureFake(), false)
		if _, _, err := b.Get(ctx, "missing"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("get: %v", err)
		}
		if err := b.Delete(ctx, "missing"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("delete: %v", err)
		}
	})

	t.Run("soft delete reserves the name", func(t *testing.T) {
		fake := newAzureFake()
		runner := newFakeRunner(fake.handler)
		b := NewAzure(Azure{VaultName: fake.vault, Runner: runner})
		if err := b.Put(ctx, "k", []byte("v"), meta); err != nil {
			t.Fatal(err)
		}
		if err := b.Delete(ctx, "k"); err != nil {
			t.Fatal(err)
		}
		if _, _, err := b.Get(ctx, "k"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("get after delete: %v", err)
		}
		if err := b.Delete(ctx, "k"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("double delete: %v", err)
		}
		err := b.Put(ctx, "k", []byte("v2"), meta)
		if err == nil || errors.Is(err, ErrNotFound) || !strings.Contains(err.Error(), "soft deleted") || !strings.Contains(err.Error(), "az keyvault secret purge") {
			t.Fatalf("put over a soft deleted name: %v", err)
		}
		for _, c := range runner.Calls() {
			if c.Args[2] == "purge" {
				t.Fatal("purge called without opting in")
			}
		}
		if _, ok := fake.deleted["burndrop-k"]; !ok {
			t.Fatal("secret should be in the soft deleted state")
		}
	})

	t.Run("purge when opted in", func(t *testing.T) {
		fake := newAzureFake()
		runner := newFakeRunner(fake.handler)
		b := NewAzure(Azure{VaultName: fake.vault, Purge: true, Runner: runner})
		if err := b.Put(ctx, "k", []byte("v"), meta); err != nil {
			t.Fatal(err)
		}
		if err := b.Delete(ctx, "k"); err != nil {
			t.Fatal(err)
		}
		var ops []string
		for _, c := range runner.Calls() {
			ops = append(ops, c.Args[2])
		}
		if strings.Join(ops, ",") != "set,delete,purge" {
			t.Fatalf("operations: %v", ops)
		}
		if len(fake.deleted) != 0 {
			t.Fatalf("secret not purged: %v", fake.deleted)
		}
		if err := b.Put(ctx, "k", []byte("v2"), meta); err != nil {
			t.Fatalf("name not reusable after purge: %v", err)
		}
	})

	t.Run("purge protection", func(t *testing.T) {
		fake := newAzureFake()
		fake.purgeProtected = true
		b := newBackend(fake, true)
		if err := b.Put(ctx, "k", []byte("v"), meta); err != nil {
			t.Fatal(err)
		}
		err := b.Delete(ctx, "k")
		if !errors.Is(err, ErrPermission) || !strings.Contains(err.Error(), "could not be purged") {
			t.Fatalf("delete with purge protection: %v", err)
		}
		if _, _, err := b.Get(ctx, "k"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("the soft delete should still have happened: %v", err)
		}
	})

	t.Run("foreign or mismatched records", func(t *testing.T) {
		fake := newAzureFake()
		b := newBackend(fake, false)
		if err := b.Put(ctx, "good", []byte("v"), meta); err != nil {
			t.Fatal(err)
		}
		rec, _ := encodeRecord(Metadata{Name: "other"}, []byte("v"))
		tagged := map[string]string{"burndrop": "1", "file-encoding": "utf-8"}
		fake.secrets["burndrop-renamed"] = &azureFakeSecret{name: "burndrop-renamed", value: string(rec), tags: tagged}
		fake.secrets["burndrop-plain"] = &azureFakeSecret{name: "burndrop-plain", value: "hunter2", tags: tagged}
		fake.secrets["burndrop-untagged"] = &azureFakeSecret{name: "burndrop-untagged", value: "hunter2", tags: map[string]string{}}
		fake.secrets["other-app"] = &azureFakeSecret{name: "other-app", value: "hunter2", tags: tagged}
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
		b := newBackend(newAzureFake(), false)
		if err := b.Put(ctx, "big", make([]byte, azureMaxValueBytes+1), meta); !errors.Is(err, ErrTooLarge) {
			t.Fatalf("over the value limit: %v", err)
		}
		if err := b.Put(ctx, "fits", make([]byte, azureMaxValueBytes), meta); err != nil {
			t.Fatalf("at the value limit: %v", err)
		}
		wide := meta
		wide.Purpose = strings.Repeat("p", 2000)
		if err := b.Put(ctx, "wide", make([]byte, azureMaxValueBytes), wide); !errors.Is(err, ErrTooLarge) {
			t.Fatalf("record over the 25 KB limit: %v", err)
		}
	})

	t.Run("prefix validation", func(t *testing.T) {
		fake := newAzureFake()
		b := NewAzure(Azure{VaultName: fake.vault, Prefix: "bad_prefix-", Runner: newFakeRunner(fake.handler)})
		if p := b.Probe(ctx); p.Available {
			t.Fatalf("probe: %+v", p)
		}
		if err := b.Put(ctx, "k", []byte("v"), meta); !errors.Is(err, ErrInvalidName) {
			t.Fatalf("put: %v", err)
		}
		long := NewAzure(Azure{VaultName: fake.vault, Prefix: strings.Repeat("p", 30) + "-", Runner: newFakeRunner(fake.handler)})
		if err := long.Put(ctx, strings.Repeat("n", 100), []byte("v"), meta); !errors.Is(err, ErrInvalidName) {
			t.Fatalf("name over 127 characters: %v", err)
		}
	})
}
