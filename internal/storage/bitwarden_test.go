package storage

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
)

// bitwardenFake simulates the Bitwarden CLI commands the backend uses with
// an in-memory vault. Output follows the CLI's CipherResponse and status
// JSON; errors use the CLI's exact messages and go to stderr with exit 1.
type bitwardenFake struct {
	t       *testing.T
	mu      sync.Mutex
	status  string // unlocked, locked or unauthenticated
	session string // when set, BW_SESSION must match or the vault counts as locked
	items   map[string]*bitwardenFakeItem
	next    int
}

// bitwardenFakeItem mirrors the item JSON bw prints.
type bitwardenFakeItem struct {
	Object         string         `json:"object"`
	ID             string         `json:"id"`
	OrganizationID *string        `json:"organizationId"`
	FolderID       *string        `json:"folderId"`
	Type           int            `json:"type"`
	Reprompt       int            `json:"reprompt"`
	Name           string         `json:"name"`
	Notes          string         `json:"notes"`
	Favorite       bool           `json:"favorite"`
	SecureNote     *bitwardenNote `json:"secureNote,omitempty"`
	CollectionIDs  []string       `json:"collectionIds"`
	RevisionDate   string         `json:"revisionDate"`
	CreationDate   string         `json:"creationDate"`
	DeletedDate    *string        `json:"deletedDate"`
}

func newBitwardenFake(t *testing.T) *bitwardenFake {
	return &bitwardenFake{t: t, status: "unlocked", items: map[string]*bitwardenFakeItem{}}
}

// seed adds an item the way a person might have, bypassing the backend.
func (f *bitwardenFake) seed(name, notes string, deleted bool) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	it := f.newItem(name, notes)
	if deleted {
		d := "2026-09-17T09:00:00.000Z"
		it.DeletedDate = &d
	}
	return it.ID
}

func (f *bitwardenFake) newItem(name, notes string) *bitwardenFakeItem {
	f.next++
	it := &bitwardenFakeItem{
		Object: "item", ID: fmt.Sprintf("00000000-0000-4000-8000-%012d", f.next), Type: 2, Name: name, Notes: notes,
		SecureNote: &bitwardenNote{Type: 0}, CollectionIDs: []string{},
		RevisionDate: "2026-09-17T10:00:00.000Z", CreationDate: "2026-09-17T10:00:00.000Z",
	}
	f.items[it.ID] = it
	return it
}

func (f *bitwardenFake) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.items)
}

// bitwardenFakeArgs splits args into positionals and flags; flags in the
// valued set consume the next argument.
func bitwardenFakeArgs(args []string) ([]string, map[string]string) {
	valued := map[string]bool{"search": true, "session": true, "organizationid": true, "folderid": true, "collectionid": true, "url": true, "output": true, "itemid": true, "file": true}
	var pos []string
	flags := map[string]string{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "-p" {
			flags["permanent"] = "true"
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

// effectiveStatus applies the session check bw performs on every command.
func (f *bitwardenFake) effectiveStatus(env []string) string {
	if f.status == "unlocked" && f.session != "" && !slices.Contains(env, "BW_SESSION="+f.session) {
		return "locked"
	}
	return f.status
}

func (f *bitwardenFake) handle(call fakeCall) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if call.Name != "bw" {
		return nil, exitError(call.Name, 127, "fake bw: unexpected command "+call.Name)
	}
	pos, flags := bitwardenFakeArgs(call.Args)
	if flags["nointeraction"] == "" {
		f.t.Errorf("bw invoked without --nointeraction: %v", call.Args)
		return nil, exitError("bw", 1, "fake bw: would prompt for the master password")
	}
	status := f.effectiveStatus(call.Env)
	if len(pos) == 1 && pos[0] == "status" {
		st := map[string]any{"serverUrl": "https://vault.bitwarden.com", "lastSync": "2026-09-17T09:00:00.000Z", "userEmail": "ops@example.com", "userId": "11111111-2222-4333-8444-555555555555", "status": status}
		if status == "unauthenticated" {
			st["userEmail"], st["userId"] = nil, nil
		}
		b, _ := json.Marshal(st)
		return b, nil
	}
	switch status {
	case "unauthenticated":
		return nil, exitError("bw", 1, "You are not logged in.")
	case "locked":
		return nil, exitError("bw", 1, "Vault is locked.")
	}
	switch {
	case len(pos) == 2 && pos[0] == "list" && pos[1] == "items":
		return f.list(flags)
	case len(pos) >= 2 && pos[0] == "create" && pos[1] == "item":
		return f.create(pos[2:], call.Stdin)
	case len(pos) >= 3 && pos[0] == "edit" && pos[1] == "item":
		return f.edit(pos[2], pos[3:], call.Stdin)
	case len(pos) == 3 && pos[0] == "delete" && pos[1] == "item":
		return f.remove(pos[2], flags)
	}
	return nil, exitError("bw", 1, "fake bw does not implement: "+strings.Join(call.Args, " "))
}

// bitwardenFakeDecode decodes the base64 JSON request from the optional
// argument or from standard input, as the CLI's create and edit do.
func bitwardenFakeDecode(arg []string, stdin []byte) (bitwardenItem, error) {
	encoded := stdin
	if len(arg) > 0 {
		encoded = []byte(arg[0])
	}
	if len(encoded) == 0 {
		return bitwardenItem{}, exitError("bw", 1, "`requestJson` was not provided.")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		return bitwardenItem{}, exitError("bw", 1, "Error parsing the encoded request data.")
	}
	var req bitwardenItem
	if err := json.Unmarshal(raw, &req); err != nil {
		return bitwardenItem{}, exitError("bw", 1, "Error parsing the encoded request data.")
	}
	return req, nil
}

// bitwardenFakeCheck applies the server's encrypted length limits.
func bitwardenFakeCheck(req bitwardenItem) error {
	if req.Type != 2 {
		return exitError("bw", 1, "fake bw only stores secure notes (type 2)")
	}
	if bitwardenEncryptedLength(len(req.Notes)) > 10000 {
		return exitError("bw", 1, "The field Notes exceeds the maximum encrypted value length of 10000 characters.")
	}
	if bitwardenEncryptedLength(len(req.Name)) > 1000 {
		return exitError("bw", 1, "The field Name exceeds the maximum encrypted value length of 1000 characters.")
	}
	return nil
}

func (f *bitwardenFake) create(arg []string, stdin []byte) ([]byte, error) {
	req, err := bitwardenFakeDecode(arg, stdin)
	if err != nil {
		return nil, err
	}
	if err := bitwardenFakeCheck(req); err != nil {
		return nil, err
	}
	it := f.newItem(req.Name, req.Notes)
	it.OrganizationID, it.FolderID, it.Favorite, it.Reprompt = req.OrganizationID, req.FolderID, req.Favorite, req.Reprompt
	if req.CollectionIDs != nil {
		it.CollectionIDs = req.CollectionIDs
	}
	b, _ := json.Marshal(it)
	return b, nil
}

func (f *bitwardenFake) edit(id string, arg []string, stdin []byte) ([]byte, error) {
	it, ok := f.items[id]
	if !ok {
		return nil, exitError("bw", 1, "Not found.")
	}
	req, err := bitwardenFakeDecode(arg, stdin)
	if err != nil {
		return nil, err
	}
	if err := bitwardenFakeCheck(req); err != nil {
		return nil, err
	}
	it.Name, it.Notes, it.FolderID, it.Favorite, it.Reprompt = req.Name, req.Notes, req.FolderID, req.Favorite, req.Reprompt
	it.RevisionDate = "2026-09-17T11:00:00.000Z"
	b, _ := json.Marshal(it)
	return b, nil
}

func (f *bitwardenFake) remove(id string, flags map[string]string) ([]byte, error) {
	it, ok := f.items[id]
	if !ok {
		return nil, exitError("bw", 1, "Not found.")
	}
	if flags["permanent"] != "" {
		delete(f.items, id)
	} else {
		d := "2026-09-17T12:00:00.000Z"
		it.DeletedDate = &d
	}
	return nil, nil
}

// list applies --search as the CLI's basic search does: a case-insensitive
// substring match on the name, excluding the trash unless --trash is given.
func (f *bitwardenFake) list(flags map[string]string) ([]byte, error) {
	search := strings.ToLower(flags["search"])
	trash := flags["trash"] != ""
	ids := make([]string, 0, len(f.items))
	for id := range f.items {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := []*bitwardenFakeItem{}
	for _, id := range ids {
		it := f.items[id]
		if (it.DeletedDate != nil) != trash {
			continue
		}
		if search != "" && !strings.Contains(strings.ToLower(it.Name), search) {
			continue
		}
		out = append(out, it)
	}
	b, _ := json.Marshal(out)
	return b, nil
}

func TestBitwardenBackend(t *testing.T) {
	type env struct {
		fake   *bitwardenFake
		runner *fakeRunner
		b      *Bitwarden
	}
	newEnv := func(t *testing.T, opts BitwardenOptions) env {
		f := newBitwardenFake(t)
		r := newFakeRunner(f.handle)
		opts.Runner = r
		return env{fake: f, runner: r, b: NewBitwarden(opts)}
	}
	ctx := context.Background()
	meta := Metadata{Retention: RetentionUntilRevoked, Purpose: "test", Source: SourceDrop}
	value := []byte("sk-live-bitwarden-secret")

	runBackendSuite(t, func(t *testing.T) Backend { return newEnv(t, BitwardenOptions{}).b }, BitwardenMaxValueBytes)

	t.Run("values travel on stdin", func(t *testing.T) {
		e := newEnv(t, BitwardenOptions{})
		if err := e.b.Put(ctx, "api-key", value, meta); err != nil {
			t.Fatal(err)
		}
		if err := e.b.Put(ctx, "api-key", value, meta); err != nil { // overwrite edits in place
			t.Fatal(err)
		}
		if v, _, err := e.b.Get(ctx, "api-key"); err != nil || !bytes.Equal(v, value) {
			t.Fatalf("get: %v %q", err, v)
		}
		e.runner.assertNoSecretInArgs(t, value)
		b64 := []byte(base64.StdEncoding.EncodeToString(value))
		var created, edited int
		for _, c := range e.runner.Calls() {
			pos, _ := bitwardenFakeArgs(c.Args)
			switch {
			case pos[0] == "create":
				created++
				if len(pos) != 2 {
					t.Fatalf("create must omit encodedJson from argv: %v", c.Args)
				}
			case pos[0] == "edit":
				edited++
				if len(pos) != 3 {
					t.Fatalf("edit must omit encodedJson from argv: %v", c.Args)
				}
			default:
				continue
			}
			decoded, err := base64.StdEncoding.DecodeString(string(c.Stdin))
			if err != nil || !bytes.Contains(decoded, b64) {
				t.Fatalf("%s must read base64 JSON with the record from stdin: %v", pos[0], err)
			}
		}
		if created != 1 || edited != 1 {
			t.Fatalf("want one create and one edit, got %d and %d", created, edited)
		}
		if n := e.fake.count(); n != 1 {
			t.Fatalf("overwrite created a duplicate: %d items", n)
		}
	})

	t.Run("binary missing", func(t *testing.T) {
		e := newEnv(t, BitwardenOptions{})
		e.runner.setMissing("bw", true)
		if p := e.b.Probe(ctx); p.Available || !strings.Contains(p.Reason, "install") {
			t.Fatalf("probe: %+v", p)
		}
	})

	t.Run("not logged in", func(t *testing.T) {
		e := newEnv(t, BitwardenOptions{})
		e.fake.status = "unauthenticated"
		if p := e.b.Probe(ctx); p.Available || !strings.Contains(p.Reason, "bw login") {
			t.Fatalf("probe: %+v", p)
		}
		if err := e.b.Put(ctx, "k", value, meta); !errors.Is(err, ErrPermission) {
			t.Fatalf("put: %v", err)
		}
		if _, _, err := e.b.Get(ctx, "k"); !errors.Is(err, ErrPermission) {
			t.Fatalf("get: %v", err)
		}
		e.runner.assertNoSecretInArgs(t, value)
	})

	t.Run("locked", func(t *testing.T) {
		e := newEnv(t, BitwardenOptions{})
		e.fake.status = "locked"
		if p := e.b.Probe(ctx); p.Available || !strings.Contains(p.Reason, "bw unlock") {
			t.Fatalf("probe: %+v", p)
		}
		if err := e.b.Put(ctx, "k", value, meta); !errors.Is(err, ErrPermission) {
			t.Fatalf("put: %v", err)
		}
		if _, err := e.b.List(ctx); !errors.Is(err, ErrPermission) {
			t.Fatalf("list: %v", err)
		}
	})

	t.Run("session key", func(t *testing.T) {
		e := newEnv(t, BitwardenOptions{Session: "sess-123"})
		e.fake.session = "sess-123"
		if p := e.b.Probe(ctx); !p.Available || p.Rank != 94 || !strings.Contains(p.Reason, "ops@example.com") {
			t.Fatalf("probe: %+v", p)
		}
		if err := e.b.Put(ctx, "k", value, meta); err != nil {
			t.Fatal(err)
		}
		if v, _, err := e.b.Get(ctx, "k"); err != nil || !bytes.Equal(v, value) {
			t.Fatalf("get: %v", err)
		}
		for _, c := range e.runner.Calls() {
			if !slices.Contains(c.Env, "BW_SESSION=sess-123") {
				t.Fatalf("session key not passed in the environment: %v", c.Args)
			}
			if slices.Contains(c.Args, "--session") {
				t.Fatalf("session key passed as an argument: %v", c.Args)
			}
		}
		noSession := NewBitwarden(BitwardenOptions{Runner: e.runner})
		if p := noSession.Probe(ctx); p.Available || !strings.Contains(p.Reason, "bw unlock") {
			t.Fatalf("probe without session: %+v", p)
		}
		if _, _, err := noSession.Get(ctx, "k"); !errors.Is(err, ErrPermission) {
			t.Fatalf("get without session: %v", err)
		}
	})

	t.Run("not found", func(t *testing.T) {
		e := newEnv(t, BitwardenOptions{})
		if _, _, err := e.b.Get(ctx, "missing"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("get: %v", err)
		}
		if err := e.b.Delete(ctx, "missing"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("delete: %v", err)
		}
		if err := bitwardenClassify(exitError("bw", 1, "Not found.")); !errors.Is(err, ErrNotFound) {
			t.Fatalf("mapping: %v", err)
		}
	})

	t.Run("substring search does not confuse names", func(t *testing.T) {
		e := newEnv(t, BitwardenOptions{})
		for _, n := range []string{"a", "A1", "ab"} {
			if err := e.b.Put(ctx, n, []byte("value-"+n), meta); err != nil {
				t.Fatal(err)
			}
		}
		if n := e.fake.count(); n != 3 {
			t.Fatalf("want 3 items, got %d", n)
		}
		for _, n := range []string{"a", "A1", "ab"} {
			if v, m, err := e.b.Get(ctx, n); err != nil || string(v) != "value-"+n || m.Name != n {
				t.Fatalf("get %s: %v %q", n, err, v)
			}
		}
		if err := e.b.Delete(ctx, "a"); err != nil {
			t.Fatal(err)
		}
		list, err := e.b.List(ctx)
		if err != nil || len(list) != 2 || list[0].Name != "A1" || list[1].Name != "ab" {
			t.Fatalf("list after delete: %v %+v", err, list)
		}
	})

	t.Run("limits", func(t *testing.T) {
		e := newEnv(t, BitwardenOptions{})
		if err := e.b.Put(ctx, "big", make([]byte, BitwardenMaxValueBytes+1), meta); !errors.Is(err, ErrTooLarge) {
			t.Fatalf("over the value cap: %v", err)
		}
		long := meta
		long.Purpose = strings.Repeat("p", 8000)
		if err := e.b.Put(ctx, "verbose", []byte("v"), long); !errors.Is(err, ErrTooLarge) {
			t.Fatalf("record over the note cap: %v", err)
		}
		if len(e.runner.Calls()) != 0 {
			t.Fatal("oversized records must be refused before calling bw")
		}
		server := exitError("bw", 1, "The field Notes exceeds the maximum encrypted value length of 10000 characters.")
		if err := bitwardenClassify(server); !errors.Is(err, ErrTooLarge) {
			t.Fatalf("server limit mapping: %v", err)
		}
		if bitwardenEncryptedLength(0) != 96 || bitwardenEncryptedLength(16) != 116 {
			t.Fatalf("encrypted length estimate: %d %d", bitwardenEncryptedLength(0), bitwardenEncryptedLength(16))
		}
	})

	t.Run("duplicates, trash and foreign items", func(t *testing.T) {
		e := newEnv(t, BitwardenOptions{})
		rec, _ := encodeRecord(Metadata{Name: "dup", Backend: "bitwarden", Purpose: "x", SizeBytes: 1}, []byte("d"))
		e.fake.seed("burndrop/dup", string(rec), false)
		e.fake.seed("burndrop/dup", string(rec), false)
		if v, _, err := e.b.Get(ctx, "dup"); err != nil || string(v) != "d" {
			t.Fatalf("get with duplicates: %v", err)
		}
		if err := e.b.Delete(ctx, "dup"); err != nil {
			t.Fatal(err)
		}
		if n := e.fake.count(); n != 0 {
			t.Fatalf("delete left %d duplicate(s)", n)
		}
		e.fake.seed("burndrop/gone", string(rec), true)
		if _, _, err := e.b.Get(ctx, "gone"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("trashed item returned: %v", err)
		}
		other, _ := encodeRecord(Metadata{Name: "else", Backend: "bitwarden", Purpose: "x", SizeBytes: 1}, []byte("e"))
		e.fake.seed("burndrop/other", string(other), false)
		if _, _, err := e.b.Get(ctx, "other"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("record of another name accepted: %v", err)
		}
		e.fake.seed("burndrop/manual", "just a note", false)
		if err := e.b.Put(ctx, "real", value, meta); err != nil {
			t.Fatal(err)
		}
		list, err := e.b.List(ctx)
		if err != nil || len(list) != 1 || list[0].Name != "real" {
			t.Fatalf("list: %v %+v", err, list)
		}
	})
}
