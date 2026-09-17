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

// onePasswordFake simulates the 1Password CLI 2 commands the backend uses
// with an in-memory vault. Output and error shapes follow the op reference:
// list output has no field values, "item get --fields --format json" prints
// one field object, errors start with "[ERROR] <date> <time>".
type onePasswordFake struct {
	t        *testing.T
	mu       sync.Mutex
	signedIn bool
	items    map[string]*onePasswordFakeItem // by ID
	next     int
}

type onePasswordFakeItem struct {
	id      string
	title   string
	vault   string
	tags    []string
	fields  []onePasswordField
	version int
}

func newOnePasswordFake(t *testing.T) *onePasswordFake {
	return &onePasswordFake{t: t, signedIn: true, items: map[string]*onePasswordFakeItem{}}
}

// seed adds an item the way a person might have, bypassing the backend.
func (f *onePasswordFake) seed(title, vault string, tags []string, record string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	it := f.newItem(title, vault, tags, []onePasswordField{{ID: "record", Type: "CONCEALED", Label: "record", Value: record}})
	return it.id
}

func (f *onePasswordFake) newItem(title, vault string, tags []string, fields []onePasswordField) *onePasswordFakeItem {
	f.next++
	it := &onePasswordFakeItem{id: fmt.Sprintf("%026d", f.next), title: title, vault: vault, tags: tags, fields: fields, version: 1}
	f.items[it.id] = it
	return it
}

func (f *onePasswordFake) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.items)
}

func onePasswordFakeErr(msg string) error {
	return exitError("op", 1, "[ERROR] 2026/09/17 10:00:00 "+msg)
}

// onePasswordFakeArgs splits args into positionals and flags. A lone "-"
// is a positional (the stdin marker); flags in the valued set consume the
// next argument.
func onePasswordFakeArgs(args []string) ([]string, map[string]string) {
	valued := map[string]bool{"vault": true, "account": true, "format": true, "fields": true, "tags": true, "template": true, "categories": true, "title": true, "category": true}
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

func (f *onePasswordFake) handle(call fakeCall) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if call.Name != "op" {
		return nil, exitError(call.Name, 127, "fake op: unexpected command "+call.Name)
	}
	pos, flags := onePasswordFakeArgs(call.Args)
	if !f.signedIn {
		return nil, onePasswordFakeErr("You are not currently signed in. Please run `op signin --help` for instructions")
	}
	if len(pos) == 1 && pos[0] == "whoami" {
		return []byte(`{"url":"https://my.1password.com","email":"ops@example.com","user_uuid":"AAAAAAAAAAAAAAAAAAAAAAAAAA","account_uuid":"BBBBBBBBBBBBBBBBBBBBBBBBBB"}` + "\n"), nil
	}
	if len(pos) >= 2 && pos[0] == "item" {
		switch pos[1] {
		case "create":
			return f.create(pos[2:], flags, call.Stdin)
		case "edit":
			return f.edit(pos[2:], flags, call.Stdin)
		case "get":
			return f.get(pos[2:], flags)
		case "delete":
			return f.remove(pos[2:], flags)
		case "list":
			return f.list(flags)
		}
	}
	return nil, onePasswordFakeErr("fake op does not implement: " + strings.Join(call.Args, " "))
}

func (f *onePasswordFake) create(pos []string, flags map[string]string, stdin []byte) ([]byte, error) {
	if len(pos) != 1 || pos[0] != "-" {
		// Assignment arguments would carry the value in argv.
		return nil, onePasswordFakeErr("fake op only accepts a template on standard input (op item create -)")
	}
	var tmpl onePasswordTemplate
	if err := json.Unmarshal(stdin, &tmpl); err != nil {
		return nil, onePasswordFakeErr("invalid item template: " + err.Error())
	}
	if tmpl.Category != "SECURE_NOTE" || tmpl.Title == "" {
		return nil, onePasswordFakeErr("the template needs a title and the SECURE_NOTE category")
	}
	vault := flags["vault"]
	if vault == "" {
		vault = "Private"
	}
	it := f.newItem(tmpl.Title, vault, tmpl.Tags, tmpl.Fields)
	return f.itemJSON(it), nil
}

func (f *onePasswordFake) edit(pos []string, flags map[string]string, stdin []byte) ([]byte, error) {
	if len(pos) != 1 {
		return nil, onePasswordFakeErr("fake op edit takes the item and a template on standard input")
	}
	it, err := f.resolve(pos[0], flags)
	if err != nil {
		return nil, err
	}
	if len(stdin) == 0 {
		return nil, onePasswordFakeErr("nothing to edit: no assignments or template given")
	}
	var tmpl onePasswordTemplate
	if err := json.Unmarshal(stdin, &tmpl); err != nil {
		return nil, onePasswordFakeErr("invalid item template: " + err.Error())
	}
	if tmpl.Title != "" {
		it.title = tmpl.Title
	}
	if tmpl.Tags != nil {
		it.tags = tmpl.Tags
	}
	for _, nf := range tmpl.Fields {
		replaced := false
		for i, of := range it.fields {
			if of.ID == nf.ID {
				it.fields[i] = nf
				replaced = true
			}
		}
		if !replaced {
			it.fields = append(it.fields, nf)
		}
	}
	it.version++
	return f.itemJSON(it), nil
}

func (f *onePasswordFake) get(pos []string, flags map[string]string) ([]byte, error) {
	if len(pos) != 1 {
		return nil, onePasswordFakeErr("item get takes one item")
	}
	it, err := f.resolve(pos[0], flags)
	if err != nil {
		return nil, err
	}
	sel := flags["fields"]
	if sel == "" {
		return f.itemJSON(it), nil
	}
	var out []map[string]string
	for _, want := range strings.Split(sel, ",") {
		label := strings.TrimPrefix(want, "label=")
		for _, fld := range it.fields {
			if fld.Label != label {
				continue
			}
			value := fld.Value
			if fld.Type == "CONCEALED" && flags["reveal"] == "" {
				value = "[use 'op item get " + it.id + " --reveal' to reveal]"
			}
			out = append(out, map[string]string{"id": fld.ID, "type": fld.Type, "label": fld.Label, "value": value, "reference": "op://" + it.vault + "/" + it.title + "/" + fld.ID})
		}
	}
	if len(out) == 0 {
		return nil, onePasswordFakeErr(fmt.Sprintf("%q isn't a field of item %q", sel, it.title))
	}
	if flags["format"] != "json" {
		vals := make([]string, 0, len(out))
		for _, o := range out {
			vals = append(vals, o["value"])
		}
		return []byte(strings.Join(vals, ",") + "\n"), nil
	}
	if len(out) == 1 {
		b, _ := json.Marshal(out[0])
		return append(b, '\n'), nil
	}
	b, _ := json.Marshal(out)
	return append(b, '\n'), nil
}

func (f *onePasswordFake) remove(pos []string, flags map[string]string) ([]byte, error) {
	if len(pos) != 1 {
		return nil, onePasswordFakeErr("item delete takes one item")
	}
	it, err := f.resolve(pos[0], flags)
	if err != nil {
		return nil, err
	}
	delete(f.items, it.id)
	return nil, nil
}

func (f *onePasswordFake) list(flags map[string]string) ([]byte, error) {
	if flags["format"] != "json" {
		return nil, onePasswordFakeErr("fake op list supports --format json only")
	}
	var want []string
	if flags["tags"] != "" {
		want = strings.Split(flags["tags"], ",")
	}
	ids := make([]string, 0, len(f.items))
	for id := range f.items {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := []map[string]any{}
	for _, id := range ids {
		it := f.items[id]
		if flags["vault"] != "" && it.vault != flags["vault"] {
			continue
		}
		tagged := true
		for _, tag := range want {
			if !slices.Contains(it.tags, tag) {
				tagged = false
			}
		}
		if !tagged {
			continue
		}
		out = append(out, map[string]any{
			"id": it.id, "title": it.title, "version": it.version,
			"vault":    map[string]string{"id": "v" + it.vault, "name": it.vault},
			"category": "SECURE_NOTE", "last_edited_by": "AAAAAAAAAAAAAAAAAAAAAAAAAA",
			"created_at": "2026-09-17T10:00:00Z", "updated_at": "2026-09-17T10:00:00Z",
		})
	}
	b, _ := json.Marshal(out)
	return append(b, '\n'), nil
}

// resolve finds an item by ID or title the way op does, restricted to the
// vault flag when one is given.
func (f *onePasswordFake) resolve(ref string, flags map[string]string) (*onePasswordFakeItem, error) {
	vault := flags["vault"]
	if it, ok := f.items[ref]; ok && (vault == "" || it.vault == vault) {
		return it, nil
	}
	var matches []*onePasswordFakeItem
	for _, it := range f.items {
		if it.title == ref && (vault == "" || it.vault == vault) {
			matches = append(matches, it)
		}
	}
	switch len(matches) {
	case 0:
		if vault != "" {
			return nil, onePasswordFakeErr(fmt.Sprintf("%q isn't an item in the %q vault. Specify the item with its UUID, name, or domain.", ref, vault))
		}
		return nil, onePasswordFakeErr(fmt.Sprintf("%q isn't an item. Specify the item with its UUID, name, or domain.", ref))
	case 1:
		return matches[0], nil
	}
	return nil, onePasswordFakeErr(fmt.Sprintf("More than one item matches %q. Try again and specify the item by its ID:", ref))
}

// itemJSON is the full item, as op item create, edit and get print it.
func (f *onePasswordFake) itemJSON(it *onePasswordFakeItem) []byte {
	b, _ := json.Marshal(map[string]any{
		"id": it.id, "title": it.title, "version": it.version,
		"vault":    map[string]string{"id": "v" + it.vault, "name": it.vault},
		"category": "SECURE_NOTE", "last_edited_by": "AAAAAAAAAAAAAAAAAAAAAAAAAA",
		"created_at": "2026-09-17T10:00:00Z", "updated_at": "2026-09-17T10:00:00Z",
		"tags": it.tags, "fields": it.fields,
	})
	return append(b, '\n')
}

func TestOnePasswordBackend(t *testing.T) {
	type env struct {
		fake   *onePasswordFake
		runner *fakeRunner
		b      *OnePassword
	}
	newEnv := func(t *testing.T, opts OnePasswordOptions) env {
		f := newOnePasswordFake(t)
		r := newFakeRunner(f.handle)
		opts.Runner = r
		return env{fake: f, runner: r, b: NewOnePassword(opts)}
	}
	ctx := context.Background()
	meta := Metadata{Retention: RetentionUntilRevoked, Purpose: "test", Source: SourceDrop}
	value := []byte("sk-live-1password-secret")

	runBackendSuite(t, func(t *testing.T) Backend { return newEnv(t, OnePasswordOptions{}).b }, 0)

	t.Run("values travel on stdin", func(t *testing.T) {
		e := newEnv(t, OnePasswordOptions{})
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
			if len(c.Args) < 2 || c.Args[0] != "item" {
				continue
			}
			switch c.Args[1] {
			case "create":
				created++
				if !slices.Contains(c.Args, "-") || !bytes.Contains(c.Stdin, b64) {
					t.Fatalf("create must read the template from stdin: %v", c.Args)
				}
			case "edit":
				edited++
				if !bytes.Contains(c.Stdin, b64) {
					t.Fatalf("edit must read the template from stdin: %v", c.Args)
				}
			case "get":
				if !slices.Contains(c.Args, "--reveal") || !slices.Contains(c.Args, "label=record") {
					t.Fatalf("get must ask for the record field with --reveal: %v", c.Args)
				}
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
		e := newEnv(t, OnePasswordOptions{})
		e.runner.setMissing("op", true)
		if p := e.b.Probe(ctx); p.Available || !strings.Contains(p.Reason, "install") {
			t.Fatalf("probe: %+v", p)
		}
	})

	t.Run("not signed in", func(t *testing.T) {
		e := newEnv(t, OnePasswordOptions{})
		e.fake.signedIn = false
		if p := e.b.Probe(ctx); p.Available || !strings.Contains(p.Reason, "op signin") || !strings.Contains(p.Reason, "not currently signed in") {
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
		e := newEnv(t, OnePasswordOptions{})
		if _, _, err := e.b.Get(ctx, "missing"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("get: %v", err)
		}
		if err := e.b.Delete(ctx, "missing"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("delete: %v", err)
		}
		scoped := exitError("op", 1, `[ERROR] 2026/09/17 10:00:00 "burndrop/x" isn't an item in the "Ops" vault. Specify the item with its UUID, name, or domain.`)
		if err := onePasswordClassify(scoped); !errors.Is(err, ErrNotFound) {
			t.Fatalf("vault scoped not found: %v", err)
		}
	})

	t.Run("vault and account flags", func(t *testing.T) {
		e := newEnv(t, OnePasswordOptions{Vault: "Ops", Account: "acme"})
		if err := e.b.Put(ctx, "db", value, meta); err != nil {
			t.Fatal(err)
		}
		for _, c := range e.runner.Calls() {
			if !slices.Contains(c.Args, "--account") || !slices.Contains(c.Args, "acme") {
				t.Fatalf("missing --account: %v", c.Args)
			}
			if c.Args[0] == "item" && !slices.Contains(c.Args, "--vault") {
				t.Fatalf("missing --vault: %v", c.Args)
			}
		}
		other := NewOnePassword(OnePasswordOptions{Vault: "Other", Runner: e.runner})
		if _, _, err := other.Get(ctx, "db"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("another vault sees the item: %v", err)
		}
		if v, _, err := e.b.Get(ctx, "db"); err != nil || !bytes.Equal(v, value) {
			t.Fatalf("own vault: %v", err)
		}
		if p := e.b.Probe(ctx); !p.Available || p.Rank != 95 || !strings.Contains(p.Reason, "ops@example.com") || !strings.Contains(p.Reason, "Ops") {
			t.Fatalf("probe: %+v", p)
		}
	})

	t.Run("foreign items", func(t *testing.T) {
		e := newEnv(t, OnePasswordOptions{})
		rec, _ := encodeRecord(Metadata{Name: "beta", Backend: "onepassword"}, []byte("b"))
		e.fake.seed("burndrop/alpha", "Private", []string{"burndrop"}, string(rec))
		if _, _, err := e.b.Get(ctx, "alpha"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("record of another name accepted: %v", err)
		}
		e.fake.seed("burndrop/manual", "Private", []string{"burndrop"}, "not a record")
		if err := e.b.Put(ctx, "real", value, meta); err != nil {
			t.Fatal(err)
		}
		list, err := e.b.List(ctx)
		if err != nil || len(list) != 1 || list[0].Name != "real" || list[0].Purpose != "test" {
			t.Fatalf("list: %v %+v", err, list)
		}
		e.fake.seed("burndrop/real", "Private", []string{"burndrop"}, string(rec))
		if _, _, err := e.b.Get(ctx, "real"); err == nil || errors.Is(err, ErrNotFound) || !strings.Contains(err.Error(), "duplicate") {
			t.Fatalf("duplicate titles: %v", err)
		}
	})
}
