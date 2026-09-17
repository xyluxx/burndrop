package storage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMemoryBackend(t *testing.T) {
	runBackendSuite(t, func(t *testing.T) Backend { return NewMemory() }, 0)
	m := NewMemory()
	_ = m.Put(context.Background(), "x", []byte("v"), Metadata{})
	m.Close()
	if _, _, err := m.Get(context.Background(), "x"); !errors.Is(err, ErrNotFound) {
		t.Fatal("close must drop values")
	}
}

func TestRecordAndRetention(t *testing.T) {
	meta := Metadata{Name: "n", Retention: RetentionUntilRevoked, Purpose: "p"}
	b, err := encodeRecord(meta, []byte{0, 1, 2})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "\x00") {
		t.Fatal("record must be text (base64 value)")
	}
	v, m, err := decodeRecord(b)
	if err != nil || string(v) != "\x00\x01\x02" || m.Purpose != "p" {
		t.Fatalf("decode: %v %v %+v", err, v, m)
	}
	if _, err := encodeRecord(meta, make([]byte, MaxValueBytes+1)); !errors.Is(err, ErrTooLarge) {
		t.Fatal("size limit")
	}
	for _, bad := range []string{"", "{}", `{"v":2}`, "not json"} {
		if _, _, err := decodeRecord([]byte(bad)); err == nil {
			t.Fatalf("decoded %q", bad)
		}
	}
	now := time.Date(2026, 9, 17, 0, 0, 0, 0, time.UTC)
	if exp, err := ParseRetention(RetentionSession, now); err != nil || !exp.IsZero() {
		t.Fatal("session")
	}
	if exp, err := ParseRetention("until:2027-01-01T00:00:00Z", now); err != nil || exp.Year() != 2027 {
		t.Fatalf("until: %v %v", exp, err)
	}
	for _, bad := range []string{"", "forever", "until:", "until:yesterday", "until:2020-01-01T00:00:00Z"} {
		if _, err := ParseRetention(bad, now); !errors.Is(err, ErrRetention) {
			t.Fatalf("%q accepted", bad)
		}
	}
	if !(Metadata{ExpiresAt: now}).Expired(now) || (Metadata{}).Expired(now) || (Metadata{ExpiresAt: now.Add(time.Second)}).Expired(now) {
		t.Fatal("expired logic")
	}
}

func TestIndex(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "index.json")
	idx, err := OpenIndex(path)
	if err != nil {
		t.Fatal(err)
	}
	if list, err := idx.List(); err != nil || len(list) != 0 {
		t.Fatalf("empty index: %v %v", err, list)
	}
	if _, err := idx.Get("nope"); !errors.Is(err, ErrNotFound) {
		t.Fatal("missing")
	}
	if err := idx.Put(Metadata{Name: "b", Purpose: "2"}); err != nil {
		t.Fatal(err)
	}
	if err := idx.Put(Metadata{Name: "a", Purpose: "1"}); err != nil {
		t.Fatal(err)
	}
	list, _ := idx.List()
	if len(list) != 2 || list[0].Name != "a" || list[1].Name != "b" {
		t.Fatalf("list: %+v", list)
	}
	if m, err := idx.Get("a"); err != nil || m.Purpose != "1" {
		t.Fatal("get")
	}
	if err := idx.Delete("a"); err != nil || idx.Delete("a") != nil {
		t.Fatal("delete")
	}
	if list, _ := idx.List(); len(list) != 1 {
		t.Fatal("after delete")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 && !isWindows() {
		t.Fatalf("index permissions too open: %o", perm)
	}
	if entries, _ := os.ReadDir(filepath.Dir(path)); len(entries) != 1 {
		t.Fatalf("temp files left behind: %v", entries)
	}
	if err := os.WriteFile(path, []byte("{corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := idx.List(); err == nil || !strings.Contains(err.Error(), "corrupt") {
		t.Fatalf("corrupt index: %v", err)
	}
	if _, err := OpenIndex(filepath.Join(path, "child")); err == nil {
		t.Fatal("directory under a file must fail")
	}
}

func TestManager(t *testing.T) {
	ctx := context.Background()
	clock := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	now := func() time.Time { return clock }
	idx, _ := OpenIndex(filepath.Join(t.TempDir(), "index.json"))
	persistent := NewMemory()
	m := NewManager(persistent, idx, now)

	if _, err := m.Put(ctx, "bad name", []byte("v"), Metadata{Retention: RetentionSession}); !errors.Is(err, ErrInvalidName) {
		t.Fatal("name validation")
	}
	if _, err := m.Put(ctx, "x", []byte("v"), Metadata{Retention: "forever"}); !errors.Is(err, ErrRetention) {
		t.Fatal("retention validation")
	}
	if _, err := m.Put(ctx, "x", make([]byte, MaxValueBytes+1), Metadata{Retention: RetentionSession}); !errors.Is(err, ErrTooLarge) {
		t.Fatal("size")
	}
	// Session secrets stay in memory and out of the persistent backend and index.
	meta, err := m.Put(ctx, "sess", []byte("s"), Metadata{Retention: RetentionSession, Purpose: "p"})
	if err != nil || meta.Backend != "memory" || meta.Source != SourceDrop || !meta.CreatedAt.Equal(clock) || !meta.ExpiresAt.IsZero() {
		t.Fatalf("session put: %v %+v", err, meta)
	}
	if _, _, err := persistent.Get(ctx, "sess"); !errors.Is(err, ErrNotFound) {
		t.Fatal("session secret leaked to persistent backend")
	}
	if list, _ := idx.List(); len(list) != 0 {
		t.Fatal("session secret in index")
	}
	// Persistent secrets go to the backend and the index.
	meta, err = m.Put(ctx, "perm", []byte("p"), Metadata{Retention: RetentionUntilRevoked, Source: SourceCapture})
	if err != nil || meta.Backend != "memory" || meta.Source != SourceCapture {
		t.Fatalf("persistent put: %v %+v", err, meta)
	}
	if got, _ := idx.Get("perm"); got.Name != "perm" || got.SizeBytes != 1 {
		t.Fatalf("index entry: %+v", got)
	}
	// Dated retention.
	meta, err = m.Put(ctx, "dated", []byte("d"), Metadata{Retention: "until:2026-09-17T13:00:00Z"})
	if err != nil || meta.ExpiresAt.Hour() != 13 {
		t.Fatalf("dated: %v %+v", err, meta)
	}
	list, err := m.List(ctx)
	if err != nil || len(list) != 3 || list[0].Name != "dated" || list[1].Name != "perm" || list[2].Name != "sess" {
		t.Fatalf("list: %v %+v", err, list)
	}
	if v, _, err := m.Get(ctx, "sess"); err != nil || string(v) != "s" {
		t.Fatal("get session")
	}
	if v, meta, err := m.Get(ctx, "dated"); err != nil || string(v) != "d" || meta.Retention != "until:2026-09-17T13:00:00Z" {
		t.Fatalf("get dated: %v", err)
	}
	// Session shadows persistent for the same name.
	_, _ = m.Put(ctx, "perm", []byte("shadow"), Metadata{Retention: RetentionSession})
	if v, meta, _ := m.Get(ctx, "perm"); string(v) != "shadow" || meta.Retention != RetentionSession {
		t.Fatal("session should shadow persistent")
	}
	// Expiry purges on get and on list.
	clock = clock.Add(2 * time.Hour)
	if _, _, err := m.Get(ctx, "dated"); !errors.Is(err, ErrNotFound) {
		t.Fatal("expired secret returned")
	}
	if _, _, err := persistent.Get(ctx, "dated"); !errors.Is(err, ErrNotFound) {
		t.Fatal("expired secret not deleted from backend")
	}
	_, _ = m.Put(ctx, "dated2", []byte("d"), Metadata{Retention: "until:2026-09-17T15:00:00Z"})
	clock = clock.Add(2 * time.Hour)
	n, err := m.PurgeExpired(ctx)
	if err != nil || n != 1 {
		t.Fatalf("purge: %v %d", err, n)
	}
	// Delete removes from every place; unknown names report not found.
	if err := m.Delete(ctx, "perm"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.Get(ctx, "perm"); !errors.Is(err, ErrNotFound) {
		t.Fatal("perm still present")
	}
	if err := m.Delete(ctx, "perm"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("double delete: %v", err)
	}
	// An index entry whose backend value vanished is pruned on get.
	_, _ = m.Put(ctx, "gone", []byte("g"), Metadata{Retention: RetentionUntilRevoked})
	_ = persistent.Delete(ctx, "gone")
	if _, _, err := m.Get(ctx, "gone"); !errors.Is(err, ErrNotFound) {
		t.Fatal("vanished value")
	}
	if _, err := idx.Get("gone"); !errors.Is(err, ErrNotFound) {
		t.Fatal("stale index entry not pruned")
	}
	m.Close()
	if _, _, err := m.Get(ctx, "sess"); !errors.Is(err, ErrNotFound) {
		t.Fatal("close must clear session secrets")
	}
}

func TestExecRunner(t *testing.T) {
	r := ExecRunner{Timeout: 10 * time.Second}
	if _, err := r.LookPath("definitely-not-a-command-xyz"); err == nil {
		t.Fatal("lookpath")
	}
	shell, args := "sh", []string{"-c"}
	if isWindows() {
		if _, err := r.LookPath("sh"); err != nil {
			shell, args = "cmd", []string{"/c"}
		}
	}
	out, err := r.Run(context.Background(), shell, append(args, "echo hello"), nil, nil)
	if err != nil || !strings.Contains(string(out), "hello") {
		t.Fatalf("run: %v %q", err, out)
	}
	_, err = r.Run(context.Background(), shell, append(args, "echo oops 1>&2 && exit 3"), nil, nil)
	var exit *ExitError
	if !errors.As(err, &exit) || exit.Code != 3 || !strings.Contains(exit.Stderr, "oops") || !strings.Contains(err.Error(), "code 3") {
		t.Fatalf("exit error: %v", err)
	}
	if _, err := r.Run(context.Background(), "definitely-not-a-command-xyz", nil, nil, nil); err == nil {
		t.Fatal("missing command")
	}
	fast := ExecRunner{Timeout: 50 * time.Millisecond}
	sleep := "sleep 2"
	if shell == "cmd" {
		sleep = "ping -n 3 127.0.0.1 > nul"
	}
	if _, err := fast.Run(context.Background(), shell, append(args, sleep), nil, nil); err == nil {
		t.Fatal("timeout")
	}
	if classifyExit(nil) != nil {
		t.Fatal("nil")
	}
	if !errors.Is(classifyExit(&ExitError{Stderr: "item not found"}, "not found"), ErrNotFound) {
		t.Fatal("not found hint")
	}
	if !errors.Is(classifyExit(&ExitError{Stderr: "You are not signed in"}), ErrPermission) {
		t.Fatal("permission")
	}
	if err := classifyExit(&ExitError{Code: 9, Stderr: "boom"}); errors.Is(err, ErrPermission) || errors.Is(err, ErrNotFound) {
		t.Fatal("unclassified")
	}
}

func isWindows() bool { return strings.EqualFold(os.Getenv("OS"), "Windows_NT") }
