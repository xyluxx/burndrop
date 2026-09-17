package storage

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// runBackendSuite is the conformance suite every backend must pass. maxValue
// lets a backend with a smaller native limit still be tested at its limit.
func runBackendSuite(t *testing.T, newBackend func(t *testing.T) Backend, maxValue int) {
	t.Helper()
	if maxValue <= 0 || maxValue > MaxValueBytes {
		maxValue = MaxValueBytes
	}
	ctx := context.Background()
	meta := func(name string) Metadata {
		return Metadata{Name: name, Retention: RetentionUntilRevoked, CreatedAt: time.Date(2026, 9, 17, 1, 2, 3, 0, time.UTC), Purpose: "test purpose", Source: SourceDrop, Sendable: true, Fingerprint: "0000-1111-2222-3333"}
	}

	t.Run("round trip", func(t *testing.T) {
		b := newBackend(t)
		if p := b.Probe(ctx); !p.Available {
			t.Fatalf("probe: %+v", p)
		}
		if err := b.Put(ctx, "api-key", []byte("sk-live-1234"), meta("api-key")); err != nil {
			t.Fatal(err)
		}
		v, m, err := b.Get(ctx, "api-key")
		if err != nil || string(v) != "sk-live-1234" {
			t.Fatalf("get: %v %q", err, v)
		}
		if m.Name != "api-key" || m.Purpose != "test purpose" || !m.Sendable || m.Fingerprint != "0000-1111-2222-3333" || m.Retention != RetentionUntilRevoked || !m.CreatedAt.Equal(meta("").CreatedAt) {
			t.Fatalf("metadata lost: %+v", m)
		}
		if m.Backend != b.Name() {
			t.Fatalf("backend name %q, want %q", m.Backend, b.Name())
		}
		// Overwrite.
		if err := b.Put(ctx, "api-key", []byte("rotated"), meta("api-key")); err != nil {
			t.Fatal(err)
		}
		if v, _, _ := b.Get(ctx, "api-key"); string(v) != "rotated" {
			t.Fatalf("overwrite: %q", v)
		}
		if err := b.Delete(ctx, "api-key"); err != nil {
			t.Fatal(err)
		}
		if _, _, err := b.Get(ctx, "api-key"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("after delete: %v", err)
		}
		if err := b.Delete(ctx, "api-key"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("double delete: %v", err)
		}
	})

	t.Run("binary and large values", func(t *testing.T) {
		b := newBackend(t)
		bin := make([]byte, 300)
		for i := range bin {
			bin[i] = byte(i)
		}
		bin = append(bin, []byte("\n\r\t\x00 quotes ' \" and unicode é")...)
		if err := b.Put(ctx, "cert", bin, meta("cert")); err != nil {
			t.Fatal(err)
		}
		if v, _, err := b.Get(ctx, "cert"); err != nil || !bytes.Equal(v, bin) {
			t.Fatalf("binary round trip: %v", err)
		}
		large := bytes.Repeat([]byte("x"), maxValue-1)
		if err := b.Put(ctx, "large", large, meta("large")); err != nil {
			t.Fatalf("large put: %v", err)
		}
		if v, m, err := b.Get(ctx, "large"); err != nil || !bytes.Equal(v, large) || m.SizeBytes != len(large) {
			t.Fatalf("large get: %v", err)
		}
		if err := b.Put(ctx, "huge", make([]byte, MaxValueBytes+1), meta("huge")); !errors.Is(err, ErrTooLarge) {
			t.Fatalf("over the limit: %v", err)
		}
		if err := b.Put(ctx, "empty", nil, meta("empty")); err != nil {
			t.Fatalf("empty value: %v", err)
		}
		if v, _, err := b.Get(ctx, "empty"); err != nil || len(v) != 0 {
			t.Fatalf("empty get: %v %q", err, v)
		}
	})

	t.Run("names", func(t *testing.T) {
		b := newBackend(t)
		for _, bad := range []string{"", " lead", "has space", "slash/name", "a..b", strings.Repeat("n", 101), "-dash-first", "é", "semi;colon"} {
			if err := b.Put(ctx, bad, []byte("v"), meta(bad)); !errors.Is(err, ErrInvalidName) {
				t.Fatalf("name %q accepted: %v", bad, err)
			}
			if _, _, err := b.Get(ctx, bad); !errors.Is(err, ErrInvalidName) {
				t.Fatalf("get with name %q: %v", bad, err)
			}
		}
		for _, good := range []string{"a", "A1", "openai-api-key", "prod.db_url", "x-1.2_3", strings.Repeat("n", 100)} {
			if err := b.Put(ctx, good, []byte("v"), meta(good)); err != nil {
				t.Fatalf("name %q rejected: %v", good, err)
			}
		}
		if _, _, err := b.Get(ctx, "missing-name"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("missing: %v", err)
		}
	})

	t.Run("list", func(t *testing.T) {
		b := newBackend(t)
		for _, n := range []string{"beta", "alpha", "gamma"} {
			if err := b.Put(ctx, n, []byte(n), meta(n)); err != nil {
				t.Fatal(err)
			}
		}
		list, err := b.List(ctx)
		if errors.Is(err, ErrUnavailable) {
			t.Skip("backend cannot enumerate; the manager uses the index")
		}
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, m := range list {
			names = append(names, m.Name)
		}
		if strings.Join(names, ",") != "alpha,beta,gamma" {
			t.Fatalf("list order or contents: %v", names)
		}
		for _, m := range list {
			if m.Purpose != "test purpose" || m.SizeBytes == 0 {
				t.Fatalf("list metadata: %+v", m)
			}
		}
	})

	t.Run("concurrent", func(t *testing.T) {
		b := newBackend(t)
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				name := "c" + string(rune('a'+i))
				if err := b.Put(ctx, name, []byte(name), meta(name)); err != nil {
					t.Error(err)
				}
			}(i)
		}
		wg.Wait()
		for i := 0; i < 8; i++ {
			name := "c" + string(rune('a'+i))
			if v, _, err := b.Get(ctx, name); err != nil || string(v) != name {
				t.Fatalf("%s: %v %q", name, err, v)
			}
		}
	})
}
