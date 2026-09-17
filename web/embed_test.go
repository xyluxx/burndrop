package web

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"testing/fstest"
)

func TestLoadFS(t *testing.T) {
	html := []byte("<!doctype html><html><body>x</body></html>")
	sum := sha256.Sum256(html)
	good := fstest.MapFS{
		"dist/page.html":      {Data: html},
		"dist/page.meta.json": {Data: []byte(`{"version":"1.2.3","sha256":"` + hex.EncodeToString(sum[:]) + `","script_sha256":"abc","style_sha256":"def","needs_wasm":true}`)},
	}
	p, err := LoadFS(good)
	if err != nil {
		t.Fatal(err)
	}
	csp := p.CSP()
	for _, want := range []string{"script-src 'sha256-abc' 'wasm-unsafe-eval'", "style-src 'sha256-def'", "default-src 'none'", "connect-src 'self'", "frame-ancestors 'none'"} {
		if !strings.Contains(csp, want) {
			t.Fatalf("csp missing %q: %s", want, csp)
		}
	}
	noWasm := fstest.MapFS{"dist/page.html": good["dist/page.html"], "dist/page.meta.json": {Data: []byte(`{"version":"1","sha256":"` + hex.EncodeToString(sum[:]) + `","script_sha256":"abc","style_sha256":"def"}`)}}
	if p, err := LoadFS(noWasm); err != nil || strings.Contains(p.CSP(), "wasm") {
		t.Fatalf("no wasm: %v", err)
	}
	if _, err := LoadFS(fstest.MapFS{}); !errors.Is(err, ErrNotBuilt) {
		t.Fatalf("missing: %v", err)
	}
	if _, err := LoadFS(fstest.MapFS{"dist/page.html": {Data: html}}); !errors.Is(err, ErrNotBuilt) {
		t.Fatalf("missing meta: %v", err)
	}
	bad := fstest.MapFS{"dist/page.html": {Data: html}, "dist/page.meta.json": {Data: []byte(`{"version":"1","sha256":"deadbeef","script_sha256":"a","style_sha256":"b"}`)}}
	if _, err := LoadFS(bad); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("hash mismatch: %v", err)
	}
	incomplete := fstest.MapFS{"dist/page.html": {Data: html}, "dist/page.meta.json": {Data: []byte(`{"sha256":"` + hex.EncodeToString(sum[:]) + `"}`)}}
	if _, err := LoadFS(incomplete); err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("incomplete meta: %v", err)
	}
	broken := fstest.MapFS{"dist/page.html": {Data: html}, "dist/page.meta.json": {Data: []byte(`{`)}}
	if _, err := LoadFS(broken); err == nil {
		t.Fatal("broken meta accepted")
	}
	// The embedded dist is empty until the page is built.
	if _, err := Load(); err != nil && !errors.Is(err, ErrNotBuilt) {
		t.Fatalf("embedded load: %v", err)
	}
}
