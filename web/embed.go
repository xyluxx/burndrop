// Package web embeds the built drop page so the relay binary can serve it.
//
// The page is one self-contained HTML file produced by the build in this
// directory. Its SHA-256 is published with every release so anyone can verify
// the page a relay serves. The build also records the hashes of the inline
// script and style so the relay can pin them in the Content-Security-Policy.
package web

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// ErrNotBuilt is returned when the page has not been built into dist/.
var ErrNotBuilt = errors.New("web: drop page not built (run the web build first)")

// Meta is written by the page build next to page.html.
type Meta struct {
	Version      string `json:"version"`
	SHA256       string `json:"sha256"`
	ScriptSHA256 string `json:"script_sha256"` // base64 digest for the CSP script-src hash source
	StyleSHA256  string `json:"style_sha256"`  // base64 digest for the CSP style-src hash source
	NeedsWasm    bool   `json:"needs_wasm"`    // whether script-src must include 'wasm-unsafe-eval'
}

// Page is the loaded drop page with its metadata.
type Page struct {
	HTML []byte
	Meta Meta
}

// Load reads the embedded page and verifies its hash against the metadata.
func Load() (*Page, error) {
	return LoadFS(dist)
}

// LoadFS is Load over an arbitrary filesystem, for tests.
func LoadFS(fsys fs.FS) (*Page, error) {
	html, err := fs.ReadFile(fsys, "dist/page.html")
	if err != nil {
		return nil, ErrNotBuilt
	}
	metaRaw, err := fs.ReadFile(fsys, "dist/page.meta.json")
	if err != nil {
		return nil, ErrNotBuilt
	}
	var meta Meta
	if err := json.Unmarshal(metaRaw, &meta); err != nil {
		return nil, fmt.Errorf("web: page.meta.json: %w", err)
	}
	sum := sha256.Sum256(html)
	if got := hex.EncodeToString(sum[:]); got != meta.SHA256 {
		return nil, fmt.Errorf("web: page.html hash %s does not match page.meta.json %s", got, meta.SHA256)
	}
	if meta.ScriptSHA256 == "" || meta.StyleSHA256 == "" || meta.Version == "" {
		return nil, errors.New("web: page.meta.json is incomplete")
	}
	return &Page{HTML: html, Meta: meta}, nil
}

// CSP returns the Content-Security-Policy for the page when it is served from
// the same origin as the relay API.
func (p *Page) CSP() string {
	script := "'sha256-" + p.Meta.ScriptSHA256 + "'"
	if p.Meta.NeedsWasm {
		script += " 'wasm-unsafe-eval'"
	}
	return "default-src 'none'; script-src " + script +
		"; style-src 'sha256-" + p.Meta.StyleSHA256 + "'" +
		"; img-src 'self' data:; font-src data:; connect-src 'self'" +
		"; frame-ancestors 'none'; form-action 'none'; base-uri 'none'; manifest-src 'none'; upgrade-insecure-requests"
}
