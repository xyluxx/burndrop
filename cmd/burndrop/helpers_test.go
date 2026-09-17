package main

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"

	"github.com/burndrop/burndrop/web"
)

// testPage builds a web.Page for tests without a built page.
func testPage(html []byte, hash string) *web.Page {
	return &web.Page{HTML: html, Meta: web.Meta{Version: "test", SHA256: hash, ScriptSHA256: "x", StyleSHA256: "y"}}
}

// hexSHA256 is the page hash form: hex, as sha256sum prints it.
func hexSHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func pipe() (*os.File, io.WriteCloser) {
	r, w, err := os.Pipe()
	if err != nil {
		panic(err)
	}
	return r, w
}
