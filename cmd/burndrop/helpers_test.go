package main

import (
	"io"
	"os"

	"github.com/burndrop/burndrop/web"
)

// testPage builds a web.Page for tests without a built page.
func testPage(html []byte, hash string) *web.Page {
	return &web.Page{HTML: html, Meta: web.Meta{Version: "test", SHA256: hash, ScriptSHA256: "x", StyleSHA256: "y"}}
}

func pipe() (*os.File, io.WriteCloser) {
	r, w, err := os.Pipe()
	if err != nil {
		panic(err)
	}
	return r, w
}
