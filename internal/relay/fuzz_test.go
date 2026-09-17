package relay

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// FuzzRequestDecoding sends arbitrary bodies to every mutating endpoint. The
// relay must answer with a client error, never a panic or a server error.
func FuzzRequestDecoding(f *testing.F) {
	cfg := DefaultConfig()
	cfg.PublicOrigin = "http://127.0.0.1"
	cfg.AgentAuth = "off"
	cfg.AgentKeys = nil
	cfg.RatePagePerMin = 1_000_000
	cfg.RateAgentPerMin = 1_000_000
	cfg.RateGlobalPerSec = 1_000_000
	if err := cfg.Validate(); err != nil {
		f.Fatal(err)
	}
	store, err := NewStore(cfg, time.Now)
	if err != nil {
		f.Fatal(err)
	}
	h := New(cfg, store, Options{Version: "fuzz"}).Handler()
	paths := []string{
		"/api/v1/drops", "/api/v1/drops/upload", "/api/v1/drops/status", "/api/v1/drops/fetch", "/api/v1/drops/revoke",
		"/api/v1/reveals", "/api/v1/reveals/open", "/api/v1/reveals/status", "/api/v1/reveals/revoke",
	}
	seeds := []string{
		`{"ttl_seconds":60,"commitment":"x"}`,
		`{"drop_id":"a","token":"b"}`,
		`{"drop_id":"a","upload_token":"b","commitment":"c","ciphertext":"AAAA"}`,
		`{"drop_id":"a","fetch_token":"b"}`,
		`{"drop_id":"a","reveal_token":"b"}`,
		`{"ttl_seconds":60,"ciphertext":"AAAA"}`,
		`{"ttl_seconds":"x"}`, `{"ttl_seconds":1e999}`, `{"ttl_seconds":-1}`, `{"drop_id":null}`,
		`{"a":1}`, `{`, ``, `[]`, `"x"`, `{"drop_id":"a"} {}`,
	}
	for _, s := range seeds {
		for i := range paths {
			f.Add(i, []byte(s))
		}
	}
	f.Fuzz(func(t *testing.T, which int, body []byte) {
		if which < 0 {
			which = -which
		}
		path := paths[which%len(paths)]
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
		req.Header.Set(ClientHeader, "fuzz/1")
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code >= 500 {
			t.Fatalf("%s: %d %s", path, rr.Code, rr.Body.String())
		}
	})
}
