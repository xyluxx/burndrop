package link

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/burndrop/burndrop/internal/crypto"
)

const (
	id    = "MTIzNDU2Nzg5MGFiY2RlZg"
	token = "YWJjZGVmZ2hpamtsbW5vcA"
	page  = "https://drop.example.com"
)

func key(b byte) []byte { return bytes.Repeat([]byte{b}, crypto.KeySize) }

func sampleDrop() Drop {
	return Drop{
		ID: id, UploadToken: token, RecipientKey: key(7),
		Name: "openai-api-key", Purpose: "Call the OpenAI API from the billing script & report",
		Storage: "macOS Keychain", Retention: "until-revoked",
	}
}

func sampleReveal() Reveal {
	return Reveal{ID: id, RevealToken: token, Key: key(9), Name: "staging-db-url", KeepsCopy: true}
}

func TestDropRoundTrip(t *testing.T) {
	d := sampleDrop()
	raw, err := d.Build(page)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(raw, page+"/drop#v=1&i="+id+"&u="+token+"&k=") {
		t.Fatalf("unexpected link shape: %s", raw)
	}
	if strings.Contains(raw, "?") {
		t.Fatal("links must not contain a query string")
	}
	got, origin, err := ParseDrop(raw)
	if err != nil {
		t.Fatal(err)
	}
	if origin != page {
		t.Fatalf("origin %q", origin)
	}
	if got.ID != d.ID || got.UploadToken != d.UploadToken || !bytes.Equal(got.RecipientKey, d.RecipientKey) ||
		got.Name != d.Name || got.Purpose != d.Purpose || got.Storage != d.Storage || got.Retention != d.Retention || got.Relay != "" {
		t.Fatalf("round trip mismatch: %+v", got)
	}
	if got.Fingerprint() != crypto.Fingerprint(key(7)) {
		t.Fatal("fingerprint mismatch")
	}
	p, err := Parse(raw)
	if err != nil || p.Kind != KindDrop || p.RelayOrigin() != page {
		t.Fatalf("Parse: %v %+v", err, p)
	}
}

func TestDropWithRelayAndUnicode(t *testing.T) {
	d := sampleDrop()
	d.Relay = "HTTPS://Relay.Example.com:8443/"
	d.Name = "clé API"
	d.Purpose = "Ligne 1\nligne 2 with + plus and % percent and #hash and =equals"
	raw, err := d.Build(page)
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := ParseDrop(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Relay != "https://relay.example.com:8443" {
		t.Fatalf("relay %q", got.Relay)
	}
	if got.Name != d.Name || got.Purpose != d.Purpose {
		t.Fatalf("text round trip: %q %q", got.Name, got.Purpose)
	}
	p, _ := Parse(raw)
	if p.RelayOrigin() != "https://relay.example.com:8443" {
		t.Fatal("relay origin")
	}
}

func TestRevealRoundTrip(t *testing.T) {
	r := sampleReveal()
	raw, err := r.Build(page)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(raw, page+"/reveal#v=1&i="+id+"&o="+token+"&k=") || !strings.HasSuffix(raw, "&c=1") {
		t.Fatalf("unexpected link shape: %s", raw)
	}
	got, origin, err := ParseReveal(raw)
	if err != nil || origin != page {
		t.Fatal(err, origin)
	}
	if got.ID != r.ID || got.RevealToken != r.RevealToken || !bytes.Equal(got.Key, r.Key) || got.Name != r.Name || !got.KeepsCopy {
		t.Fatalf("round trip mismatch: %+v", got)
	}
	if !bytes.Equal(got.AAD(), crypto.RevealAAD("staging-db-url", true)) {
		t.Fatal("aad mismatch")
	}
	r.KeepsCopy = false
	raw2, _ := r.Build(page)
	got2, _, _ := ParseReveal(raw2)
	if got2.KeepsCopy {
		t.Fatal("keeps copy should be false")
	}
	if _, _, err := ParseDrop(raw); err == nil {
		t.Fatal("reveal link parsed as drop")
	}
}

func TestInvalidLinks(t *testing.T) {
	good, _ := sampleDrop().Build(page)
	frag := good[strings.IndexByte(good, '#')+1:]
	cases := map[string]string{
		"no fragment":        page + "/drop",
		"wrong path":         page + "/other#" + frag,
		"root path":          page + "/#" + frag,
		"query string":       page + "/drop?x=1#" + frag,
		"userinfo":           "https://user@drop.example.com/drop#" + frag,
		"http origin":        "http://drop.example.com/drop#" + frag,
		"no scheme":          "drop.example.com/drop#" + frag,
		"empty fragment":     page + "/drop#",
		"wrong version":      page + "/drop#" + strings.Replace(frag, "v=1", "v=2", 1),
		"missing version":    page + "/drop#" + strings.Replace(frag, "v=1&", "", 1),
		"unknown field":      page + "/drop#" + frag + "&x=1",
		"duplicate field":    page + "/drop#" + frag + "&n=again",
		"missing id":         page + "/drop#" + strings.Replace(frag, "i="+id, "i=", 1),
		"short id":           page + "/drop#" + strings.Replace(frag, "i="+id, "i=abc", 1),
		"bad key":            page + "/drop#" + strings.Replace(frag, "&k=", "&k=x", 1),
		"bad retention":      page + "/drop#" + strings.Replace(frag, "t=until-revoked", "t=forever", 1),
		"bad relay scheme":   page + "/drop#" + frag + "&r=ftp%3A%2F%2Fx",
		"relay with path":    page + "/drop#" + frag + "&r=https%3A%2F%2Fx%2Fpath",
		"malformed escape":   page + "/drop#" + strings.Replace(frag, "n=", "n=%zz", 1),
		"field without eq":   page + "/drop#" + frag + "&novalue",
		"long name":          page + "/drop#" + strings.Replace(frag, "n=openai-api-key", "n="+strings.Repeat("a", 101), 1),
		"control in name":    page + "/drop#" + strings.Replace(frag, "n=openai-api-key", "n=a%00b", 1),
		"reveal bad c":       strings.Replace(mustBuild(t, sampleReveal()), "&c=1", "&c=2", 1),
		"reveal missing c":   strings.Replace(mustBuild(t, sampleReveal()), "&c=1", "", 1),
		"reveal drop fields": mustBuild(t, sampleReveal()) + "&t=session",
		"too long":           page + "/drop#" + frag + "&p=" + strings.Repeat("a", 9000),
	}
	for name, raw := range cases {
		if _, err := Parse(raw); !errors.Is(err, ErrLink) {
			t.Fatalf("%s: got %v, want ErrLink", name, err)
		}
	}
}

func mustBuild(t *testing.T, r Reveal) string {
	t.Helper()
	raw, err := r.Build(page)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestBuildValidation(t *testing.T) {
	d := sampleDrop()
	d.RecipientKey = key(1)[:31]
	if _, err := d.Build(page); !errors.Is(err, ErrLink) {
		t.Fatal("short key accepted")
	}
	d = sampleDrop()
	if _, err := d.Build("http://drop.example.com"); !errors.Is(err, ErrLink) {
		t.Fatal("http page origin accepted")
	}
	if _, err := d.Build("http://localhost:8080"); err != nil {
		t.Fatalf("localhost http should be allowed: %v", err)
	}
	d.Relay = "https://relay.example.com/api"
	if _, err := d.Build(page); !errors.Is(err, ErrLink) {
		t.Fatal("relay with path accepted")
	}
	r := sampleReveal()
	r.Name = ""
	if _, err := r.Build(page); !errors.Is(err, ErrLink) {
		t.Fatal("empty name accepted")
	}
}

func TestNormalizeOrigin(t *testing.T) {
	ok := map[string]string{
		"https://Example.com":        "https://example.com",
		"https://example.com/":       "https://example.com",
		"https://example.com:8443":   "https://example.com:8443",
		"http://localhost:3000":      "http://localhost:3000",
		"http://127.0.0.1":           "http://127.0.0.1",
		"https://[2001:db8::1]:443":  "https://[2001:db8::1]",
		"https://example.com:443/":   "https://example.com",
		"http://localhost:80":        "http://localhost",
		"http://localhost:8080":      "http://localhost:8080",
		"https://sub.example.co.uk/": "https://sub.example.co.uk",
	}
	for in, want := range ok {
		got, err := NormalizeOrigin(in)
		if err != nil || got != want {
			t.Fatalf("%s: got %q %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "example.com", "http://example.com", "https://", "https://example.com/path", "https://example.com?x=1", "https://example.com#f", "https://u:p@example.com", "ftp://example.com", "https://" + strings.Repeat("a", 600)} {
		if _, err := NormalizeOrigin(bad); !errors.Is(err, ErrLink) {
			t.Fatalf("%q accepted", bad)
		}
	}
}

func TestLinkLengthIsReasonable(t *testing.T) {
	raw, _ := sampleDrop().Build(page)
	if len(raw) > 400 {
		t.Fatalf("drop link unexpectedly long: %d", len(raw))
	}
	raw, _ = sampleReveal().Build(page)
	if len(raw) > 250 {
		t.Fatalf("reveal link unexpectedly long: %d", len(raw))
	}
}

func TestRelayOriginFallback(t *testing.T) {
	if (Drop{}).RelayOrigin("https://page.example") != "https://page.example" || (Drop{Relay: "https://r.example"}).RelayOrigin("https://page.example") != "https://r.example" {
		t.Fatal("drop relay origin")
	}
	if (Reveal{}).RelayOrigin("https://page.example") != "https://page.example" || (Reveal{Relay: "https://r.example"}).RelayOrigin("https://page.example") != "https://r.example" {
		t.Fatal("reveal relay origin")
	}
}
