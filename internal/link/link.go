// Package link builds and parses burndrop links.
//
// Everything a client needs travels after the # in the URL, so no server, proxy,
// or link scanner ever receives an identifier, a token, or a key. See
// docs/crypto-spec.md section 5.6 for the format. Parsing is strict: the
// version must be 1, every required field must be present exactly once, no
// unknown fields are allowed, binary fields must have their exact length, and
// text fields are bounded.
package link

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/burndrop/burndrop/internal/crypto"
)

// Link kinds and page paths.
const (
	Version    = "1"
	KindDrop   = "drop"
	KindReveal = "reveal"
	PathDrop   = "/drop"
	PathReveal = "/reveal"
)

// ErrLink is wrapped by every parse or build error.
var ErrLink = errors.New("link: invalid link")

// Drop is a human-to-agent link: the agent's request public key plus what the
// page must display.
type Drop struct {
	Relay        string // relay origin; empty means "same as the page origin"
	ID           string
	UploadToken  string
	RecipientKey []byte // 32 bytes
	Name         string
	Purpose      string
	Storage      string
	Retention    string
}

// Reveal is an agent-to-human link: the reveal token and the decryption key.
type Reveal struct {
	Relay       string
	ID          string
	RevealToken string
	Key         []byte // 32 bytes
	Name        string
	KeepsCopy   bool
}

// Parsed is the result of Parse: exactly one of Drop or Reveal is set.
type Parsed struct {
	Kind       string
	PageOrigin string
	Drop       *Drop
	Reveal     *Reveal
}

// Validate checks every field of a drop link.
func (d Drop) Validate() error {
	if d.Relay != "" {
		if _, err := NormalizeOrigin(d.Relay); err != nil {
			return err
		}
	}
	if !crypto.ValidToken(d.ID) {
		return fmt.Errorf("%w: malformed drop id", ErrLink)
	}
	if !crypto.ValidToken(d.UploadToken) {
		return fmt.Errorf("%w: malformed upload token", ErrLink)
	}
	if len(d.RecipientKey) != crypto.KeySize {
		return fmt.Errorf("%w: recipient key must be %d bytes", ErrLink, crypto.KeySize)
	}
	if err := crypto.ValidateName(d.Name); err != nil {
		return fmt.Errorf("%w: %v", ErrLink, err)
	}
	if err := crypto.ValidateText("purpose", d.Purpose); err != nil {
		return fmt.Errorf("%w: %v", ErrLink, err)
	}
	if err := crypto.ValidateText("storage", d.Storage); err != nil {
		return fmt.Errorf("%w: %v", ErrLink, err)
	}
	if err := crypto.ValidateRetention(d.Retention); err != nil {
		return fmt.Errorf("%w: %v", ErrLink, err)
	}
	return nil
}

// Build returns the full link for a page served at pageOrigin.
func (d Drop) Build(pageOrigin string) (string, error) {
	if err := d.Validate(); err != nil {
		return "", err
	}
	origin, err := NormalizeOrigin(pageOrigin)
	if err != nil {
		return "", err
	}
	fields := []field{
		{"v", Version},
		{"i", d.ID},
		{"u", d.UploadToken},
		{"k", crypto.Encoding.EncodeToString(d.RecipientKey)},
		{"n", d.Name},
		{"p", d.Purpose},
		{"s", d.Storage},
		{"t", d.Retention},
	}
	if d.Relay != "" {
		relay, _ := NormalizeOrigin(d.Relay)
		fields = append(fields, field{"r", relay})
	}
	return origin + PathDrop + "#" + encodeFields(fields), nil
}

// Fingerprint returns the fingerprint of the recipient key.
func (d Drop) Fingerprint() string {
	return crypto.Fingerprint(d.RecipientKey)
}

// Validate checks every field of a reveal link.
func (r Reveal) Validate() error {
	if r.Relay != "" {
		if _, err := NormalizeOrigin(r.Relay); err != nil {
			return err
		}
	}
	if !crypto.ValidToken(r.ID) {
		return fmt.Errorf("%w: malformed drop id", ErrLink)
	}
	if !crypto.ValidToken(r.RevealToken) {
		return fmt.Errorf("%w: malformed reveal token", ErrLink)
	}
	if len(r.Key) != crypto.KeySize {
		return fmt.Errorf("%w: key must be %d bytes", ErrLink, crypto.KeySize)
	}
	if err := crypto.ValidateName(r.Name); err != nil {
		return fmt.Errorf("%w: %v", ErrLink, err)
	}
	return nil
}

// Build returns the full link for a page served at pageOrigin.
func (r Reveal) Build(pageOrigin string) (string, error) {
	if err := r.Validate(); err != nil {
		return "", err
	}
	origin, err := NormalizeOrigin(pageOrigin)
	if err != nil {
		return "", err
	}
	c := "0"
	if r.KeepsCopy {
		c = "1"
	}
	fields := []field{
		{"v", Version},
		{"i", r.ID},
		{"o", r.RevealToken},
		{"k", crypto.Encoding.EncodeToString(r.Key)},
		{"n", r.Name},
		{"c", c},
	}
	if r.Relay != "" {
		relay, _ := NormalizeOrigin(r.Relay)
		fields = append(fields, field{"r", relay})
	}
	return origin + PathReveal + "#" + encodeFields(fields), nil
}

// AAD returns the additional data that authenticates the display fields.
func (r Reveal) AAD() []byte {
	return crypto.RevealAAD(r.ID, r.Name, r.KeepsCopy)
}

// Parse parses either kind of link.
func Parse(raw string) (Parsed, error) {
	origin, path, frag, err := split(raw)
	if err != nil {
		return Parsed{}, err
	}
	switch path {
	case PathDrop:
		d, err := parseDrop(frag)
		if err != nil {
			return Parsed{}, err
		}
		return Parsed{Kind: KindDrop, PageOrigin: origin, Drop: &d}, nil
	case PathReveal:
		r, err := parseReveal(frag)
		if err != nil {
			return Parsed{}, err
		}
		return Parsed{Kind: KindReveal, PageOrigin: origin, Reveal: &r}, nil
	default:
		return Parsed{}, fmt.Errorf("%w: path must be %s or %s", ErrLink, PathDrop, PathReveal)
	}
}

// ParseDrop parses a drop link and returns it with the page origin.
func ParseDrop(raw string) (Drop, string, error) {
	p, err := Parse(raw)
	if err != nil {
		return Drop{}, "", err
	}
	if p.Kind != KindDrop {
		return Drop{}, "", fmt.Errorf("%w: not a drop link", ErrLink)
	}
	return *p.Drop, p.PageOrigin, nil
}

// ParseReveal parses a reveal link and returns it with the page origin.
func ParseReveal(raw string) (Reveal, string, error) {
	p, err := Parse(raw)
	if err != nil {
		return Reveal{}, "", err
	}
	if p.Kind != KindReveal {
		return Reveal{}, "", fmt.Errorf("%w: not a reveal link", ErrLink)
	}
	return *p.Reveal, p.PageOrigin, nil
}

// RelayOrigin returns the relay a client should talk to: the explicit relay
// field if present, otherwise the page origin.
func (p Parsed) RelayOrigin() string {
	switch p.Kind {
	case KindDrop:
		if p.Drop.Relay != "" {
			return p.Drop.Relay
		}
	case KindReveal:
		if p.Reveal.Relay != "" {
			return p.Reveal.Relay
		}
	}
	return p.PageOrigin
}

// NormalizeOrigin validates an origin and returns it as scheme://host[:port]
// in lowercase. Only https is accepted, except http for localhost and loopback
// addresses so local development works.
func NormalizeOrigin(s string) (string, error) {
	if len(s) > 512 {
		return "", fmt.Errorf("%w: origin too long", ErrLink)
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", fmt.Errorf("%w: origin: %v", ErrLink, err)
	}
	if u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", fmt.Errorf("%w: origin must be scheme://host[:port] only", ErrLink)
	}
	host := strings.ToLower(u.Host)
	if u.Hostname() == "" {
		return "", fmt.Errorf("%w: origin has no host", ErrLink)
	}
	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "https":
	case "http":
		h := strings.ToLower(u.Hostname())
		if h != "localhost" && h != "127.0.0.1" && h != "::1" {
			return "", fmt.Errorf("%w: http is only allowed for localhost", ErrLink)
		}
	default:
		return "", fmt.Errorf("%w: origin scheme must be https", ErrLink)
	}
	return scheme + "://" + host, nil
}

type field struct{ key, value string }

func encodeFields(fields []field) string {
	var b strings.Builder
	for i, f := range fields {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(f.key)
		b.WriteByte('=')
		b.WriteString(url.QueryEscape(f.value))
	}
	return b.String()
}

// split separates a raw link into page origin, path, and the raw fragment.
// The fragment is taken from the raw string so that percent-encoded field
// separators are not decoded prematurely.
func split(raw string) (origin, path, frag string, err error) {
	if len(raw) > 8192 {
		return "", "", "", fmt.Errorf("%w: link too long", ErrLink)
	}
	hash := strings.IndexByte(raw, '#')
	if hash < 0 {
		return "", "", "", fmt.Errorf("%w: no fragment", ErrLink)
	}
	base, frag := raw[:hash], raw[hash+1:]
	u, err := url.Parse(base)
	if err != nil {
		return "", "", "", fmt.Errorf("%w: %v", ErrLink, err)
	}
	if u.RawQuery != "" || u.User != nil {
		return "", "", "", fmt.Errorf("%w: links carry no query string or userinfo", ErrLink)
	}
	origin, err = NormalizeOrigin(u.Scheme + "://" + u.Host)
	if err != nil {
		return "", "", "", err
	}
	return origin, strings.TrimSuffix(u.Path, "/"), frag, nil
}

func parseFields(frag string, allowed []string) (map[string]string, error) {
	out := make(map[string]string, len(allowed))
	if frag == "" {
		return nil, fmt.Errorf("%w: empty fragment", ErrLink)
	}
	for _, part := range strings.Split(frag, "&") {
		eq := strings.IndexByte(part, '=')
		if eq <= 0 {
			return nil, fmt.Errorf("%w: malformed field %q", ErrLink, part)
		}
		key := part[:eq]
		known := false
		for _, a := range allowed {
			if a == key {
				known = true
				break
			}
		}
		if !known {
			return nil, fmt.Errorf("%w: unknown field %q", ErrLink, key)
		}
		if _, dup := out[key]; dup {
			return nil, fmt.Errorf("%w: duplicate field %q", ErrLink, key)
		}
		value, err := url.QueryUnescape(part[eq+1:])
		if err != nil {
			return nil, fmt.Errorf("%w: field %q: %v", ErrLink, key, err)
		}
		out[key] = value
	}
	if out["v"] != Version {
		return nil, fmt.Errorf("%w: unsupported link version %q", ErrLink, out["v"])
	}
	return out, nil
}

func require(m map[string]string, keys ...string) error {
	for _, k := range keys {
		if m[k] == "" {
			return fmt.Errorf("%w: missing field %q", ErrLink, k)
		}
	}
	return nil
}

func decodeKey(s string) ([]byte, error) {
	if len(s) != 43 {
		return nil, fmt.Errorf("%w: key must be 43 base64url characters", ErrLink)
	}
	b, err := crypto.Encoding.DecodeString(s)
	if err != nil || len(b) != crypto.KeySize {
		return nil, fmt.Errorf("%w: key is not valid base64url", ErrLink)
	}
	return b, nil
}

func parseDrop(frag string) (Drop, error) {
	m, err := parseFields(frag, []string{"v", "i", "u", "k", "n", "p", "s", "t", "r"})
	if err != nil {
		return Drop{}, err
	}
	if err := require(m, "i", "u", "k", "n", "t"); err != nil {
		return Drop{}, err
	}
	key, err := decodeKey(m["k"])
	if err != nil {
		return Drop{}, err
	}
	d := Drop{ID: m["i"], UploadToken: m["u"], RecipientKey: key, Name: m["n"], Purpose: m["p"], Storage: m["s"], Retention: m["t"]}
	if r := m["r"]; r != "" {
		d.Relay, err = NormalizeOrigin(r)
		if err != nil {
			return Drop{}, err
		}
	}
	if err := d.Validate(); err != nil {
		return Drop{}, err
	}
	return d, nil
}

func parseReveal(frag string) (Reveal, error) {
	m, err := parseFields(frag, []string{"v", "i", "o", "k", "n", "c", "r"})
	if err != nil {
		return Reveal{}, err
	}
	if err := require(m, "i", "o", "k", "n", "c"); err != nil {
		return Reveal{}, err
	}
	key, err := decodeKey(m["k"])
	if err != nil {
		return Reveal{}, err
	}
	var keeps bool
	switch m["c"] {
	case "0":
	case "1":
		keeps = true
	default:
		return Reveal{}, fmt.Errorf("%w: field c must be 0 or 1", ErrLink)
	}
	r := Reveal{ID: m["i"], RevealToken: m["o"], Key: key, Name: m["n"], KeepsCopy: keeps}
	if rel := m["r"]; rel != "" {
		r.Relay, err = NormalizeOrigin(rel)
		if err != nil {
			return Reveal{}, err
		}
	}
	if err := r.Validate(); err != nil {
		return Reveal{}, err
	}
	return r, nil
}
