package crypto

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

// Limits on envelope text fields. Section 5.6.
const (
	MaxNameLen = 100
	MaxTextLen = 200
)

// Envelope types and formats.
const (
	TypeDrop   = "drop"
	TypeReveal = "reveal"

	FormatText   = "text"
	FormatBase64 = "base64"

	RetentionSession      = "session"
	RetentionUntilRevoked = "until-revoked"
	RetentionUntilPrefix  = "until:"
)

// ErrEnvelope is returned for a malformed envelope.
var ErrEnvelope = errors.New("crypto: invalid envelope")

var fingerprintRe = regexp.MustCompile(`^[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}$`)

// Envelope is the plaintext structure that is padded and encrypted. Section 5.5.
//
// For drops, the browser fills in the metadata it displayed (name, purpose,
// storage, retention, fingerprint) so the agent can verify that the human saw
// exactly what the agent asked for. For reveals only name, format and secret
// are set; the display fields travel as additional data instead.
type Envelope struct {
	V           int    `json:"v"`
	Type        string `json:"type"`
	Name        string `json:"name"`
	Purpose     string `json:"purpose,omitempty"`
	Storage     string `json:"storage,omitempty"`
	Retention   string `json:"retention,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Format      string `json:"format"`
	Secret      string `json:"secret"`
}

// Validate checks every field against the specification.
func (e Envelope) Validate() error {
	if e.V != 1 {
		return fmt.Errorf("%w: unsupported version %d", ErrEnvelope, e.V)
	}
	switch e.Type {
	case TypeDrop, TypeReveal:
	default:
		return fmt.Errorf("%w: unknown type", ErrEnvelope)
	}
	switch e.Format {
	case FormatText, FormatBase64:
	default:
		return fmt.Errorf("%w: unknown format", ErrEnvelope)
	}
	if err := ValidateName(e.Name); err != nil {
		return err
	}
	if err := ValidateText("purpose", e.Purpose); err != nil {
		return err
	}
	if err := ValidateText("storage", e.Storage); err != nil {
		return err
	}
	if e.Type == TypeDrop {
		if err := ValidateRetention(e.Retention); err != nil {
			return err
		}
		if !fingerprintRe.MatchString(e.Fingerprint) {
			return fmt.Errorf("%w: malformed fingerprint", ErrEnvelope)
		}
	} else {
		if e.Retention != "" || e.Fingerprint != "" || e.Purpose != "" || e.Storage != "" {
			return fmt.Errorf("%w: reveal envelopes carry no drop metadata", ErrEnvelope)
		}
	}
	if e.Format == FormatBase64 {
		if _, err := Encoding.DecodeString(e.Secret); err != nil {
			return fmt.Errorf("%w: secret is not base64url", ErrEnvelope)
		}
	} else if !utf8.ValidString(e.Secret) {
		return fmt.Errorf("%w: secret is not valid UTF-8", ErrEnvelope)
	}
	return nil
}

// Encode validates and serializes the envelope as compact JSON without HTML
// escaping. The output is stable for a given envelope in Go, but consumers in
// other languages only need to parse it as JSON.
func (e Envelope) Encode() ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(e); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// DecodeEnvelope parses and validates an envelope. Unknown fields are rejected.
func DecodeEnvelope(b []byte) (Envelope, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var e Envelope
	if err := dec.Decode(&e); err != nil {
		return Envelope{}, fmt.Errorf("%w: %v", ErrEnvelope, err)
	}
	if dec.More() {
		return Envelope{}, fmt.Errorf("%w: trailing data", ErrEnvelope)
	}
	if err := e.Validate(); err != nil {
		return Envelope{}, err
	}
	return e, nil
}

// SecretBytes returns the secret as raw bytes, decoding base64 if needed.
func (e Envelope) SecretBytes() ([]byte, error) {
	if e.Format == FormatBase64 {
		return Encoding.DecodeString(e.Secret)
	}
	return []byte(e.Secret), nil
}

// ValidateName checks a secret reference name: 1 to MaxNameLen characters,
// printable, no control characters, no leading or trailing whitespace.
func ValidateName(name string) error {
	if name == "" || utf8.RuneCountInString(name) > MaxNameLen {
		return fmt.Errorf("%w: name must be 1 to %d characters", ErrEnvelope, MaxNameLen)
	}
	if strings.TrimSpace(name) != name {
		return fmt.Errorf("%w: name has leading or trailing whitespace", ErrEnvelope)
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%w: name contains a control character", ErrEnvelope)
		}
	}
	return nil
}

// ValidateText checks a display text field (purpose, storage): at most
// MaxTextLen characters, valid UTF-8, no control characters except newline.
func ValidateText(field, s string) error {
	if utf8.RuneCountInString(s) > MaxTextLen {
		return fmt.Errorf("%w: %s longer than %d characters", ErrEnvelope, field, MaxTextLen)
	}
	if !utf8.ValidString(s) {
		return fmt.Errorf("%w: %s is not valid UTF-8", ErrEnvelope, field)
	}
	for _, r := range s {
		if (r < 0x20 && r != '\n') || r == 0x7f {
			return fmt.Errorf("%w: %s contains a control character", ErrEnvelope, field)
		}
	}
	return nil
}

// ValidateRetention accepts "session", "until-revoked", or "until:<RFC 3339>".
func ValidateRetention(r string) error {
	switch {
	case r == RetentionSession, r == RetentionUntilRevoked:
		return nil
	case strings.HasPrefix(r, RetentionUntilPrefix):
		if _, err := time.Parse(time.RFC3339, strings.TrimPrefix(r, RetentionUntilPrefix)); err != nil {
			return fmt.Errorf("%w: retention date is not RFC 3339", ErrEnvelope)
		}
		return nil
	default:
		return fmt.Errorf("%w: unknown retention policy", ErrEnvelope)
	}
}

// RevealAAD builds the additional data for a reveal: the display fields the
// page shows, joined with newlines behind a fixed domain string, so a link
// whose display fields were altered fails to decrypt. Section 5.6.
func RevealAAD(dropID, name string, keepsCopy bool) []byte {
	c := "0"
	if keepsCopy {
		c = "1"
	}
	return []byte("burndrop/reveal/v1\n" + dropID + "\n" + name + "\n" + c)
}
