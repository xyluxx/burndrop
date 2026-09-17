package crypto

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
)

func dropEnvelope(secret string) Envelope {
	return Envelope{
		V: 1, Type: TypeDrop, Name: "openai-api-key",
		Purpose: "Call the OpenAI API from the billing script", Storage: "macOS Keychain",
		Retention: RetentionUntilRevoked, Fingerprint: "a1b2-c3d4-e5f6-a7b8",
		Format: FormatText, Secret: secret,
	}
}

func revealEnvelope(secret string) Envelope {
	return Envelope{V: 1, Type: TypeReveal, Name: "staging-db-url", Format: FormatText, Secret: secret}
}

func TestSealedBoxRoundTrip(t *testing.T) {
	pub, priv, err := GenerateKeyPair(nil)
	if err != nil {
		t.Fatal(err)
	}
	env := dropEnvelope("sk-live-0123456789")
	sealed, err := SealEnvelope(pub, env, nil)
	if err != nil {
		t.Fatal(err)
	}
	plain, _ := env.Encode()
	wantLen := len(Pad(plain, PadBlock)) + SealedOverhead
	if len(sealed) != wantLen {
		t.Fatalf("sealed length %d, want %d", len(sealed), wantLen)
	}
	got, err := OpenEnvelope(pub, priv, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if got != env {
		t.Fatalf("round trip mismatch: %+v", got)
	}
}

func TestSealedBoxRejectsTamperAndWrongKey(t *testing.T) {
	pub, priv, _ := GenerateKeyPair(nil)
	sealed, err := SealEnvelope(pub, dropEnvelope("secret"), nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(sealed); i += 7 {
		bad := append([]byte(nil), sealed...)
		bad[i] ^= 0x01
		if _, err := OpenEnvelope(pub, priv, bad); !errors.Is(err, ErrDecrypt) {
			t.Fatalf("byte %d tampered: got %v, want ErrDecrypt", i, err)
		}
	}
	pub2, priv2, _ := GenerateKeyPair(nil)
	if _, err := OpenEnvelope(pub2, priv2, sealed); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("wrong key: got %v", err)
	}
	if _, err := OpenSealed(pub, priv, sealed[:SealedOverhead-1]); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("short input: got %v", err)
	}
	if _, err := OpenSealed(pub, priv, nil); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("nil input: got %v", err)
	}
}

func TestSealedBoxDifferentEachTime(t *testing.T) {
	pub, _, _ := GenerateKeyPair(nil)
	a, _ := Seal(pub, []byte("same"), nil)
	b, _ := Seal(pub, []byte("same"), nil)
	if bytes.Equal(a, b) {
		t.Fatal("two seals of the same plaintext must differ (fresh ephemeral key)")
	}
}

func TestAEADRoundTripAndAAD(t *testing.T) {
	key, err := NewSymmetricKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	env := revealEnvelope("postgres://user:pass@host/db")
	aad := RevealAAD("staging-db-url", false)
	blob, err := EncryptEnvelope(key, env, aad, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecryptEnvelope(key, blob, aad)
	if err != nil {
		t.Fatal(err)
	}
	if got != env {
		t.Fatalf("round trip mismatch: %+v", got)
	}
	// Altered display fields (different AAD) must fail.
	if _, err := DecryptEnvelope(key, blob, RevealAAD("staging-db-url", true)); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("aad mismatch: got %v", err)
	}
	if _, err := DecryptEnvelope(key, blob, RevealAAD("prod-db-url", false)); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("aad name mismatch: got %v", err)
	}
	// Tampered blob must fail.
	for i := 0; i < len(blob); i += 5 {
		bad := append([]byte(nil), blob...)
		bad[i] ^= 0x80
		if _, err := DecryptEnvelope(key, bad, aad); !errors.Is(err, ErrDecrypt) {
			t.Fatalf("byte %d tampered: got %v", i, err)
		}
	}
	// Wrong key must fail.
	other, _ := NewSymmetricKey(nil)
	if _, err := DecryptEnvelope(other, blob, aad); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("wrong key: got %v", err)
	}
	if _, err := DecryptAEAD(key, blob[:AEADOverhead-1], aad); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("short blob: got %v", err)
	}
}

func TestPadding(t *testing.T) {
	cases := []int{0, 1, 2, 100, 255, 256, 257, 511, 512, 1000}
	for _, n := range cases {
		in := bytes.Repeat([]byte{0xAB}, n)
		padded := Pad(in, PadBlock)
		if len(padded)%PadBlock != 0 {
			t.Fatalf("n=%d: padded length %d not a multiple of %d", n, len(padded), PadBlock)
		}
		if len(padded) <= n {
			t.Fatalf("n=%d: padding must add at least one byte", n)
		}
		if len(padded)-n > PadBlock {
			t.Fatalf("n=%d: padding added more than one block", n)
		}
		if padded[n] != 0x80 {
			t.Fatalf("n=%d: marker byte missing", n)
		}
		out, err := Unpad(padded, PadBlock)
		if err != nil || !bytes.Equal(out, in) {
			t.Fatalf("n=%d: unpad failed: %v", n, err)
		}
	}
	// Aligned input grows by exactly one block, like sodium_pad.
	if got := len(Pad(make([]byte, 256), 256)); got != 512 {
		t.Fatalf("aligned input padded to %d, want 512", got)
	}
	bad := [][]byte{
		nil,
		make([]byte, 255),               // not block aligned
		make([]byte, 256),               // all zeros, no marker
		append(make([]byte, 255), 0x01), // wrong marker
	}
	for i, b := range bad {
		if _, err := Unpad(b, PadBlock); !errors.Is(err, ErrPadding) {
			t.Fatalf("case %d: got %v, want ErrPadding", i, err)
		}
	}
	// Marker at position 0 followed by zeros is a valid encoding of the empty message.
	if out, err := Unpad(append([]byte{0x80}, make([]byte, 255)...), PadBlock); err != nil || len(out) != 0 {
		t.Fatalf("empty message: %v %d", err, len(out))
	}
	// A marker further back than one block must not be found.
	far := make([]byte, 512)
	far[100] = 0x80
	if _, err := Unpad(far, PadBlock); !errors.Is(err, ErrPadding) {
		t.Fatalf("far marker: got %v", err)
	}
}

func TestFingerprintAndCommitment(t *testing.T) {
	pub := bytes.Repeat([]byte{0x42}, KeySize)
	fp := Fingerprint(pub)
	if !fingerprintRe.MatchString(fp) {
		t.Fatalf("fingerprint format: %q", fp)
	}
	sum := sha256.Sum256(pub)
	want := strings.ToLower(strings.ReplaceAll(fp, "-", ""))
	if got := hexOf(sum[:8]); got != want {
		t.Fatalf("fingerprint bytes: %s vs %s", got, want)
	}
	if c := Commitment(pub); c != Encoding.EncodeToString(sum[:]) || !ValidCommitment(c) {
		t.Fatalf("commitment: %q", c)
	}
	if ValidCommitment("short") || ValidCommitment(strings.Repeat("A", 44)) {
		t.Fatal("malformed commitments accepted")
	}
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, x := range b {
		out = append(out, digits[x>>4], digits[x&0x0f])
	}
	return string(out)
}

func TestTokens(t *testing.T) {
	seen := make(map[string]struct{}, 100000)
	for i := 0; i < 100000; i++ {
		tok, err := RandomToken()
		if err != nil {
			t.Fatal(err)
		}
		if !ValidToken(tok) {
			t.Fatalf("token %q is not well formed", tok)
		}
		if _, dup := seen[tok]; dup {
			t.Fatalf("duplicate token after %d draws", i)
		}
		seen[tok] = struct{}{}
	}
	for _, bad := range []string{"", "short", strings.Repeat("A", 21), strings.Repeat("A", 23), strings.Repeat("A", 22)[:21] + "=", "AAAAAAAAAAAAAAAAAAAA+/"} {
		if ValidToken(bad) {
			t.Fatalf("malformed token accepted: %q", bad)
		}
	}
	// 22 characters of base64url can encode 132 bits; the last character must
	// leave the trailing 4 bits zero to decode to exactly 16 bytes. "AAAAAAAAAAAAAAAAAAAAAB"
	// has a non-zero trailing bit pattern and is rejected by strict decoding.
	if ValidToken("AAAAAAAAAAAAAAAAAAAAAB") {
		t.Fatal("token with non-canonical trailing bits accepted")
	}
	a := HashToken("abc")
	b := HashToken("abc")
	c := HashToken("abd")
	if !HashEqual(a, b) || HashEqual(a, c) {
		t.Fatal("hash equality broken")
	}
	parsed, err := ParseHash(a.Encode())
	if err != nil || !HashEqual(parsed, a) {
		t.Fatalf("hash encode/parse: %v", err)
	}
	if _, err := ParseHash("nope"); err == nil {
		t.Fatal("malformed hash parsed")
	}
	key, err := RandomAgentKey()
	if err != nil || len(key) != 43 {
		t.Fatalf("agent key: %v %d", err, len(key))
	}
}

func TestEnvelopeValidation(t *testing.T) {
	good := dropEnvelope("x")
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	mutate := func(f func(e *Envelope)) Envelope { e := good; f(&e); return e }
	bad := map[string]Envelope{
		"version":            mutate(func(e *Envelope) { e.V = 2 }),
		"type":               mutate(func(e *Envelope) { e.Type = "other" }),
		"format":             mutate(func(e *Envelope) { e.Format = "hex" }),
		"empty name":         mutate(func(e *Envelope) { e.Name = "" }),
		"long name":          mutate(func(e *Envelope) { e.Name = strings.Repeat("n", 101) }),
		"padded name":        mutate(func(e *Envelope) { e.Name = " x" }),
		"control in name":    mutate(func(e *Envelope) { e.Name = "a\x00b" }),
		"long purpose":       mutate(func(e *Envelope) { e.Purpose = strings.Repeat("p", 201) }),
		"control in storage": mutate(func(e *Envelope) { e.Storage = "a\x07b" }),
		"retention":          mutate(func(e *Envelope) { e.Retention = "forever" }),
		"retention date":     mutate(func(e *Envelope) { e.Retention = "until:tomorrow" }),
		"fingerprint":        mutate(func(e *Envelope) { e.Fingerprint = "A1B2-C3D4-E5F6-A7B8" }),
		"bad base64":         mutate(func(e *Envelope) { e.Format = FormatBase64; e.Secret = "not base64!" }),
		"invalid utf8":       mutate(func(e *Envelope) { e.Secret = "\xff\xfe" }),
		"reveal with meta":   {V: 1, Type: TypeReveal, Name: "n", Format: FormatText, Secret: "s", Purpose: "p"},
	}
	for name, e := range bad {
		if err := e.Validate(); err == nil {
			t.Fatalf("%s: expected validation error", name)
		}
	}
	ok := mutate(func(e *Envelope) { e.Retention = "until:2027-01-02T03:04:05Z" })
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := revealEnvelope("s").Validate(); err != nil {
		t.Fatal(err)
	}
	b64 := Envelope{V: 1, Type: TypeReveal, Name: "cert", Format: FormatBase64, Secret: Encoding.EncodeToString([]byte{0, 1, 2})}
	raw, err := b64.SecretBytes()
	if err != nil || !bytes.Equal(raw, []byte{0, 1, 2}) {
		t.Fatalf("secret bytes: %v %v", raw, err)
	}
}

func TestEnvelopeEncodeDecode(t *testing.T) {
	env := dropEnvelope("value with <html> & \"quotes\" and unicode é")
	b, err := env.Encode()
	if err != nil {
		t.Fatal(err)
	}
	// The JSON encoder must not turn < > & into unicode escapes: other
	// languages parse either form, but stable bytes keep vectors simple.
	escaped := string(rune(92)) + "u003c" // backslash u003c
	if bytes.Contains(b, []byte(escaped)) || !bytes.Contains(b, []byte("<html>")) {
		t.Fatal("HTML escaping must be off")
	}
	got, err := DecodeEnvelope(b)
	if err != nil || got != env {
		t.Fatalf("decode: %v %+v", err, got)
	}
	for name, raw := range map[string]string{
		"unknown field": `{"v":1,"type":"reveal","name":"n","format":"text","secret":"s","extra":1}`,
		"trailing":      `{"v":1,"type":"reveal","name":"n","format":"text","secret":"s"} {}`,
		"not json":      `hello`,
		"wrong version": `{"v":2,"type":"reveal","name":"n","format":"text","secret":"s"}`,
	} {
		if _, err := DecodeEnvelope([]byte(raw)); !errors.Is(err, ErrEnvelope) {
			t.Fatalf("%s: got %v", name, err)
		}
	}
}

func TestSizeLimits(t *testing.T) {
	pub, priv, _ := GenerateKeyPair(nil)
	big := dropEnvelope(strings.Repeat("x", MaxPlaintext))
	if _, err := SealEnvelope(pub, big, nil); !errors.Is(err, ErrSize) {
		t.Fatalf("oversized envelope sealed: %v", err)
	}
	if _, err := OpenEnvelope(pub, priv, make([]byte, MaxPlaintext+PadBlock+SealedOverhead+1)); !errors.Is(err, ErrSize) {
		t.Fatalf("oversized sealed accepted: %v", err)
	}
	key, _ := NewSymmetricKey(nil)
	if _, err := EncryptEnvelope(key, revealEnvelope(strings.Repeat("x", MaxPlaintext)), nil, nil); !errors.Is(err, ErrSize) {
		t.Fatalf("oversized reveal encrypted: %v", err)
	}
	// The largest accepted secret still works.
	largest := revealEnvelope(strings.Repeat("y", MaxPlaintext-200))
	blob, err := EncryptEnvelope(key, largest, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecryptEnvelope(key, blob, nil); err != nil {
		t.Fatal(err)
	}
}

func TestZero(t *testing.T) {
	k, _ := NewSymmetricKey(nil)
	ZeroKey(k)
	if !bytes.Equal(k[:], make([]byte, KeySize)) {
		t.Fatal("key not zeroed")
	}
	if _, err := KeyFromBytes(make([]byte, 31)); !errors.Is(err, ErrLength) {
		t.Fatal("short key accepted")
	}
}

func TestRevealAAD(t *testing.T) {
	a := RevealAAD("name", true)
	if string(a) != "burndrop/reveal/v1\nname\n1" {
		t.Fatalf("aad: %q", a)
	}
	if bytes.Equal(a, RevealAAD("name", false)) {
		t.Fatal("keeps_copy must change the aad")
	}
}
