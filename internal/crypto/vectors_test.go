package crypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

// Test vectors shared with the TypeScript and Python modules. Regenerate with:
//
//	go test ./internal/crypto -run TestVectors -update
//
// Every consumer must be able to open, decrypt, unpad, and parse these
// exactly. Sealed boxes are randomized, so the sealed vectors are produced
// with a deterministic reader and consumed as decryption vectors.

var update = flag.Bool("update", false, "rewrite spec/vectors.json")

const vectorsPath = "../../spec/vectors.json"

type sealedVector struct {
	Name               string `json:"name"`
	RecipientPublicKey string `json:"recipient_public_key"`
	RecipientSecretKey string `json:"recipient_secret_key"`
	Sealed             string `json:"sealed"`
	Padded             string `json:"padded_plaintext"`
	Plaintext          string `json:"plaintext"`
}

type aeadVector struct {
	Name      string `json:"name"`
	Key       string `json:"key"`
	Nonce     string `json:"nonce"`
	AAD       string `json:"aad"`
	Plaintext string `json:"plaintext"`
	Blob      string `json:"blob"`
}

type padVector struct {
	Block    int    `json:"block"`
	Unpadded string `json:"unpadded"`
	Padded   string `json:"padded"`
}

type fpVector struct {
	PublicKey   string `json:"public_key"`
	Fingerprint string `json:"fingerprint"`
	Commitment  string `json:"commitment"`
}

type envVector struct {
	Name     string   `json:"name"`
	Envelope Envelope `json:"envelope"`
	Valid    bool     `json:"valid"`
	Encoded  string   `json:"encoded,omitempty"`
}

type aadVector struct {
	Name      string `json:"name"`
	KeepsCopy bool   `json:"keeps_copy"`
	AAD       string `json:"aad"`
}

type tokenVector struct {
	Token string `json:"token"`
	Hash  string `json:"sha256"`
	Valid bool   `json:"valid"`
}

type vectors struct {
	Version     int            `json:"version"`
	Description string         `json:"description"`
	PadBlock    int            `json:"pad_block"`
	Sealed      []sealedVector `json:"sealed_box"`
	AEAD        []aeadVector   `json:"xchacha20poly1305"`
	Padding     []padVector    `json:"padding"`
	Fingerprint []fpVector     `json:"fingerprint"`
	Envelope    []envVector    `json:"envelope"`
	RevealAAD   []aadVector    `json:"reveal_aad"`
	Tokens      []tokenVector  `json:"tokens"`
}

// detReader yields a deterministic byte stream from a seed (SHA-256 counter
// mode). Only used to make the vectors reproducible.
type detReader struct {
	seed    []byte
	counter uint64
	buf     []byte
}

func (d *detReader) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		if len(d.buf) == 0 {
			h := sha256.New()
			h.Write(d.seed)
			var c [8]byte
			for i := 0; i < 8; i++ {
				c[i] = byte(d.counter >> (8 * i))
			}
			h.Write(c[:])
			d.buf = h.Sum(nil)
			d.counter++
		}
		k := copy(p[n:], d.buf)
		d.buf = d.buf[k:]
		n += k
	}
	return n, nil
}

func enc(b []byte) string { return Encoding.EncodeToString(b) }

func dec(t *testing.T, s string) []byte {
	t.Helper()
	b, err := Encoding.DecodeString(s)
	if err != nil {
		t.Fatalf("bad base64url in vectors: %q", s)
	}
	return b
}

func generate(t *testing.T) vectors {
	t.Helper()
	v := vectors{
		Version:     1,
		Description: "burndrop cross-language test vectors. All binary fields are base64url without padding. Sealed boxes are libsodium crypto_box_seal. xchacha20poly1305 blobs are nonce || ciphertext || tag. Padding is ISO/IEC 7816-4.",
		PadBlock:    PadBlock,
	}
	envs := []struct {
		name string
		env  Envelope
	}{
		{"drop text", dropEnvelope("sk-live-0123456789abcdef")},
		{"drop unicode and json characters", dropEnvelope("päss \"quoted\" <tag> & done")},
		{"drop base64 binary", func() Envelope {
			e := dropEnvelope("")
			e.Name = "client-cert"
			e.Format = FormatBase64
			e.Secret = enc([]byte{0, 1, 2, 3, 250, 251, 252, 253, 254, 255})
			return e
		}()},
		{"drop until date", func() Envelope {
			e := dropEnvelope("temporary")
			e.Retention = "until:2027-03-04T05:06:07Z"
			return e
		}()},
		{"reveal text", revealEnvelope("postgres://app:s3cret@db.staging.example:5432/app")},
		{"reveal empty secret", revealEnvelope("")},
	}
	for i, c := range envs {
		seed := []byte("burndrop-vector-seed-" + c.name)
		rd := &detReader{seed: seed}
		if c.env.Type == TypeDrop {
			pub, priv, err := GenerateKeyPair(rd)
			if err != nil {
				t.Fatal(err)
			}
			c.env.Fingerprint = Fingerprint(pub[:])
			plain, err := c.env.Encode()
			if err != nil {
				t.Fatal(err)
			}
			padded := Pad(plain, PadBlock)
			sealed, err := Seal(pub, padded, rd)
			if err != nil {
				t.Fatal(err)
			}
			v.Sealed = append(v.Sealed, sealedVector{
				Name: c.name, RecipientPublicKey: enc(pub[:]), RecipientSecretKey: enc(priv[:]),
				Sealed: enc(sealed), Padded: enc(padded), Plaintext: enc(plain),
			})
			v.Fingerprint = append(v.Fingerprint, fpVector{PublicKey: enc(pub[:]), Fingerprint: Fingerprint(pub[:]), Commitment: Commitment(pub[:])})
		} else {
			key, err := NewSymmetricKey(rd)
			if err != nil {
				t.Fatal(err)
			}
			aad := RevealAAD(c.env.Name, i%2 == 0)
			plain, err := c.env.Encode()
			if err != nil {
				t.Fatal(err)
			}
			padded := Pad(plain, PadBlock)
			blob, err := EncryptAEAD(key, padded, aad, rd)
			if err != nil {
				t.Fatal(err)
			}
			v.AEAD = append(v.AEAD, aeadVector{
				Name: c.name, Key: enc(key[:]), Nonce: enc(blob[:NonceSize]), AAD: enc(aad),
				Plaintext: enc(padded), Blob: enc(blob),
			})
			v.RevealAAD = append(v.RevealAAD, aadVector{Name: c.env.Name, KeepsCopy: i%2 == 0, AAD: enc(aad)})
		}
		v.Envelope = append(v.Envelope, envVector{Name: c.name, Envelope: c.env, Valid: true})
	}
	// Invalid envelopes every consumer must reject.
	for _, bad := range []struct {
		name string
		env  Envelope
	}{
		{"wrong version", Envelope{V: 2, Type: TypeReveal, Name: "n", Format: FormatText, Secret: "s"}},
		{"unknown type", Envelope{V: 1, Type: "share", Name: "n", Format: FormatText, Secret: "s"}},
		{"unknown format", Envelope{V: 1, Type: TypeReveal, Name: "n", Format: "hex", Secret: "s"}},
		{"empty name", Envelope{V: 1, Type: TypeReveal, Name: "", Format: FormatText, Secret: "s"}},
		{"bad retention", Envelope{V: 1, Type: TypeDrop, Name: "n", Format: FormatText, Secret: "s", Retention: "forever", Fingerprint: "0000-0000-0000-0000"}},
		{"bad fingerprint", Envelope{V: 1, Type: TypeDrop, Name: "n", Format: FormatText, Secret: "s", Retention: "session", Fingerprint: "zzzz"}},
	} {
		v.Envelope = append(v.Envelope, envVector{Name: bad.name, Envelope: bad.env, Valid: false})
	}
	// Padding.
	for _, n := range []int{0, 1, 17, 255, 256, 257, 511, 512} {
		in := make([]byte, n)
		for i := range in {
			in[i] = byte(i*7 + 3)
		}
		v.Padding = append(v.Padding, padVector{Block: PadBlock, Unpadded: enc(in), Padded: enc(Pad(in, PadBlock))})
	}
	// Extra fingerprints for fixed keys.
	for _, b := range []byte{0x00, 0x42, 0xff} {
		pub := bytes.Repeat([]byte{b}, KeySize)
		v.Fingerprint = append(v.Fingerprint, fpVector{PublicKey: enc(pub), Fingerprint: Fingerprint(pub), Commitment: Commitment(pub)})
	}
	// Tokens.
	for _, tk := range []struct {
		s     string
		valid bool
	}{
		{"AAAAAAAAAAAAAAAAAAAAAA", true},
		{"MTIzNDU2Nzg5MGFiY2RlZg", true},
		{"AAAAAAAAAAAAAAAAAAAAAB", false},
		{"AAAAAAAAAAAAAAAAAAAAA", false},
		{"AAAAAAAAAAAAAAAAAAAAAAA", false},
		{"AAAAAAAAAAAAAAAAAAAA+/", false},
		{"", false},
	} {
		h := HashToken(tk.s)
		v.Tokens = append(v.Tokens, tokenVector{Token: tk.s, Hash: h.Encode(), Valid: tk.valid})
	}
	return v
}

func TestVectors(t *testing.T) {
	if *update {
		v := generate(t)
		b, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(vectorsPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(vectorsPath, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s", vectorsPath)
	}
	raw, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("read vectors (run with -update to generate): %v", err)
	}
	var v vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if v.Version != 1 || v.PadBlock != PadBlock {
		t.Fatalf("vector header mismatch: %+v", v.Version)
	}
	if len(v.Sealed) == 0 || len(v.AEAD) == 0 || len(v.Padding) == 0 || len(v.Envelope) == 0 {
		t.Fatal("vectors incomplete")
	}
	for _, s := range v.Sealed {
		pub, _ := KeyFromBytes(dec(t, s.RecipientPublicKey))
		priv, _ := KeyFromBytes(dec(t, s.RecipientSecretKey))
		padded, err := OpenSealed(pub, priv, dec(t, s.Sealed))
		if err != nil {
			t.Fatalf("%s: open: %v", s.Name, err)
		}
		if !bytes.Equal(padded, dec(t, s.Padded)) {
			t.Fatalf("%s: padded mismatch", s.Name)
		}
		plain, err := Unpad(padded, PadBlock)
		if err != nil || !bytes.Equal(plain, dec(t, s.Plaintext)) {
			t.Fatalf("%s: unpad: %v", s.Name, err)
		}
		if _, err := DecodeEnvelope(plain); err != nil {
			t.Fatalf("%s: envelope: %v", s.Name, err)
		}
		if _, err := OpenEnvelope(pub, priv, dec(t, s.Sealed)); err != nil {
			t.Fatalf("%s: OpenEnvelope: %v", s.Name, err)
		}
	}
	for _, a := range v.AEAD {
		key, _ := KeyFromBytes(dec(t, a.Key))
		blob := dec(t, a.Blob)
		if !bytes.Equal(blob[:NonceSize], dec(t, a.Nonce)) {
			t.Fatalf("%s: nonce prefix mismatch", a.Name)
		}
		padded, err := DecryptAEAD(key, blob, dec(t, a.AAD))
		if err != nil || !bytes.Equal(padded, dec(t, a.Plaintext)) {
			t.Fatalf("%s: decrypt: %v", a.Name, err)
		}
		if _, err := DecryptAEAD(key, blob, append(dec(t, a.AAD), 'x')); !errors.Is(err, ErrDecrypt) {
			t.Fatalf("%s: altered aad accepted", a.Name)
		}
		if _, err := DecryptEnvelope(key, blob, dec(t, a.AAD)); err != nil {
			t.Fatalf("%s: DecryptEnvelope: %v", a.Name, err)
		}
	}
	for _, p := range v.Padding {
		if !bytes.Equal(Pad(dec(t, p.Unpadded), p.Block), dec(t, p.Padded)) {
			t.Fatalf("padding vector mismatch for %d bytes", len(dec(t, p.Unpadded)))
		}
		out, err := Unpad(dec(t, p.Padded), p.Block)
		if err != nil || !bytes.Equal(out, dec(t, p.Unpadded)) {
			t.Fatalf("unpad vector: %v", err)
		}
	}
	for _, f := range v.Fingerprint {
		pub := dec(t, f.PublicKey)
		if Fingerprint(pub) != f.Fingerprint || Commitment(pub) != f.Commitment {
			t.Fatalf("fingerprint vector mismatch for %s", f.PublicKey)
		}
	}
	for _, e := range v.Envelope {
		err := e.Envelope.Validate()
		if e.Valid && err != nil {
			t.Fatalf("%s: expected valid: %v", e.Name, err)
		}
		if !e.Valid && err == nil {
			t.Fatalf("%s: expected invalid", e.Name)
		}
	}
	for _, a := range v.RevealAAD {
		if !bytes.Equal(RevealAAD(a.Name, a.KeepsCopy), dec(t, a.AAD)) {
			t.Fatalf("reveal aad vector mismatch for %s", a.Name)
		}
	}
	for _, tk := range v.Tokens {
		if ValidToken(tk.Token) != tk.Valid {
			t.Fatalf("token validity mismatch for %q", tk.Token)
		}
		if HashToken(tk.Token).Encode() != tk.Hash {
			t.Fatalf("token hash mismatch for %q", tk.Token)
		}
	}
	// Regenerating must be deterministic.
	if *update {
		again := generate(t)
		b1, _ := json.Marshal(generate(t))
		b2, _ := json.Marshal(again)
		if !bytes.Equal(b1, b2) {
			t.Fatal("vector generation is not deterministic")
		}
	}
}
