package crypto

import (
	"bytes"
	"testing"
)

// Vectors produced by PyNaCl 1.6.2 (libsodium 1.0.20) with scripts kept in the
// repository under spec/. They prove that this package is byte-compatible with
// the reference libsodium implementation used by the Python SDK and, through
// libsodium-wrappers, by the browser page.
const (
	pynaclSK     = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
	pynaclPK     = "j0DFrbaPJWJK5bIU6nZ6bslNgp09e14a0bpvPiE4KF8"
	pynaclSealed = "CWyGeyyhVXSLOVZsusDihcVkhj6rC1lb6fW55LjFD0NgLBL9plmYv0N_RIvTTY1PxXsSddl7RvlmqSZRzfIF3VtgNiCw9MDOrSbhQW0ZTQ"
	pynaclPT     = "aGVsbG8gZnJvbSBsaWJzb2RpdW0gdmlhIFB5TmFDbA"

	pynaclKey   = "ERERERERERERERERERERERERERERERERERERERERERE"
	pynaclNonce = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYX"
	pynaclAAD   = "YnVybmRyb3AvcmV2ZWFsL3YxCk1USXpORFUyTnpnNU1HRmlZMlJsWmcKc3RhZ2luZy1kYi11cmwKMQ"
	pynaclMsg   = "cmV2ZWFsIHBheWxvYWQgd2l0aCBhZGRpdGlvbmFsIGRhdGE"
	pynaclCT    = "6X-kF4NAfCeIUQ9TCW0KrmjLMPlhCx7spmJ67Kl_KeBC9RVEP_craS2yHaiomuQFYAsH"

	pynaclPadABC = "YWJjgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)

func TestOpensLibsodiumSealedBox(t *testing.T) {
	pub, _ := KeyFromBytes(dec(t, pynaclPK))
	priv, _ := KeyFromBytes(dec(t, pynaclSK))
	// The public key must be the one libsodium derives from this secret key.
	derivedPub, _, err := GenerateKeyPair(bytes.NewReader(dec(t, pynaclSK)))
	if err != nil || !bytes.Equal(derivedPub[:], pub[:]) {
		t.Fatalf("public key derivation differs from libsodium: %v", err)
	}
	got, err := OpenSealed(pub, priv, dec(t, pynaclSealed))
	if err != nil || !bytes.Equal(got, dec(t, pynaclPT)) {
		t.Fatalf("could not open libsodium sealed box: %v", err)
	}
}

func TestMatchesLibsodiumXChaCha20Poly1305(t *testing.T) {
	key, _ := KeyFromBytes(dec(t, pynaclKey))
	blob, err := EncryptAEAD(key, dec(t, pynaclMsg), dec(t, pynaclAAD), bytes.NewReader(dec(t, pynaclNonce)))
	if err != nil {
		t.Fatal(err)
	}
	want := append(dec(t, pynaclNonce), dec(t, pynaclCT)...)
	if !bytes.Equal(blob, want) {
		t.Fatalf("ciphertext differs from libsodium\n got %x\nwant %x", blob, want)
	}
	pt, err := DecryptAEAD(key, want, dec(t, pynaclAAD))
	if err != nil || !bytes.Equal(pt, dec(t, pynaclMsg)) {
		t.Fatalf("decrypt libsodium ciphertext: %v", err)
	}
}

func TestMatchesLibsodiumPadding(t *testing.T) {
	if !bytes.Equal(Pad([]byte("abc"), 256), dec(t, pynaclPadABC)) {
		t.Fatal("padding differs from sodium_pad")
	}
	aligned := Pad(make([]byte, 256), 256)
	if len(aligned) != 512 || aligned[256] != 0x80 {
		t.Fatal("aligned padding differs from sodium_pad")
	}
}
