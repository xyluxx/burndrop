// Package crypto is the cryptographic core of burndrop.
//
// It is deliberately small. Every operation maps to one libsodium-compatible
// primitive from golang.org/x/crypto, so the bytes produced here are consumed
// unchanged by the TypeScript module (libsodium-wrappers) and the Python
// module (PyNaCl), and vice versa. The shared test vectors live in
// spec/vectors.json.
//
// The section numbers in comments refer to docs/crypto-spec.md.
//
// Two encryption paths exist and nothing else:
//
//   - Drop (human to agent): a libsodium sealed box to the agent's per-request
//     X25519 public key. Section 5.3.
//   - Reveal (agent to human): XChaCha20-Poly1305 (IETF) under a random
//     256-bit key with the display metadata as additional data. Section 5.4.
//
// Plaintext is always an Envelope (envelope.go), padded to a multiple of
// PadBlock bytes with ISO/IEC 7816-4 padding before encryption, so the relay
// only ever learns a coarse size class.
package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/nacl/box"
)

const (
	// KeySize is the size of X25519 keys and of XChaCha20-Poly1305 keys.
	KeySize = 32
	// NonceSize is the XChaCha20-Poly1305 nonce size (192 bits).
	NonceSize = chacha20poly1305.NonceSizeX
	// TagSize is the Poly1305 authentication tag size.
	TagSize = chacha20poly1305.Overhead
	// SealedOverhead is the sealed box overhead: ephemeral public key (32)
	// plus Poly1305 tag (16). Equal to libsodium's crypto_box_SEALBYTES.
	SealedOverhead = box.AnonymousOverhead
	// AEADOverhead is the reveal blob overhead: nonce (24) plus tag (16).
	AEADOverhead = NonceSize + TagSize
	// PadBlock is the padding block size. Section 5.1.
	PadBlock = 256
	// MaxPlaintext is the largest envelope accepted before padding.
	MaxPlaintext = 64 * 1024
)

var (
	// ErrDecrypt is returned when authentication fails. It is deliberately
	// the same for a wrong key, altered ciphertext, or altered additional
	// data, so callers cannot distinguish them (and neither can an attacker).
	ErrDecrypt = errors.New("crypto: decryption failed")
	// ErrPadding is returned when padding is malformed after decryption.
	ErrPadding = errors.New("crypto: invalid padding")
	// ErrSize is returned when an input exceeds MaxPlaintext.
	ErrSize = errors.New("crypto: input too large")
	// ErrLength is returned when a key, nonce, or blob has the wrong length.
	ErrLength = errors.New("crypto: wrong length")
)

// Encoding is base64url without padding, decoded strictly (non-zero trailing
// bits are rejected, so every byte string has exactly one encoding). Every
// binary field in links, JSON bodies, and vectors uses it.
var Encoding = base64.RawURLEncoding.Strict()

// GenerateKeyPair returns a fresh X25519 keypair for one drop request.
// random may be nil, in which case crypto/rand is used.
func GenerateKeyPair(random io.Reader) (pub, priv *[KeySize]byte, err error) {
	if random == nil {
		random = rand.Reader
	}
	return box.GenerateKey(random)
}

// Seal encrypts plaintext to recipientPub as a libsodium sealed box
// (crypto_box_seal): an ephemeral X25519 key is generated, the nonce is
// BLAKE2b-24(ephemeral public key || recipient public key), and the output is
// ephemeral public key || XSalsa20-Poly1305 ciphertext. random may be nil.
func Seal(recipientPub *[KeySize]byte, plaintext []byte, random io.Reader) ([]byte, error) {
	if random == nil {
		random = rand.Reader
	}
	return box.SealAnonymous(nil, plaintext, recipientPub, random)
}

// OpenSealed decrypts a sealed box with the recipient keypair.
func OpenSealed(pub, priv *[KeySize]byte, sealed []byte) ([]byte, error) {
	if len(sealed) < SealedOverhead {
		return nil, ErrDecrypt
	}
	out, ok := box.OpenAnonymous(nil, sealed, pub, priv)
	if !ok {
		return nil, ErrDecrypt
	}
	return out, nil
}

// NewSymmetricKey returns a random 256-bit key for one reveal. random may be nil.
func NewSymmetricKey(random io.Reader) (*[KeySize]byte, error) {
	if random == nil {
		random = rand.Reader
	}
	key := new([KeySize]byte)
	if _, err := io.ReadFull(random, key[:]); err != nil {
		return nil, err
	}
	return key, nil
}

// EncryptAEAD encrypts plaintext with XChaCha20-Poly1305 (IETF) and returns
// nonce || ciphertext || tag, the wire format for reveal blobs. aad is
// authenticated but not encrypted. random may be nil.
func EncryptAEAD(key *[KeySize]byte, plaintext, aad []byte, random io.Reader) ([]byte, error) {
	if random == nil {
		random = rand.Reader
	}
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, err
	}
	out := make([]byte, NonceSize, NonceSize+len(plaintext)+TagSize)
	if _, err := io.ReadFull(random, out[:NonceSize]); err != nil {
		return nil, err
	}
	return aead.Seal(out, out[:NonceSize], plaintext, aad), nil
}

// DecryptAEAD reverses EncryptAEAD. Any modification of blob or aad yields
// ErrDecrypt.
func DecryptAEAD(key *[KeySize]byte, blob, aad []byte) ([]byte, error) {
	if len(blob) < AEADOverhead {
		return nil, ErrDecrypt
	}
	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, err
	}
	out, err := aead.Open(nil, blob[:NonceSize], blob[NonceSize:], aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return out, nil
}

// Pad applies ISO/IEC 7816-4 padding: append 0x80, then 0x00 bytes up to the
// next multiple of block. At least one byte is always added, so an input that
// is already aligned grows by a full block. Identical to libsodium sodium_pad.
func Pad(data []byte, block int) []byte {
	padLen := block - len(data)%block
	out := make([]byte, len(data)+padLen)
	copy(out, data)
	out[len(data)] = 0x80
	return out
}

// Unpad reverses Pad. It scans back at most block bytes for the 0x80 marker
// and rejects anything else, like libsodium sodium_unpad. It runs on
// authenticated plaintext, so its timing is not a concern.
func Unpad(data []byte, block int) ([]byte, error) {
	if len(data) == 0 || len(data)%block != 0 {
		return nil, ErrPadding
	}
	stop := len(data) - block
	for i := len(data) - 1; i >= stop; i-- {
		switch data[i] {
		case 0x80:
			return data[:i], nil
		case 0x00:
			continue
		default:
			return nil, ErrPadding
		}
	}
	return nil, ErrPadding
}

// Fingerprint returns the human-comparable fingerprint of a public key: the
// first 64 bits of SHA-256(key) as four groups of four lowercase hex
// characters, for example "a1b2-c3d4-e5f6-a7b8". Section 5.3 step 4.
func Fingerprint(pub []byte) string {
	sum := sha256.Sum256(pub)
	s := hex.EncodeToString(sum[:8])
	return s[0:4] + "-" + s[4:8] + "-" + s[8:12] + "-" + s[12:16]
}

// Commitment returns SHA-256(key) encoded with Encoding. The agent registers
// it with the relay when it creates a slot and the browser sends it again
// with the upload, so a link whose key was altered in transit is rejected by
// an honest relay. Section 5.3 steps 2 and 8.
func Commitment(pub []byte) string {
	sum := sha256.Sum256(pub)
	return Encoding.EncodeToString(sum[:])
}

// Zero overwrites b with zeros. Best effort: Go may hold other copies.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ZeroKey overwrites a key with zeros.
func ZeroKey(k *[KeySize]byte) {
	if k != nil {
		Zero(k[:])
	}
}

// SealEnvelope encodes, pads, and seals an envelope to a recipient key.
func SealEnvelope(recipientPub *[KeySize]byte, env Envelope, random io.Reader) ([]byte, error) {
	plain, err := env.Encode()
	if err != nil {
		return nil, err
	}
	if len(plain) > MaxPlaintext {
		return nil, ErrSize
	}
	padded := Pad(plain, PadBlock)
	defer Zero(padded)
	defer Zero(plain)
	return Seal(recipientPub, padded, random)
}

// OpenEnvelope opens a sealed box, unpads, and decodes the envelope.
func OpenEnvelope(pub, priv *[KeySize]byte, sealed []byte) (Envelope, error) {
	if len(sealed) > MaxPlaintext+PadBlock+SealedOverhead {
		return Envelope{}, ErrSize
	}
	padded, err := OpenSealed(pub, priv, sealed)
	if err != nil {
		return Envelope{}, err
	}
	defer Zero(padded)
	plain, err := Unpad(padded, PadBlock)
	if err != nil {
		return Envelope{}, err
	}
	return DecodeEnvelope(plain)
}

// EncryptEnvelope encodes, pads, and encrypts an envelope for a reveal.
func EncryptEnvelope(key *[KeySize]byte, env Envelope, aad []byte, random io.Reader) ([]byte, error) {
	plain, err := env.Encode()
	if err != nil {
		return nil, err
	}
	if len(plain) > MaxPlaintext {
		return nil, ErrSize
	}
	padded := Pad(plain, PadBlock)
	defer Zero(padded)
	defer Zero(plain)
	return EncryptAEAD(key, padded, aad, random)
}

// DecryptEnvelope reverses EncryptEnvelope.
func DecryptEnvelope(key *[KeySize]byte, blob, aad []byte) (Envelope, error) {
	if len(blob) > MaxPlaintext+PadBlock+AEADOverhead {
		return Envelope{}, ErrSize
	}
	padded, err := DecryptAEAD(key, blob, aad)
	if err != nil {
		return Envelope{}, err
	}
	defer Zero(padded)
	plain, err := Unpad(padded, PadBlock)
	if err != nil {
		return Envelope{}, err
	}
	return DecodeEnvelope(plain)
}

// KeyFromBytes copies a 32-byte slice into a key array.
func KeyFromBytes(b []byte) (*[KeySize]byte, error) {
	if len(b) != KeySize {
		return nil, ErrLength
	}
	k := new([KeySize]byte)
	copy(k[:], b)
	return k, nil
}
