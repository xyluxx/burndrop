package crypto

import (
	"crypto/rand"
	"errors"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/blake2b"
)

// Password-protected reveals (docs/crypto-spec.md section 4.1).
//
// A reveal link normally carries the whole decryption key, so whoever holds
// the link can open it. When the human has set a reveal password, the agent
// mixes a password-derived key into the link key: the link alone is not
// enough, and the password alone is not enough. The parameters below are
// libsodium's crypto_pwhash interactive limits with Argon2id 1.3, so the
// browser (libsodium.js), PyNaCl, and Go derive the same bytes.

const (
	// SaltSize is the size of the per-reveal password salt carried in the link.
	SaltSize = 16
	// PasswordOpsLimit is the Argon2id time cost (crypto_pwhash_OPSLIMIT_INTERACTIVE).
	PasswordOpsLimit = 2
	// PasswordMemLimitKiB is the Argon2id memory cost in KiB (crypto_pwhash_MEMLIMIT_INTERACTIVE, 64 MiB).
	PasswordMemLimitKiB = 64 * 1024
	// MinPasswordLen is the shortest reveal password the CLI accepts.
	MinPasswordLen = 8
	// passwordDomain separates this derivation from any other use of BLAKE2b.
	passwordDomain = "burndrop/reveal-password/v1"
)

// ErrPassword is returned for an empty password or a salt of the wrong size.
var ErrPassword = errors.New("crypto: password or salt invalid")

// NewSalt returns a random salt for one password-protected reveal. random
// may be nil, in which case crypto/rand is used.
func NewSalt(random io.Reader) ([]byte, error) {
	if random == nil {
		random = rand.Reader
	}
	salt := make([]byte, SaltSize)
	if _, err := io.ReadFull(random, salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// PasswordKey derives 32 bytes from a password and a salt with Argon2id
// (time 2, memory 64 MiB, one lane), the libsodium interactive parameters.
// The password is used as typed, in UTF-8, with no normalization.
func PasswordKey(password, salt []byte) (*[KeySize]byte, error) {
	if len(password) == 0 || len(salt) != SaltSize {
		return nil, ErrPassword
	}
	out := argon2.IDKey(password, salt, PasswordOpsLimit, PasswordMemLimitKiB, 1, KeySize)
	key := new([KeySize]byte)
	copy(key[:], out)
	Zero(out)
	return key, nil
}

// RevealKeyWithPassword combines the key carried in the link with the
// password-derived key: BLAKE2b-256(domain || linkKey || passwordKey). The
// result is the XChaCha20-Poly1305 key of the reveal.
func RevealKeyWithPassword(linkKey *[KeySize]byte, password, salt []byte) (*[KeySize]byte, error) {
	pw, err := PasswordKey(password, salt)
	if err != nil {
		return nil, err
	}
	defer ZeroKey(pw)
	return combineKeys(linkKey, pw), nil
}

func combineKeys(linkKey, passwordKey *[KeySize]byte) *[KeySize]byte {
	msg := make([]byte, 0, len(passwordDomain)+2*KeySize)
	msg = append(msg, passwordDomain...)
	msg = append(msg, linkKey[:]...)
	msg = append(msg, passwordKey[:]...)
	sum := blake2b.Sum256(msg)
	Zero(msg)
	key := new([KeySize]byte)
	copy(key[:], sum[:])
	Zero(sum[:])
	return key
}
