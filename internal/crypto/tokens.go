package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
)

const (
	// TokenBytes is the entropy of every token and identifier: 128 bits.
	// Section 5.2.
	TokenBytes = 16
	// TokenLen is the encoded length of a token or identifier (22 characters).
	TokenLen = 22
	// AgentKeyBytes is the entropy of a relay agent API key: 256 bits.
	AgentKeyBytes = 32
	// HashLen is the encoded length of a SHA-256 hash (43 characters).
	HashLen = 43
)

// Hash is a SHA-256 digest. The relay stores token hashes, never tokens.
type Hash [sha256.Size]byte

// RandomToken returns 16 random bytes encoded with Encoding. Used for drop
// IDs and for upload, fetch, reveal, and revoke tokens.
func RandomToken() (string, error) {
	return randomString(TokenBytes)
}

// RandomAgentKey returns a 256-bit relay agent API key.
func RandomAgentKey() (string, error) {
	return randomString(AgentKeyBytes)
}

func randomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return Encoding.EncodeToString(b), nil
}

// HashToken hashes the presented token string. Tokens are opaque strings to
// the relay; hashing the string bytes (not the decoded bytes) keeps the relay
// free of any decoding step on the authentication path.
func HashToken(token string) Hash {
	return sha256.Sum256([]byte(token))
}

// HashEqual compares two hashes in constant time.
func HashEqual(a, b Hash) bool {
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

// Encode returns the hash encoded with Encoding.
func (h Hash) Encode() string {
	return Encoding.EncodeToString(h[:])
}

// ParseHash decodes an encoded hash.
func ParseHash(s string) (Hash, error) {
	var h Hash
	b, err := Encoding.DecodeString(s)
	if err != nil || len(b) != len(h) {
		return h, fmt.Errorf("%w: hash must be %d base64url characters", ErrLength, HashLen)
	}
	copy(h[:], b)
	return h, nil
}

// ValidToken reports whether s is a well-formed token or identifier: exactly
// TokenLen characters of base64url decoding to TokenBytes bytes.
func ValidToken(s string) bool {
	if len(s) != TokenLen {
		return false
	}
	b, err := Encoding.DecodeString(s)
	return err == nil && len(b) == TokenBytes
}

// ValidCommitment reports whether s is a well-formed commitment (43
// characters of base64url decoding to 32 bytes).
func ValidCommitment(s string) bool {
	if len(s) != HashLen {
		return false
	}
	b, err := Encoding.DecodeString(s)
	return err == nil && len(b) == sha256.Size
}
