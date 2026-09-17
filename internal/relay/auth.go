package relay

import (
	"net/http"
	"strings"

	"github.com/burndrop/burndrop/internal/crypto"
)

// authenticate checks the Authorization header against the configured agent
// keys. It returns the key ID on success. Every configured hash is compared
// even after a match so the time taken does not depend on which key matched.
func (s *Server) authenticate(r *http.Request) (string, bool) {
	if !s.cfg.AuthRequired() {
		if id, ok := s.bearerID(r); ok {
			return id, true
		}
		return "anonymous", true
	}
	return s.bearerID(r)
}

func (s *Server) bearerID(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", false
	}
	token := strings.TrimSpace(h[len(prefix):])
	if len(token) < 16 || len(token) > 256 {
		return "", false
	}
	presented := crypto.HashToken(token)
	matched := ""
	for _, k := range s.cfg.AgentKeys {
		if crypto.HashEqual(k.Hash, presented) {
			matched = k.ID
		}
	}
	return matched, matched != ""
}
