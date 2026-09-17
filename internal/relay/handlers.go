package relay

import (
	"errors"
	"net/http"
	"time"

	"github.com/xyluxx/burndrop/internal/crypto"
)

// Request and response bodies. Field names are the public API.

type createDropRequest struct {
	TTLSeconds int64  `json:"ttl_seconds"`
	Commitment string `json:"commitment"`
}

type createDropResponse struct {
	DropID      string `json:"drop_id"`
	UploadToken string `json:"upload_token"`
	FetchToken  string `json:"fetch_token"`
	ExpiresAt   string `json:"expires_at"`
}

type uploadRequest struct {
	DropID      string `json:"drop_id"`
	UploadToken string `json:"upload_token"`
	Commitment  string `json:"commitment"`
	Ciphertext  string `json:"ciphertext"`
}

type tokenRequest struct {
	DropID string `json:"drop_id"`
	Token  string `json:"token"`
}

type fetchRequest struct {
	DropID     string `json:"drop_id"`
	FetchToken string `json:"fetch_token"`
}

type openRequest struct {
	DropID      string `json:"drop_id"`
	RevealToken string `json:"reveal_token"`
}

type statusRequest struct {
	DropID      string `json:"drop_id"`
	WaitSeconds int64  `json:"wait_seconds"`
	WaitWhile   string `json:"wait_while"`
}

type createRevealRequest struct {
	TTLSeconds int64  `json:"ttl_seconds"`
	Ciphertext string `json:"ciphertext"`
}

type createRevealResponse struct {
	DropID      string `json:"drop_id"`
	RevealToken string `json:"reveal_token"`
	RevokeToken string `json:"revoke_token"`
	ExpiresAt   string `json:"expires_at"`
}

func (s *Server) createDrop(w http.ResponseWriter, r *http.Request) {
	keyID, ok := s.authenticate(r)
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", nil)
		return
	}
	if !s.limitAgent(w, r, keyID) {
		return
	}
	var req createDropRequest
	if !s.decodeJSON(w, r, &req) {
		return
	}
	if !crypto.ValidCommitment(req.Commitment) {
		s.writeError(w, http.StatusBadRequest, "bad_request", map[string]any{"detail": "commitment must be the base64url SHA-256 of the recipient public key"})
		return
	}
	id, uploadTok, fetchTok, err := newTokens()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "internal_error", nil)
		return
	}
	now := s.now()
	d := &Drop{
		ID: id, Kind: KindDrop, State: StateCreated, Commitment: req.Commitment,
		TokenA: crypto.HashToken(uploadTok), TokenB: crypto.HashToken(fetchTok),
		AgentKeyID: keyID, CreatedAt: now, ExpiresAt: now.Add(s.cfg.ClampTTL(req.TTLSeconds)),
	}
	if err := s.store.Create(r.Context(), d); err != nil {
		s.storeError(w, err, KindDrop, "create")
		return
	}
	s.writeJSON(w, http.StatusCreated, createDropResponse{DropID: id, UploadToken: uploadTok, FetchToken: fetchTok, ExpiresAt: rfc3339(d.ExpiresAt)})
}

func (s *Server) upload(w http.ResponseWriter, r *http.Request) {
	if !s.limitPage(w, r) {
		return
	}
	var req uploadRequest
	if !s.decodeJSON(w, r, &req) {
		return
	}
	if !crypto.ValidToken(req.DropID) || !crypto.ValidToken(req.UploadToken) {
		s.writeError(w, http.StatusBadRequest, "bad_request", map[string]any{"detail": "drop_id and upload_token must be 22 base64url characters"})
		return
	}
	if !crypto.ValidCommitment(req.Commitment) {
		s.writeError(w, http.StatusBadRequest, "bad_request", map[string]any{"detail": "malformed commitment"})
		return
	}
	ct, ok := s.decodeCiphertext(w, req.Ciphertext, crypto.SealedOverhead+crypto.PadBlock)
	if !ok {
		return
	}
	err := s.store.Upload(r.Context(), req.DropID, crypto.HashToken(req.UploadToken), req.Commitment, ct)
	crypto.Zero(ct)
	if err != nil {
		s.storeError(w, err, KindDrop, "upload")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"state": StateUploaded})
}

func (s *Server) fetch(w http.ResponseWriter, r *http.Request) {
	keyID, ok := s.authenticate(r)
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", nil)
		return
	}
	if !s.limitAgent(w, r, keyID) {
		return
	}
	var req fetchRequest
	if !s.decodeJSON(w, r, &req) {
		return
	}
	if !crypto.ValidToken(req.DropID) || !crypto.ValidToken(req.FetchToken) {
		s.writeError(w, http.StatusBadRequest, "bad_request", map[string]any{"detail": "drop_id and fetch_token must be 22 base64url characters"})
		return
	}
	ct, uploadedAt, err := s.store.Fetch(r.Context(), req.DropID, crypto.HashToken(req.FetchToken))
	if err != nil {
		s.storeError(w, err, KindDrop, "fetch")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"ciphertext": crypto.Encoding.EncodeToString(ct), "uploaded_at": rfc3339(uploadedAt)})
	crypto.Zero(ct)
}

func (s *Server) createReveal(w http.ResponseWriter, r *http.Request) {
	keyID, ok := s.authenticate(r)
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", nil)
		return
	}
	if !s.limitAgent(w, r, keyID) {
		return
	}
	var req createRevealRequest
	if !s.decodeJSON(w, r, &req) {
		return
	}
	ct, ok := s.decodeCiphertext(w, req.Ciphertext, crypto.AEADOverhead+crypto.PadBlock)
	if !ok {
		return
	}
	id, revealTok, revokeTok, err := newTokens()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "internal_error", nil)
		return
	}
	now := s.now()
	d := &Drop{
		ID: id, Kind: KindReveal, State: StateCreated, Ciphertext: ct,
		TokenA: crypto.HashToken(revealTok), TokenB: crypto.HashToken(revokeTok),
		AgentKeyID: keyID, CreatedAt: now, ExpiresAt: now.Add(s.cfg.ClampTTL(req.TTLSeconds)),
	}
	err = s.store.Create(r.Context(), d)
	crypto.Zero(ct)
	if err != nil {
		s.storeError(w, err, KindReveal, "create")
		return
	}
	s.writeJSON(w, http.StatusCreated, createRevealResponse{DropID: id, RevealToken: revealTok, RevokeToken: revokeTok, ExpiresAt: rfc3339(d.ExpiresAt)})
}

func (s *Server) open(w http.ResponseWriter, r *http.Request) {
	if !s.limitPage(w, r) {
		return
	}
	var req openRequest
	if !s.decodeJSON(w, r, &req) {
		return
	}
	if !crypto.ValidToken(req.DropID) || !crypto.ValidToken(req.RevealToken) {
		s.writeError(w, http.StatusBadRequest, "bad_request", map[string]any{"detail": "drop_id and reveal_token must be 22 base64url characters"})
		return
	}
	ct, createdAt, err := s.store.Open(r.Context(), req.DropID, crypto.HashToken(req.RevealToken))
	if err != nil {
		s.storeError(w, err, KindReveal, "open")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"ciphertext": crypto.Encoding.EncodeToString(ct), "created_at": rfc3339(createdAt)})
	crypto.Zero(ct)
}

func (s *Server) statusHandler(kind Kind) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.limitPage(w, r) {
			return
		}
		var req statusRequest
		if !s.decodeJSON(w, r, &req) {
			return
		}
		if !crypto.ValidToken(req.DropID) {
			s.writeError(w, http.StatusBadRequest, "bad_request", map[string]any{"detail": "drop_id must be 22 base64url characters"})
			return
		}
		if req.WaitSeconds < 0 || time.Duration(req.WaitSeconds)*time.Second > MaxLongPoll {
			s.writeError(w, http.StatusBadRequest, "bad_request", map[string]any{"detail": "wait_seconds must be between 0 and 30"})
			return
		}
		st, err := s.store.Status(r.Context(), req.DropID)
		if err != nil {
			s.storeError(w, err, kind, "status")
			return
		}
		if st.Kind != kind {
			s.writeError(w, http.StatusNotFound, "not_found", nil)
			return
		}
		waitWhile := State(req.WaitWhile)
		if req.WaitSeconds > 0 && !st.State.Terminal() && (waitWhile == "" || waitWhile == st.State) {
			if s.waiters.Load() >= int64(s.cfg.MaxWaiters) {
				w.Header().Set("Retry-After", "5")
				s.writeError(w, http.StatusServiceUnavailable, "too_many_waiters", nil)
				return
			}
			s.waiters.Add(1)
			st, err = s.store.Wait(r.Context(), req.DropID, st.State, time.Duration(req.WaitSeconds)*time.Second)
			s.waiters.Add(-1)
			if err != nil {
				s.storeError(w, err, kind, "status")
				return
			}
		}
		s.writeJSON(w, http.StatusOK, statusBody(st))
	}
}

func (s *Server) revokeHandler(kind Kind) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.limitPage(w, r) {
			return
		}
		var req tokenRequest
		if !s.decodeJSON(w, r, &req) {
			return
		}
		if !crypto.ValidToken(req.DropID) || !crypto.ValidToken(req.Token) {
			s.writeError(w, http.StatusBadRequest, "bad_request", map[string]any{"detail": "drop_id and token must be 22 base64url characters"})
			return
		}
		st, err := s.store.Status(r.Context(), req.DropID)
		if err != nil {
			s.storeError(w, err, kind, "revoke")
			return
		}
		if st.Kind != kind {
			s.writeError(w, http.StatusNotFound, "not_found", nil)
			return
		}
		if err := s.store.Revoke(r.Context(), req.DropID, crypto.HashToken(req.Token)); err != nil {
			s.storeError(w, err, kind, "revoke")
			return
		}
		s.writeJSON(w, http.StatusOK, map[string]any{"state": StateRevoked})
	}
}

func statusBody(st Status) map[string]any {
	body := map[string]any{
		"state":      st.State,
		"kind":       st.Kind,
		"created_at": rfc3339(st.CreatedAt),
		"expires_at": rfc3339(st.ExpiresAt),
	}
	if !st.UploadedAt.IsZero() {
		body["uploaded_at"] = rfc3339(st.UploadedAt)
	}
	if !st.FetchedAt.IsZero() {
		if st.Kind == KindReveal {
			body["opened_at"] = rfc3339(st.FetchedAt)
		} else {
			body["fetched_at"] = rfc3339(st.FetchedAt)
		}
	}
	if !st.RevokedAt.IsZero() {
		body["revoked_at"] = rfc3339(st.RevokedAt)
	}
	return body
}

// storeError maps store errors to the documented HTTP responses.
func (s *Server) storeError(w http.ResponseWriter, err error, kind Kind, op string) {
	var se *StateError
	switch {
	case errors.Is(err, ErrNotFound), errors.Is(err, ErrWrongKind):
		s.writeError(w, http.StatusNotFound, "not_found", nil)
	case errors.Is(err, ErrBadToken):
		s.writeError(w, http.StatusForbidden, "bad_token", nil)
	case errors.Is(err, ErrCommitment):
		s.writeError(w, http.StatusUnprocessableEntity, "commitment_mismatch", map[string]any{"detail": "the public key in this link does not match the key the agent registered"})
	case errors.Is(err, ErrFull):
		w.Header().Set("Retry-After", "30")
		s.writeError(w, http.StatusServiceUnavailable, "store_full", nil)
	case errors.As(err, &se):
		extra := map[string]any{"state": se.State}
		if !se.At.IsZero() {
			extra["at"] = rfc3339(se.At)
		}
		switch {
		case op == "upload" && se.State == StateUploaded:
			s.writeError(w, http.StatusConflict, "already_uploaded", extra)
		case op == "fetch" && se.State == StateCreated:
			s.writeError(w, http.StatusNotFound, "not_uploaded", extra)
		default:
			s.writeError(w, http.StatusGone, "gone", extra)
		}
	default:
		s.log.Error("store error", "op", op, "kind", kind, "err", err.Error())
		s.writeError(w, http.StatusInternalServerError, "internal_error", nil)
	}
}

// decodeCiphertext validates and decodes a ciphertext field.
func (s *Server) decodeCiphertext(w http.ResponseWriter, encoded string, minLen int) ([]byte, bool) {
	if encoded == "" {
		s.writeError(w, http.StatusBadRequest, "bad_request", map[string]any{"detail": "ciphertext is required"})
		return nil, false
	}
	if len(encoded) > s.cfg.MaxCiphertextBytes*4/3+4 {
		s.writeError(w, http.StatusRequestEntityTooLarge, "too_large", map[string]any{"max_bytes": s.cfg.MaxCiphertextBytes})
		return nil, false
	}
	ct, err := crypto.Encoding.DecodeString(encoded)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "bad_request", map[string]any{"detail": "ciphertext must be base64url without padding"})
		return nil, false
	}
	if len(ct) > s.cfg.MaxCiphertextBytes {
		s.writeError(w, http.StatusRequestEntityTooLarge, "too_large", map[string]any{"max_bytes": s.cfg.MaxCiphertextBytes})
		return nil, false
	}
	if len(ct) < minLen {
		s.writeError(w, http.StatusBadRequest, "bad_request", map[string]any{"detail": "ciphertext is too short to be valid"})
		return nil, false
	}
	return ct, true
}

func newTokens() (id, a, b string, err error) {
	if id, err = crypto.RandomToken(); err != nil {
		return
	}
	if a, err = crypto.RandomToken(); err != nil {
		return
	}
	b, err = crypto.RandomToken()
	return
}
