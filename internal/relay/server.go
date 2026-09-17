package relay

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/burndrop/burndrop/web"
)

// ClientHeader must be present on every API request. Its presence forces a
// CORS preflight for cross-origin browser callers and blocks plain form posts.
const ClientHeader = "X-Client"

// Server is the relay HTTP server.
type Server struct {
	cfg      Config
	store    Store
	log      *slog.Logger
	page     *web.Page
	version  string
	now      func() time.Time
	pageLim  *Limiter
	agentLim *Limiter
	global   *Global
	waiters  atomic.Int64
	mux      *http.ServeMux
	handler  http.Handler
}

// Options tune a Server beyond its Config.
type Options struct {
	Page    *web.Page // nil means the page is not served
	Version string
	Now     func() time.Time
	Logger  *slog.Logger
}

// New builds a Server. The store must already be created with limits derived
// from the same Config (see NewStore).
func New(cfg Config, store Store, opts Options) *Server {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if opts.Version == "" {
		opts.Version = "dev"
	}
	s := &Server{
		cfg:      cfg,
		store:    store,
		log:      opts.Logger,
		page:     opts.Page,
		version:  opts.Version,
		now:      opts.Now,
		pageLim:  NewLimiter(cfg.RatePagePerMin, int(cfg.RatePagePerMin/3)+1, opts.Now),
		agentLim: NewLimiter(cfg.RateAgentPerMin, int(cfg.RateAgentPerMin/3)+1, opts.Now),
		global:   NewGlobal(cfg.RateGlobalPerSec, opts.Now),
	}
	s.routes()
	return s
}

// NewStore creates the store named by the configuration.
func NewStore(cfg Config, now func() time.Time) (Store, error) {
	switch cfg.Store {
	case "memory":
		return NewMemory(StoreOptions{MaxLive: cfg.MaxLiveDrops, MaxBytes: cfg.MaxTotalBytes, Now: now}), nil
	case "redis":
		return newRedisStore(cfg, now)
	default:
		return nil, fmt.Errorf("unknown store %q", cfg.Store)
	}
}

// Handler returns the fully wrapped HTTP handler.
func (s *Server) Handler() http.Handler { return s.handler }

func (s *Server) routes() {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/drops", s.createDrop)
	mux.HandleFunc("POST /api/v1/drops/upload", s.upload)
	mux.HandleFunc("POST /api/v1/drops/status", s.statusHandler(KindDrop))
	mux.HandleFunc("POST /api/v1/drops/fetch", s.fetch)
	mux.HandleFunc("POST /api/v1/drops/revoke", s.revokeHandler(KindDrop))
	mux.HandleFunc("POST /api/v1/reveals", s.createReveal)
	mux.HandleFunc("POST /api/v1/reveals/open", s.open)
	mux.HandleFunc("POST /api/v1/reveals/status", s.statusHandler(KindReveal))
	mux.HandleFunc("POST /api/v1/reveals/revoke", s.revokeHandler(KindReveal))
	mux.HandleFunc("OPTIONS /api/v1/", s.preflight)
	mux.HandleFunc("GET /api/v1/info", s.info)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "ok\n")
	})
	if s.cfg.ServePage {
		mux.HandleFunc("GET /{$}", s.servePage)
		mux.HandleFunc("GET /drop", s.servePage)
		mux.HandleFunc("GET /reveal", s.servePage)
	}
	s.mux = mux
	s.handler = s.middleware(mux)
}

// requestIDKey carries the request ID through the context.
type requestIDKey struct{}

func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := s.now()
		rid := newRequestID()
		r = r.WithContext(context.WithValue(r.Context(), requestIDKey{}, rid))
		rec := &recorder{ResponseWriter: w, status: 200}
		h := rec.Header()
		h.Set("X-Request-Id", rid)
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Permissions-Policy", "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=(), interest-cohort=()")
		if strings.EqualFold(r.URL.Scheme, "https") || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") || r.TLS != nil {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		defer func() {
			if p := recover(); p != nil {
				s.log.Error("panic", "request_id", rid, "route", r.Pattern, "panic", fmt.Sprint(p))
				if !rec.wrote {
					s.writeError(rec, http.StatusInternalServerError, "internal_error", nil)
				}
			}
			attrs := []any{"method", r.Method, "route", routeName(r), "status", rec.status, "duration_ms", s.now().Sub(start).Milliseconds(), "request_id", rid}
			if s.cfg.LogClientIP {
				attrs = append(attrs, "client_ip", ClientIP(r, s.cfg.TrustedProxies))
			}
			s.log.Info("request", attrs...)
		}()
		if !s.global.Allow() {
			rec.Header().Set("Retry-After", "1")
			s.writeError(rec, http.StatusTooManyRequests, "rate_limited", nil)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") && !s.cors(rec, r) {
			// A browser page from an origin that is not configured gets no
			// CORS headers and, for good measure, no processing at all.
			s.writeError(rec, http.StatusForbidden, "origin_not_allowed", nil)
			return
		}
		next.ServeHTTP(rec, r)
	})
}

// routeName returns the matched pattern, never the raw path, so logs cannot
// contain anything a client put in a URL.
func routeName(r *http.Request) string {
	if r.Pattern != "" {
		return r.Pattern
	}
	return "unmatched"
}

type recorder struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (r *recorder) WriteHeader(code int) {
	if !r.wrote {
		r.status = code
		r.wrote = true
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *recorder) Write(b []byte) (int, error) {
	if !r.wrote {
		r.wrote = true
	}
	return r.ResponseWriter.Write(b)
}

func newRequestID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "00000000"
	}
	return hex.EncodeToString(b[:])
}

// cors sets response headers for allowed page origins. Requests without an
// Origin header (agents, curl) are unaffected.
func (s *Server) cors(w http.ResponseWriter, r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	w.Header().Add("Vary", "Origin")
	for _, allowed := range s.cfg.PageOrigins {
		if strings.EqualFold(origin, allowed) {
			h := w.Header()
			h.Set("Access-Control-Allow-Origin", allowed)
			h.Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
			h.Set("Access-Control-Allow-Headers", "Content-Type, "+ClientHeader+", Authorization")
			h.Set("Access-Control-Max-Age", "600")
			return true
		}
	}
	return false
}

func (s *Server) preflight(w http.ResponseWriter, _ *http.Request) {
	// The middleware already rejected disallowed origins and set the headers
	// for allowed ones.
	w.WriteHeader(http.StatusNoContent)
}

// servePage serves the embedded single-file page with its strict CSP.
func (s *Server) servePage(w http.ResponseWriter, r *http.Request) {
	if s.page == nil {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, "The drop page is not built into this relay. Use the CLI or the browser extension, or rebuild the relay with the page.\n")
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Security-Policy", s.page.CSP())
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Drop-Page-Version", s.page.Meta.Version)
	h.Set("X-Drop-Page-SHA256", s.page.Meta.SHA256)
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(s.page.HTML)
	}
}

func (s *Server) info(w http.ResponseWriter, _ *http.Request) {
	pageSHA := ""
	pageVersion := ""
	if s.page != nil {
		pageSHA = s.page.Meta.SHA256
		pageVersion = s.page.Meta.Version
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"version":               s.version,
		"api":                   "v1",
		"default_ttl_seconds":   int64(s.cfg.DefaultTTL / time.Second),
		"max_ttl_seconds":       int64(s.cfg.MaxTTL / time.Second),
		"max_ciphertext_bytes":  s.cfg.MaxCiphertextBytes,
		"long_poll_max_seconds": int64(MaxLongPoll / time.Second),
		"agent_auth":            s.cfg.AgentAuth,
		"page_served":           s.page != nil,
		"page_version":          pageVersion,
		"page_sha256":           pageSHA,
	})
}

// decodeJSON enforces the API request contract: the client header, a JSON
// content type, a bounded body, and no unknown fields.
func (s *Server) decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	if r.Header.Get(ClientHeader) == "" {
		s.writeError(w, http.StatusBadRequest, "missing_client_header", map[string]any{"header": ClientHeader})
		return false
	}
	ct := r.Header.Get("Content-Type")
	if mt, _, _ := strings.Cut(ct, ";"); strings.TrimSpace(strings.ToLower(mt)) != "application/json" {
		s.writeError(w, http.StatusUnsupportedMediaType, "unsupported_media_type", nil)
		return false
	}
	limit := int64(s.cfg.MaxCiphertextBytes)*4/3 + 4096
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			s.writeError(w, http.StatusRequestEntityTooLarge, "too_large", map[string]any{"max_bytes": s.cfg.MaxCiphertextBytes})
			return false
		}
		s.writeError(w, http.StatusBadRequest, "bad_request", map[string]any{"detail": sanitizeJSONError(err)})
		return false
	}
	if dec.More() {
		s.writeError(w, http.StatusBadRequest, "bad_request", map[string]any{"detail": "trailing data"})
		return false
	}
	return true
}

// sanitizeJSONError keeps decoder messages, which describe structure and never
// echo values, and drops anything else.
func sanitizeJSONError(err error) string {
	var syn *json.SyntaxError
	var typ *json.UnmarshalTypeError
	switch {
	case errors.As(err, &syn):
		return "malformed JSON"
	case errors.As(err, &typ):
		return "wrong type for field " + typ.Field
	case strings.HasPrefix(err.Error(), "json: unknown field"):
		return err.Error()
	case errors.Is(err, io.EOF):
		return "empty body"
	default:
		return "invalid body"
	}
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	_ = enc.Encode(v)
}

func (s *Server) writeError(w http.ResponseWriter, status int, code string, extra map[string]any) {
	body := map[string]any{"error": code}
	for k, v := range extra {
		body[k] = v
	}
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer realm="burndrop"`)
	}
	s.writeJSON(w, status, body)
}

func (s *Server) limitPage(w http.ResponseWriter, r *http.Request) bool {
	if !s.pageLim.Allow(ClientIP(r, s.cfg.TrustedProxies)) {
		w.Header().Set("Retry-After", "10")
		s.writeError(w, http.StatusTooManyRequests, "rate_limited", nil)
		return false
	}
	return true
}

func (s *Server) limitAgent(w http.ResponseWriter, keyID string) bool {
	if !s.agentLim.Allow(keyID) {
		w.Header().Set("Retry-After", "10")
		s.writeError(w, http.StatusTooManyRequests, "rate_limited", nil)
		return false
	}
	return true
}

func rfc3339(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// Sweeper runs the store's expiry sweep every interval until ctx is done.
func (s *Server) Sweeper(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if n := s.store.Sweep(); n > 0 {
				s.log.Debug("sweep", "expired_or_removed", n)
			}
		}
	}
}
