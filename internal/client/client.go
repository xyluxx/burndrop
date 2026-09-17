// Package client talks to a burndrop relay over its JSON API. Every call is
// a POST with the identifiers in the body, so nothing sensitive reaches a
// URL or an access log. See docs/design.md section 7.
package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/burndrop/burndrop/internal/crypto"
	"github.com/burndrop/burndrop/internal/link"
)

// ClientHeader must be present on every API request; the relay rejects
// requests without it so that simple form posts and scanners cannot reach
// the API.
const ClientHeader = "X-Client"

// MaxWait is the longest single long poll the relay allows.
const MaxWait = 30 * time.Second

// Client is safe for concurrent use.
type Client struct {
	// Origin is the normalized relay origin, for example https://relay.example.
	Origin string
	// APIKey is sent as a bearer token on agent endpoints when set.
	APIKey string
	// HTTP is the transport; nil means a client with sane timeouts.
	HTTP *http.Client
	// Name identifies the software in the X-Client header.
	Name string
}

// New validates and normalizes the relay origin.
func New(relay, apiKey, name string) (*Client, error) {
	origin, err := link.NormalizeOrigin(relay)
	if err != nil {
		return nil, fmt.Errorf("relay: %w", err)
	}
	if name == "" {
		name = "burndrop-go"
	}
	return &Client{Origin: origin, APIKey: apiKey, HTTP: &http.Client{Timeout: MaxWait + 15*time.Second}, Name: name}, nil
}

// Error is a relay error response.
type Error struct {
	Status int
	Code   string
	Detail string
	State  string
	At     time.Time
}

func (e *Error) Error() string {
	var sb strings.Builder
	sb.WriteString("relay: ")
	sb.WriteString(e.Code)
	if e.State != "" {
		sb.WriteString(" (" + e.State + ")")
	}
	if e.Detail != "" {
		sb.WriteString(": " + e.Detail)
	}
	sb.WriteString(fmt.Sprintf(" [HTTP %d]", e.Status))
	return sb.String()
}

// IsCode reports whether err is a relay error with the given code.
func IsCode(err error, code string) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == code
}

// Common error codes returned by the relay.
const (
	CodeNotFound        = "not_found"
	CodeNotUploaded     = "not_uploaded"
	CodeGone            = "gone"
	CodeBadToken        = "bad_token"
	CodeUnauthorized    = "unauthorized"
	CodeRateLimited     = "rate_limited"
	CodeCommitment      = "commitment_mismatch"
	CodeAlreadyUploaded = "already_uploaded"
)

// Drop states as reported by the relay.
const (
	StateCreated  = "created"
	StateUploaded = "uploaded"
	StateFetched  = "fetched"
	StateOpened   = "opened"
	StateRevoked  = "revoked"
	StateExpired  = "expired"
)

// DropCreated is the result of CreateDrop.
type DropCreated struct {
	ID          string
	UploadToken string
	FetchToken  string
	ExpiresAt   time.Time
}

// RevealCreated is the result of CreateReveal.
type RevealCreated struct {
	ID          string
	RevealToken string
	RevokeToken string
	ExpiresAt   time.Time
}

// Status is a drop or reveal status.
type Status struct {
	State      string
	Kind       string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	UploadedAt time.Time
	FetchedAt  time.Time
	OpenedAt   time.Time
	RevokedAt  time.Time
}

// Terminal reports whether the state can no longer change.
func (s Status) Terminal() bool {
	switch s.State {
	case StateFetched, StateOpened, StateRevoked, StateExpired:
		return true
	}
	return false
}

// Info is the relay's self description.
type Info struct {
	Version            string `json:"version"`
	API                string `json:"api"`
	DefaultTTLSeconds  int64  `json:"default_ttl_seconds"`
	MaxTTLSeconds      int64  `json:"max_ttl_seconds"`
	MaxCiphertextBytes int    `json:"max_ciphertext_bytes"`
	LongPollMaxSeconds int64  `json:"long_poll_max_seconds"`
	AgentAuth          string `json:"agent_auth"`
	PageServed         bool   `json:"page_served"`
	PageVersion        string `json:"page_version"`
	PageSHA256         string `json:"page_sha256"`
}

// CreateDrop reserves a slot for a human to upload into. commitment is the
// base64url SHA-256 of the recipient public key; ttl of zero uses the relay
// default.
func (c *Client) CreateDrop(ctx context.Context, commitment string, ttl time.Duration) (DropCreated, error) {
	var out struct {
		DropID      string `json:"drop_id"`
		UploadToken string `json:"upload_token"`
		FetchToken  string `json:"fetch_token"`
		ExpiresAt   string `json:"expires_at"`
	}
	req := map[string]any{"ttl_seconds": int64(ttl / time.Second), "commitment": commitment}
	if err := c.post(ctx, "/api/v1/drops", req, &out, true); err != nil {
		return DropCreated{}, err
	}
	return DropCreated{ID: out.DropID, UploadToken: out.UploadToken, FetchToken: out.FetchToken, ExpiresAt: parseTime(out.ExpiresAt)}, nil
}

// Upload stores a sealed envelope in a drop slot. It is what the page does;
// the CLI uses it for the human side of a request.
func (c *Client) Upload(ctx context.Context, id, uploadToken, commitment string, ciphertext []byte) error {
	req := map[string]any{"drop_id": id, "upload_token": uploadToken, "commitment": commitment, "ciphertext": crypto.Encoding.EncodeToString(ciphertext)}
	return c.post(ctx, "/api/v1/drops/upload", req, nil, false)
}

// DropStatus reports a drop's state. With wait above zero the relay holds
// the request for up to that long while the state equals waitWhile.
func (c *Client) DropStatus(ctx context.Context, id string, wait time.Duration, waitWhile string) (Status, error) {
	return c.status(ctx, "/api/v1/drops/status", id, wait, waitWhile)
}

// RevealStatus is DropStatus for reveals.
func (c *Client) RevealStatus(ctx context.Context, id string, wait time.Duration, waitWhile string) (Status, error) {
	return c.status(ctx, "/api/v1/reveals/status", id, wait, waitWhile)
}

func (c *Client) status(ctx context.Context, path, id string, wait time.Duration, waitWhile string) (Status, error) {
	if wait > MaxWait {
		wait = MaxWait
	}
	var out struct {
		State      string `json:"state"`
		Kind       string `json:"kind"`
		CreatedAt  string `json:"created_at"`
		ExpiresAt  string `json:"expires_at"`
		UploadedAt string `json:"uploaded_at"`
		FetchedAt  string `json:"fetched_at"`
		OpenedAt   string `json:"opened_at"`
		RevokedAt  string `json:"revoked_at"`
	}
	req := map[string]any{"drop_id": id, "wait_seconds": int64(wait / time.Second), "wait_while": waitWhile}
	if err := c.post(ctx, path, req, &out, false); err != nil {
		return Status{}, err
	}
	return Status{State: out.State, Kind: out.Kind, CreatedAt: parseTime(out.CreatedAt), ExpiresAt: parseTime(out.ExpiresAt), UploadedAt: parseTime(out.UploadedAt), FetchedAt: parseTime(out.FetchedAt), OpenedAt: parseTime(out.OpenedAt), RevokedAt: parseTime(out.RevokedAt)}, nil
}

// WaitForUpload long polls until the drop leaves the created state, the
// deadline passes, or ctx ends. It returns the last status seen.
func (c *Client) WaitForUpload(ctx context.Context, id string, deadline time.Time) (Status, error) {
	return c.waitWhile(ctx, func(ctx context.Context, wait time.Duration) (Status, error) {
		return c.DropStatus(ctx, id, wait, StateCreated)
	}, StateCreated, deadline)
}

// WaitForOpen long polls until the reveal leaves the created state, which
// for a reveal means it was opened, revoked, or expired.
func (c *Client) WaitForOpen(ctx context.Context, id string, deadline time.Time) (Status, error) {
	return c.waitWhile(ctx, func(ctx context.Context, wait time.Duration) (Status, error) {
		return c.RevealStatus(ctx, id, wait, StateCreated)
	}, StateCreated, deadline)
}

func (c *Client) waitWhile(ctx context.Context, poll func(context.Context, time.Duration) (Status, error), state string, deadline time.Time) (Status, error) {
	var last Status
	failures := 0
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return last, context.DeadlineExceeded
		}
		wait := min(remaining, MaxWait)
		st, err := poll(ctx, wait)
		if err != nil {
			if ctx.Err() != nil {
				return last, ctx.Err()
			}
			var relayErr *Error
			if errors.As(err, &relayErr) && relayErr.Status < 500 && relayErr.Code != CodeRateLimited {
				return last, err
			}
			failures++
			if failures > 5 {
				return last, err
			}
			select {
			case <-ctx.Done():
				return last, ctx.Err()
			case <-time.After(time.Duration(failures) * time.Second):
			}
			continue
		}
		failures = 0
		last = st
		if st.State != state {
			return st, nil
		}
	}
}

// Fetch downloads and deletes the sealed envelope. Only the first call with
// a valid fetch token succeeds.
func (c *Client) Fetch(ctx context.Context, id, fetchToken string) (ciphertext []byte, uploadedAt time.Time, err error) {
	var out struct {
		Ciphertext string `json:"ciphertext"`
		UploadedAt string `json:"uploaded_at"`
	}
	req := map[string]any{"drop_id": id, "fetch_token": fetchToken}
	if err := c.post(ctx, "/api/v1/drops/fetch", req, &out, true); err != nil {
		return nil, time.Time{}, err
	}
	ct, err := crypto.Encoding.DecodeString(out.Ciphertext)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("relay: malformed ciphertext in response")
	}
	return ct, parseTime(out.UploadedAt), nil
}

// CreateReveal stores an encrypted reveal for a human to open once.
func (c *Client) CreateReveal(ctx context.Context, ciphertext []byte, ttl time.Duration) (RevealCreated, error) {
	var out struct {
		DropID      string `json:"drop_id"`
		RevealToken string `json:"reveal_token"`
		RevokeToken string `json:"revoke_token"`
		ExpiresAt   string `json:"expires_at"`
	}
	req := map[string]any{"ttl_seconds": int64(ttl / time.Second), "ciphertext": crypto.Encoding.EncodeToString(ciphertext)}
	if err := c.post(ctx, "/api/v1/reveals", req, &out, true); err != nil {
		return RevealCreated{}, err
	}
	return RevealCreated{ID: out.DropID, RevealToken: out.RevealToken, RevokeToken: out.RevokeToken, ExpiresAt: parseTime(out.ExpiresAt)}, nil
}

// Open downloads and deletes a reveal's ciphertext. It is what the page
// does; the CLI uses it for the human side of a send.
func (c *Client) Open(ctx context.Context, id, revealToken string) (ciphertext []byte, createdAt time.Time, err error) {
	var out struct {
		Ciphertext string `json:"ciphertext"`
		CreatedAt  string `json:"created_at"`
	}
	req := map[string]any{"drop_id": id, "reveal_token": revealToken}
	if err := c.post(ctx, "/api/v1/reveals/open", req, &out, false); err != nil {
		return nil, time.Time{}, err
	}
	ct, err := crypto.Encoding.DecodeString(out.Ciphertext)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("relay: malformed ciphertext in response")
	}
	return ct, parseTime(out.CreatedAt), nil
}

// RevokeDrop cancels a request; either of its tokens is accepted.
func (c *Client) RevokeDrop(ctx context.Context, id, token string) error {
	return c.post(ctx, "/api/v1/drops/revoke", map[string]any{"drop_id": id, "token": token}, nil, false)
}

// RevokeReveal deletes an unopened reveal.
func (c *Client) RevokeReveal(ctx context.Context, id, token string) error {
	return c.post(ctx, "/api/v1/reveals/revoke", map[string]any{"drop_id": id, "token": token}, nil, false)
}

// Info fetches the relay description.
func (c *Client) Info(ctx context.Context) (Info, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Origin+"/api/v1/info", nil)
	if err != nil {
		return Info{}, err
	}
	req.Header.Set(ClientHeader, c.Name)
	var out Info
	if err := c.do(req, &out); err != nil {
		return Info{}, err
	}
	return out, nil
}

// PageHash fetches the served page and returns its SHA-256 (base64url) so a
// caller can compare it with a published hash.
func (c *Client) PageHash(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Origin+"/drop", nil)
	if err != nil {
		return "", err
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", &Error{Status: resp.StatusCode, Code: "page_unavailable"}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:]), nil
}

const maxResponse = 1 << 20

func (c *Client) post(ctx context.Context, path string, body any, out any, auth bool) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Origin+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(ClientHeader, c.Name)
	if auth && c.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
	}
	return c.do(req, out)
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}

func (c *Client) do(req *http.Request, out any) error {
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return fmt.Errorf("relay: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return fmt.Errorf("relay: reading response: %w", err)
	}
	if resp.StatusCode/100 != 2 {
		return decodeError(resp.StatusCode, body)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("relay: malformed response (HTTP %d)", resp.StatusCode)
	}
	return nil
}

func decodeError(status int, body []byte) error {
	var e struct {
		Error  string `json:"error"`
		Detail string `json:"detail"`
		State  string `json:"state"`
		At     string `json:"at"`
	}
	if json.Unmarshal(body, &e) != nil || e.Error == "" {
		return &Error{Status: status, Code: "http_" + fmt.Sprint(status)}
	}
	return &Error{Status: status, Code: e.Error, Detail: e.Detail, State: e.State, At: parseTime(e.At)}
}

func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t
}
