package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/xyluxx/burndrop/internal/client"
	"github.com/xyluxx/burndrop/internal/crypto"
	"github.com/xyluxx/burndrop/internal/link"
	"github.com/xyluxx/burndrop/internal/storage"
)

// Agent implements the flows. Construct it with New.
type Agent struct {
	Config     Config
	Relay      *client.Client
	Store      *storage.Manager
	Audit      *Audit
	Redactor   *Redactor
	PageOrigin string
	Now        func() time.Time
	Random     io.Reader
	// PasswordSource returns the reveal password when the human has set
	// one; the CLI wires it from the config reference. Nil means none.
	PasswordSource func() ([]byte, error)
}

// New wires the dependencies. audit may be nil (disabled).
func New(cfg Config, relay *client.Client, store *storage.Manager, audit *Audit) *Agent {
	page := cfg.PageOrigin
	if page == "" {
		page = relay.Origin
	} else if normalized, err := link.NormalizeOrigin(page); err == nil {
		page = normalized
	}
	return &Agent{Config: cfg, Relay: relay, Store: store, Audit: audit, Redactor: NewRedactor(), PageOrigin: page, Now: time.Now, Random: rand.Reader}
}

// Errors the tools translate into messages.
var (
	ErrNotSendable = errors.New("this secret was received from a human and is not marked sendable; only secrets created by the agent or marked sendable by the operator can be sent")
	ErrNoPending   = errors.New("no pending request or unopened reveal with that id")
	ErrAmbiguous   = errors.New("more than one request is pending; pass request_id")
	ErrNotAllowed  = errors.New("command is not in run_with_secret.allowed_commands")
	// ErrNoRevealPassword is returned when reveals must be password
	// protected but no password is available.
	ErrNoRevealPassword = errors.New("reveal links must carry a password but none is set; the human runs: burndrop reveal-password set")
)

// pendingRecord is what the agent keeps about an outstanding request: the
// private key that can open the drop and the tokens that can fetch or
// revoke it. It is stored as an internal record in the storage manager so
// it survives restarts and expires with the request.
type pendingRecord struct {
	V           int       `json:"v"`
	DropID      string    `json:"drop_id"`
	FetchToken  string    `json:"fetch_token"`
	UploadToken string    `json:"upload_token"`
	PrivateKey  []byte    `json:"private_key"`
	PublicKey   []byte    `json:"public_key"`
	Name        string    `json:"name"`
	Purpose     string    `json:"purpose"`
	Retention   string    `json:"retention"`
	Storage     string    `json:"storage"`
	Sendable    bool      `json:"sendable"`
	Fingerprint string    `json:"fingerprint"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
}

const pendingPrefix = "pending."

func pendingName(dropID string) string { return pendingPrefix + dropID }

// sentRecord remembers an unopened reveal so that a revoke can cancel it.
// It holds the revoke token and display facts, never the key or the value,
// and expires with the link.
type sentRecord struct {
	V           int       `json:"v"`
	DropID      string    `json:"drop_id"`
	RevokeToken string    `json:"revoke_token"`
	Name        string    `json:"name"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
}

const sentPrefix = "sent."

func sentName(dropID string) string { return sentPrefix + dropID }

// isInternalName reports whether a storage name belongs to a bookkeeping
// record (a pending request or a sent reveal) rather than to a secret.
func isInternalName(name string) bool {
	return strings.HasPrefix(name, pendingPrefix) || strings.HasPrefix(name, sentPrefix)
}

// isInternalKind is the metadata form of isInternalName.
func isInternalKind(kind string) bool {
	return kind == storage.KindPending || kind == storage.KindSent
}

// DeliveryNote travels with every link so that the model is reminded, on
// every call and not only in the instruction file, who may receive it. The
// link may travel over any channel; it must reach only the human the agent
// works for.
const DeliveryNote = "Deliver this only to the human you are working for, through the channel you already use with them (this chat, or their email, Telegram, Slack, or wherever they read you). Any channel can carry the link, but it must reach only that person: never a group, ticket, file, commit, log, or web page, and never anyone else. If it reached the wrong person, revoke it at once with this request_id (revoke_request, or burndrop revoke)."

// RequestInput is the request_secret input.
type RequestInput struct {
	Name      string `json:"name" jsonschema:"reference name for the secret, for example openai-api-key; letters, digits, dot, underscore, dash"`
	Purpose   string `json:"purpose" jsonschema:"one sentence shown to the human explaining what the secret is for"`
	Retention string `json:"retention,omitempty" jsonschema:"session, until-revoked, or until:<RFC 3339 date>; default from the config file"`
	Sendable  bool   `json:"sendable,omitempty" jsonschema:"whether the agent may later send this secret back to a human with send_secret; default false"`
	TTL       string `json:"ttl,omitempty" jsonschema:"how long the link stays valid, for example 30m or 2h; default from the config file, relay maximum applies"`
}

// RequestOutput is the request_secret output.
type RequestOutput struct {
	RequestID   string    `json:"request_id"`
	Link        string    `json:"link"`
	Fingerprint string    `json:"fingerprint"`
	ExpiresAt   time.Time `json:"expires_at"`
	Storage     string    `json:"storage"`
	Retention   string    `json:"retention"`
	Message     string    `json:"message"`
	Delivery    string    `json:"delivery"`
}

// Request creates a drop slot and returns a link for the human.
func (a *Agent) Request(ctx context.Context, in RequestInput) (RequestOutput, error) {
	if err := storage.ValidateName(in.Name); err != nil {
		return RequestOutput{}, err
	}
	if err := crypto.ValidateText("purpose", in.Purpose); err != nil {
		return RequestOutput{}, err
	}
	if strings.TrimSpace(in.Purpose) == "" {
		return RequestOutput{}, errors.New("purpose is required so the human knows what the secret is for")
	}
	retention := in.Retention
	if retention == "" {
		retention = a.Config.Retention()
	}
	now := a.Now().UTC()
	if _, err := storage.ParseRetention(retention, now); err != nil {
		return RequestOutput{}, err
	}
	ttl, err := a.ttl(in.TTL)
	if err != nil {
		return RequestOutput{}, err
	}
	pub, priv, err := crypto.GenerateKeyPair(a.Random)
	if err != nil {
		return RequestOutput{}, err
	}
	defer crypto.ZeroKey(priv)
	commitment := crypto.Commitment(pub[:])
	created, err := a.Relay.CreateDrop(ctx, commitment, ttl)
	if err != nil {
		a.log(Event{Event: "request_secret", Name: in.Name, Result: "relay_error", Detail: a.safeErr(err)})
		return RequestOutput{}, err
	}
	storageName := a.Store.Persistent().Name()
	if retention == storage.RetentionSession {
		storageName = "memory"
	}
	fingerprint := crypto.Fingerprint(pub[:])
	d := link.Drop{ID: created.ID, UploadToken: created.UploadToken, RecipientKey: pub[:], Name: in.Name, Purpose: in.Purpose, Storage: describeStorage(storageName), Retention: retention}
	if a.Relay.Origin != a.PageOrigin {
		d.Relay = a.Relay.Origin
	}
	url, err := d.Build(a.PageOrigin)
	if err != nil {
		_ = a.Relay.RevokeDrop(ctx, created.ID, created.UploadToken)
		return RequestOutput{}, err
	}
	rec := pendingRecord{V: 1, DropID: created.ID, FetchToken: created.FetchToken, UploadToken: created.UploadToken, PrivateKey: priv[:], PublicKey: pub[:], Name: in.Name, Purpose: in.Purpose, Retention: retention, Storage: storageName, Sendable: in.Sendable, Fingerprint: fingerprint, CreatedAt: now, ExpiresAt: created.ExpiresAt.UTC()}
	if err := a.savePending(ctx, rec); err != nil {
		_ = a.Relay.RevokeDrop(ctx, created.ID, created.UploadToken)
		return RequestOutput{}, fmt.Errorf("could not save the pending request: %w", err)
	}
	a.log(Event{Event: "request_secret", Name: in.Name, DropID: created.ID, Result: "created", Fields: map[string]string{"fingerprint": fingerprint, "retention": retention, "storage": storageName, "expires_at": created.ExpiresAt.UTC().Format(time.RFC3339)}})
	out := RequestOutput{RequestID: created.ID, Link: url, Fingerprint: fingerprint, ExpiresAt: created.ExpiresAt.UTC(), Storage: storageName, Retention: retention}
	out.Message = requestMessage(out, in)
	out.Delivery = DeliveryNote
	return out, nil
}

func (a *Agent) ttl(s string) (time.Duration, error) {
	if s == "" {
		return a.Config.TTL()
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("ttl %q is not a positive duration such as 30m or 2h", s)
	}
	return d, nil
}

func (a *Agent) savePending(ctx context.Context, rec pendingRecord) error {
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	defer storage.Zero(b)
	retention := storage.RetentionUntilPrefix + rec.ExpiresAt.Format(time.RFC3339)
	if !rec.ExpiresAt.After(a.Now().Add(time.Second)) {
		retention = storage.RetentionSession
	}
	_, err = a.Store.Put(ctx, pendingName(rec.DropID), b, storage.Metadata{Retention: retention, Purpose: rec.Purpose, Source: storage.SourceDrop, Kind: storage.KindPending, Fingerprint: rec.Fingerprint})
	return err
}

func (a *Agent) loadPending(ctx context.Context, dropID string) (pendingRecord, error) {
	if !crypto.ValidToken(dropID) {
		return pendingRecord{}, fmt.Errorf("%w: malformed request id", ErrNoPending)
	}
	b, _, err := a.Store.Get(ctx, pendingName(dropID))
	if errors.Is(err, storage.ErrNotFound) {
		return pendingRecord{}, ErrNoPending
	}
	if err != nil {
		return pendingRecord{}, err
	}
	defer storage.Zero(b)
	var rec pendingRecord
	if err := json.Unmarshal(b, &rec); err != nil || rec.V != 1 {
		return pendingRecord{}, errors.New("pending request record is corrupt")
	}
	return rec, nil
}

func (a *Agent) deletePending(ctx context.Context, dropID string) {
	_ = a.Store.Delete(ctx, pendingName(dropID))
}

func (a *Agent) saveSent(ctx context.Context, rec sentRecord) error {
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	retention := storage.RetentionUntilPrefix + rec.ExpiresAt.Format(time.RFC3339)
	if !rec.ExpiresAt.After(a.Now().Add(time.Second)) {
		retention = storage.RetentionSession
	}
	_, err = a.Store.Put(ctx, sentName(rec.DropID), b, storage.Metadata{Retention: retention, Source: storage.SourceCapture, Kind: storage.KindSent})
	return err
}

func (a *Agent) loadSent(ctx context.Context, dropID string) (sentRecord, error) {
	if !crypto.ValidToken(dropID) {
		return sentRecord{}, fmt.Errorf("%w: malformed request id", ErrNoPending)
	}
	b, _, err := a.Store.Get(ctx, sentName(dropID))
	if errors.Is(err, storage.ErrNotFound) {
		return sentRecord{}, ErrNoPending
	}
	if err != nil {
		return sentRecord{}, err
	}
	defer storage.Zero(b)
	var rec sentRecord
	if err := json.Unmarshal(b, &rec); err != nil || rec.V != 1 {
		return sentRecord{}, errors.New("sent reveal record is corrupt")
	}
	return rec, nil
}

func (a *Agent) deleteSent(ctx context.Context, dropID string) {
	_ = a.Store.Delete(ctx, sentName(dropID))
}

// PendingRequest describes an outstanding request without its keys.
type PendingRequest struct {
	RequestID   string    `json:"request_id"`
	Name        string    `json:"name"`
	Purpose     string    `json:"purpose"`
	Fingerprint string    `json:"fingerprint"`
	Retention   string    `json:"retention"`
	Storage     string    `json:"storage"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// Pending lists outstanding requests, oldest first.
func (a *Agent) Pending(ctx context.Context) ([]PendingRequest, error) {
	all, err := a.Store.List(ctx)
	if err != nil {
		return nil, err
	}
	var out []PendingRequest
	for _, m := range all {
		if m.Kind != storage.KindPending {
			continue
		}
		rec, err := a.loadPending(ctx, strings.TrimPrefix(m.Name, pendingPrefix))
		if err != nil {
			continue
		}
		out = append(out, PendingRequest{RequestID: rec.DropID, Name: rec.Name, Purpose: rec.Purpose, Fingerprint: rec.Fingerprint, Retention: rec.Retention, Storage: rec.Storage, CreatedAt: rec.CreatedAt, ExpiresAt: rec.ExpiresAt})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, nil
}

// FetchInput is the fetch_secret input.
type FetchInput struct {
	RequestID   string `json:"request_id,omitempty" jsonschema:"the request_id returned by request_secret; may be omitted when exactly one request is pending"`
	WaitSeconds int    `json:"wait_seconds,omitempty" jsonschema:"how long to wait for the human, default 30, maximum 300"`
}

// FetchOutput is the fetch_secret output.
type FetchOutput struct {
	Status      string    `json:"status"`
	RequestID   string    `json:"request_id"`
	Name        string    `json:"name,omitempty"`
	Storage     string    `json:"storage,omitempty"`
	Retention   string    `json:"retention,omitempty"`
	Fingerprint string    `json:"fingerprint,omitempty"`
	SizeBytes   int       `json:"size_bytes,omitempty"`
	ExpiresAt   time.Time `json:"expires_at,omitzero"`
	Message     string    `json:"message"`
}

// Fetch statuses.
const (
	StatusWaiting  = "waiting"
	StatusStored   = "stored"
	StatusExpired  = "expired"
	StatusRevoked  = "revoked"
	StatusRejected = "rejected"
	StatusGone     = "gone"
)

// MaxFetchWait bounds one fetch call.
const MaxFetchWait = 300 * time.Second

// Fetch waits for the human's upload, then downloads, decrypts, verifies, and
// stores the secret. The value never leaves this function except into the
// storage manager.
func (a *Agent) Fetch(ctx context.Context, in FetchInput) (FetchOutput, error) {
	id := in.RequestID
	if id == "" {
		pending, err := a.Pending(ctx)
		if err != nil {
			return FetchOutput{}, err
		}
		switch len(pending) {
		case 0:
			return FetchOutput{}, ErrNoPending
		case 1:
			id = pending[0].RequestID
		default:
			return FetchOutput{}, ErrAmbiguous
		}
	}
	rec, err := a.loadPending(ctx, id)
	if err != nil {
		return FetchOutput{}, err
	}
	defer storage.Zero(rec.PrivateKey)
	wait := time.Duration(in.WaitSeconds) * time.Second
	if in.WaitSeconds == 0 {
		wait = 30 * time.Second
	}
	if wait > MaxFetchWait {
		wait = MaxFetchWait
	}
	out := FetchOutput{RequestID: rec.DropID, Name: rec.Name, Storage: rec.Storage, Retention: rec.Retention, Fingerprint: rec.Fingerprint, ExpiresAt: rec.ExpiresAt}
	st, err := a.Relay.WaitForUpload(ctx, rec.DropID, a.Now().Add(wait))
	if err != nil && !errors.Is(err, context.DeadlineExceeded) {
		if client.IsCode(err, client.CodeNotFound) {
			a.deletePending(ctx, rec.DropID)
			out.Status = StatusExpired
			out.Message = "The request is no longer known to the relay; it expired. Ask again with request_secret if you still need it."
			a.log(Event{Event: "fetch_secret", Name: rec.Name, DropID: rec.DropID, Result: out.Status})
			return out, nil
		}
		return FetchOutput{}, err
	}
	switch st.State {
	case client.StateCreated, "":
		out.Status = StatusWaiting
		out.Message = fmt.Sprintf("The human has not submitted %s yet. The link is valid until %s. Call fetch_secret again to keep waiting.", rec.Name, rec.ExpiresAt.Format(time.RFC3339))
		return out, nil
	case client.StateRevoked:
		a.deletePending(ctx, rec.DropID)
		out.Status = StatusRevoked
		out.Message = "The request was revoked before the human submitted anything."
	case client.StateExpired:
		a.deletePending(ctx, rec.DropID)
		out.Status = StatusExpired
		out.Message = "The request expired before the human submitted anything. Ask again with request_secret if you still need it."
	case client.StateFetched:
		a.deletePending(ctx, rec.DropID)
		out.Status = StatusGone
		out.Message = "The submission was already fetched. If it was not stored by this agent, treat the secret as exposed and ask the human to rotate it."
	case client.StateUploaded:
		return a.fetchUploaded(ctx, rec, out)
	default:
		return FetchOutput{}, fmt.Errorf("unexpected relay state %q", st.State)
	}
	a.log(Event{Event: "fetch_secret", Name: rec.Name, DropID: rec.DropID, Result: out.Status})
	return out, nil
}

func (a *Agent) fetchUploaded(ctx context.Context, rec pendingRecord, out FetchOutput) (FetchOutput, error) {
	ct, _, err := a.Relay.Fetch(ctx, rec.DropID, rec.FetchToken)
	if err != nil {
		if client.IsCode(err, client.CodeGone) {
			a.deletePending(ctx, rec.DropID)
			out.Status = StatusGone
			out.Message = "The submission was fetched by someone else before this agent could. Treat the secret as exposed and ask the human to rotate it."
			a.log(Event{Event: "fetch_secret", Name: rec.Name, DropID: rec.DropID, Result: out.Status})
			return out, nil
		}
		return FetchOutput{}, err
	}
	pub, err := crypto.KeyFromBytes(rec.PublicKey)
	if err != nil {
		return FetchOutput{}, err
	}
	priv, err := crypto.KeyFromBytes(rec.PrivateKey)
	if err != nil {
		return FetchOutput{}, err
	}
	defer crypto.ZeroKey(priv)
	env, err := crypto.OpenEnvelope(pub, priv, ct)
	if err != nil {
		a.deletePending(ctx, rec.DropID)
		out.Status = StatusRejected
		out.Message = "The submission could not be decrypted with this request's key. The relay or the page may have been tampered with. Ask the human to try again with a fresh link and to compare fingerprints."
		a.log(Event{Event: "fetch_secret", Name: rec.Name, DropID: rec.DropID, Result: out.Status, Detail: "decrypt failed"})
		return out, nil
	}
	defer zeroEnvelope(&env)
	if reason := checkEnvelope(env, rec); reason != "" {
		a.deletePending(ctx, rec.DropID)
		out.Status = StatusRejected
		out.Message = "The submission was rejected: " + reason + ". Ask the human to try again with a fresh link."
		a.log(Event{Event: "fetch_secret", Name: rec.Name, DropID: rec.DropID, Result: out.Status, Detail: reason})
		return out, nil
	}
	value, err := env.SecretBytes()
	if err != nil {
		return FetchOutput{}, err
	}
	defer storage.Zero(value)
	meta, err := a.Store.Put(ctx, rec.Name, value, storage.Metadata{Retention: rec.Retention, Purpose: rec.Purpose, Source: storage.SourceDrop, Sendable: rec.Sendable, Fingerprint: rec.Fingerprint})
	if err != nil {
		// The ciphertext is gone from the relay. Keep the pending record so
		// the operator can see what happened; the value itself is lost and
		// the human must submit again.
		a.log(Event{Event: "fetch_secret", Name: rec.Name, DropID: rec.DropID, Result: "store_failed", Detail: a.safeErr(err)})
		return FetchOutput{}, fmt.Errorf("the secret was received but could not be stored (%w); ask the human to submit again after fixing storage", err)
	}
	a.Redactor.Add(rec.Name, value)
	a.deletePending(ctx, rec.DropID)
	out.Status = StatusStored
	out.Storage = meta.Backend
	out.SizeBytes = meta.SizeBytes
	out.Message = fmt.Sprintf("Stored %s in %s (%s). Use it with run_with_secret; its value is never shown.", rec.Name, describeStorage(meta.Backend), describeRetention(meta.Retention, meta.ExpiresAt))
	a.log(Event{Event: "fetch_secret", Name: rec.Name, DropID: rec.DropID, Result: out.Status, Fields: map[string]string{"backend": meta.Backend, "size_bytes": fmt.Sprint(meta.SizeBytes)}})
	return out, nil
}

// checkEnvelope verifies the decrypted envelope against the request. The
// page fills the envelope from the link it was given, so any difference
// means the link the human used was not the one this agent made.
func checkEnvelope(env crypto.Envelope, rec pendingRecord) string {
	switch {
	case env.Type != crypto.TypeDrop:
		return "the envelope is not a drop"
	case env.Name != rec.Name:
		return "the secret name in the submission does not match the request"
	case env.Fingerprint != "" && env.Fingerprint != rec.Fingerprint:
		return "the fingerprint shown to the human does not match this request"
	case env.Retention != rec.Retention:
		return "the retention shown to the human does not match the request"
	case env.Purpose != rec.Purpose:
		return "the purpose shown to the human does not match the request"
	case env.Storage != describeStorage(rec.Storage):
		return "the storage description shown to the human does not match the request"
	}
	return ""
}

func zeroEnvelope(env *crypto.Envelope) {
	env.Secret = strings.Repeat("\x00", 0)
	*env = crypto.Envelope{}
}

// SendInput is the send_secret input.
type SendInput struct {
	Name        string `json:"name" jsonschema:"name of a stored secret that is marked sendable"`
	TTL         string `json:"ttl,omitempty" jsonschema:"how long the link stays valid, for example 30m; default from the config file"`
	DeleteAfter bool   `json:"delete_after,omitempty" jsonschema:"delete the agent's copy once the link is created; the human is told whether the agent keeps a copy"`
}

// SendOutput is the send_secret output.
type SendOutput struct {
	RequestID         string    `json:"request_id"`
	Link              string    `json:"link"`
	ExpiresAt         time.Time `json:"expires_at"`
	KeepsCopy         bool      `json:"keeps_copy"`
	PasswordProtected bool      `json:"password_protected"`
	Message           string    `json:"message"`
	Delivery          string    `json:"delivery"`
}

// CanSend reports whether a stored secret exists and is marked sendable,
// without reading its value. It lets a caller refuse before asking the
// human to confirm.
func (a *Agent) CanSend(ctx context.Context, name string) error {
	if err := storage.ValidateName(name); err != nil {
		return err
	}
	meta, err := a.Store.Stat(ctx, name)
	if err != nil {
		return err
	}
	if isInternalKind(meta.Kind) {
		return storage.ErrNotFound
	}
	if !meta.Sendable {
		return ErrNotSendable
	}
	return nil
}

// Send encrypts a stored secret for a human and returns a one-time link.
func (a *Agent) Send(ctx context.Context, in SendInput) (SendOutput, error) {
	if err := storage.ValidateName(in.Name); err != nil {
		return SendOutput{}, err
	}
	ttl, err := a.ttl(in.TTL)
	if err != nil {
		return SendOutput{}, err
	}
	value, meta, err := a.Store.Get(ctx, in.Name)
	if err != nil {
		return SendOutput{}, err
	}
	defer storage.Zero(value)
	if meta.Kind == storage.KindPending {
		return SendOutput{}, storage.ErrNotFound
	}
	if !meta.Sendable {
		a.log(Event{Event: "send_secret", Name: in.Name, Result: "refused_not_sendable"})
		return SendOutput{}, ErrNotSendable
	}
	a.Redactor.Add(in.Name, value)
	key, err := crypto.NewSymmetricKey(a.Random)
	if err != nil {
		return SendOutput{}, err
	}
	defer crypto.ZeroKey(key)
	// With a reveal password the link carries key and a salt, and the
	// ciphertext is under a key derived from both and the password.
	encKey := key
	var salt []byte
	if a.Config.RevealPasswordRequired {
		if a.PasswordSource == nil {
			return SendOutput{}, ErrNoRevealPassword
		}
		password, err := a.PasswordSource()
		if err != nil {
			return SendOutput{}, fmt.Errorf("reveal password: %w", err)
		}
		if len(password) == 0 {
			return SendOutput{}, ErrNoRevealPassword
		}
		salt, err = crypto.NewSalt(a.Random)
		if err != nil {
			crypto.Zero(password)
			return SendOutput{}, err
		}
		derived, err := crypto.RevealKeyWithPassword(key, password, salt)
		crypto.Zero(password)
		if err != nil {
			return SendOutput{}, err
		}
		defer crypto.ZeroKey(derived)
		encKey = derived
	}
	keepsCopy := !in.DeleteAfter
	env := crypto.Envelope{V: 1, Type: crypto.TypeReveal, Name: in.Name}
	env.SetSecret(value)
	ct, err := crypto.EncryptEnvelope(encKey, env, crypto.RevealAAD(in.Name, keepsCopy), a.Random)
	if err != nil {
		return SendOutput{}, err
	}
	created, err := a.Relay.CreateReveal(ctx, ct, ttl)
	if err != nil {
		a.log(Event{Event: "send_secret", Name: in.Name, Result: "relay_error", Detail: a.safeErr(err)})
		return SendOutput{}, err
	}
	r := link.Reveal{ID: created.ID, RevealToken: created.RevealToken, Key: key[:], Name: in.Name, KeepsCopy: keepsCopy, Salt: salt}
	if a.Relay.Origin != a.PageOrigin {
		r.Relay = a.Relay.Origin
	}
	url, err := r.Build(a.PageOrigin)
	if err != nil {
		_ = a.Relay.RevokeReveal(ctx, created.ID, created.RevokeToken)
		return SendOutput{}, err
	}
	// The revoke token is kept until the link expires, so a link that went
	// to the wrong place can still be cancelled.
	if err := a.saveSent(ctx, sentRecord{V: 1, DropID: created.ID, RevokeToken: created.RevokeToken, Name: in.Name, CreatedAt: a.Now().UTC(), ExpiresAt: created.ExpiresAt.UTC()}); err != nil {
		_ = a.Relay.RevokeReveal(ctx, created.ID, created.RevokeToken)
		return SendOutput{}, fmt.Errorf("could not save the sent record: %w", err)
	}
	if in.DeleteAfter {
		if err := a.Store.Delete(ctx, in.Name); err != nil {
			keepsCopy = true
		}
	}
	a.log(Event{Event: "send_secret", Name: in.Name, DropID: created.ID, Result: "created", Fields: map[string]string{"keeps_copy": fmt.Sprint(keepsCopy), "expires_at": created.ExpiresAt.UTC().Format(time.RFC3339), "password": fmt.Sprint(salt != nil)}})
	out := SendOutput{RequestID: created.ID, Link: url, ExpiresAt: created.ExpiresAt.UTC(), KeepsCopy: keepsCopy, PasswordProtected: salt != nil}
	out.Message = sendMessage(out, in.Name)
	out.Delivery = DeliveryNote
	return out, nil
}

// List returns metadata for stored secrets, hiding internal records.
func (a *Agent) List(ctx context.Context) ([]storage.Metadata, error) {
	all, err := a.Store.List(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]storage.Metadata, 0, len(all))
	for _, m := range all {
		if isInternalKind(m.Kind) {
			continue
		}
		out = append(out, m)
	}
	return out, nil
}

// Delete removes a stored secret.
func (a *Agent) Delete(ctx context.Context, name string) error {
	if err := storage.ValidateName(name); err != nil {
		return err
	}
	if isInternalName(name) {
		return storage.ErrNotFound
	}
	err := a.Store.Delete(ctx, name)
	result := "deleted"
	if err != nil {
		result = "error"
	}
	a.Redactor.Remove(name)
	a.log(Event{Event: "delete_secret", Name: name, Result: result, Detail: a.safeErr(err)})
	return err
}

// Revoke cancels a pending request, or an unopened reveal created by Send,
// on the relay and forgets it locally. The id is the request_id that
// request_secret or send_secret returned. The returned state says whether
// the revocation came in time (revoked) or what happened first (fetched,
// opened, expired).
func (a *Agent) Revoke(ctx context.Context, requestID string) (string, error) {
	rec, err := a.loadPending(ctx, requestID)
	if errors.Is(err, ErrNoPending) {
		return a.revokeSent(ctx, requestID)
	}
	if err != nil {
		return "", err
	}
	storage.Zero(rec.PrivateKey)
	state, err := revokeState(a.Relay.RevokeDrop(ctx, rec.DropID, rec.UploadToken))
	if err != nil {
		return "", err
	}
	a.deletePending(ctx, rec.DropID)
	a.log(Event{Event: "revoke_request", Name: rec.Name, DropID: rec.DropID, Result: state})
	return state, nil
}

func (a *Agent) revokeSent(ctx context.Context, dropID string) (string, error) {
	rec, err := a.loadSent(ctx, dropID)
	if err != nil {
		return "", err
	}
	state, err := revokeState(a.Relay.RevokeReveal(ctx, rec.DropID, rec.RevokeToken))
	if err != nil {
		return "", err
	}
	a.deleteSent(ctx, rec.DropID)
	a.log(Event{Event: "revoke_request", Name: rec.Name, DropID: rec.DropID, Result: state, Fields: map[string]string{"kind": "reveal"}})
	return state, nil
}

// revokeState maps the relay's answer to a revoke into the slot's final
// state: revoked when it came in time, the terminal state the relay reports
// when it was too late, and expired when the relay no longer knows the id.
func revokeState(err error) (string, error) {
	var relayErr *client.Error
	switch {
	case err == nil:
		return client.StateRevoked, nil
	case errors.As(err, &relayErr) && relayErr.State != "":
		return relayErr.State, nil
	case client.IsCode(err, client.CodeNotFound):
		return client.StateExpired, nil
	default:
		return "", err
	}
}

// Load registers every stored session value with the redactor is not
// possible without reading values, so the redactor learns values lazily as
// they are fetched or used. LoadRedactions primes it from the given names,
// for callers that know a run will print output.
func (a *Agent) LoadRedactions(ctx context.Context, names ...string) {
	for _, n := range names {
		if v, _, err := a.Store.Get(ctx, n); err == nil {
			a.Redactor.Add(n, v)
			storage.Zero(v)
		}
	}
}

func (a *Agent) log(e Event) {
	if a.Audit == nil {
		return
	}
	_ = a.Audit.Log(e)
}

// safeErr returns an error string for the audit log with every value the
// process has handled redacted, so a backend or relay error that echoes a
// value cannot carry it into the log.
func (a *Agent) safeErr(err error) string {
	if err == nil {
		return ""
	}
	return a.Redactor.Redact(err.Error())
}

func bytesReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }
