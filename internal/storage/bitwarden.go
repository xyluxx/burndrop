package storage

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// The Bitwarden backend drives the Bitwarden CLI (bw). It was written
// against @bitwarden/cli 2026.8.0, https://bitwarden.com/help/cli/ (the
// create, edit, list, delete, status and session sections) and the command
// sources in github.com/bitwarden/clients under apps/cli/src.
//
// "bw create item" and "bw edit item <id>" read a base64 encoded item JSON
// from standard input when the encodedJson argument is omitted, so the value
// never appears in an argument. Every call carries --nointeraction so a
// locked vault fails instead of prompting for the master password. The
// session key comes from BW_SESSION, inherited from the environment or set
// from BitwardenOptions.Session.

// BitwardenOptions configures the Bitwarden backend.
type BitwardenOptions struct {
	// Session is the key printed by "bw unlock --raw". It is passed to bw as
	// BW_SESSION. Empty inherits BW_SESSION from the environment.
	Session string
	// Runner executes bw. Nil means ExecRunner{}.
	Runner Runner
}

// BitwardenMaxValueBytes is the largest value the backend accepts. The
// Bitwarden server caps an encrypted note at 10,000 characters and the
// record adds base64 and metadata overhead on top of the value.
const BitwardenMaxValueBytes = 4 * 1024

const (
	bitwardenTitlePrefix = "burndrop/"
	bitwardenNotesLimit  = 10000 // characters of the encrypted note string
	bitwardenTypeNote    = 2     // item type: Secure Note
)

// Bitwarden stores each secret as a Secure Note named "burndrop/<name>"
// whose notes hold the JSON record.
type Bitwarden struct {
	opts BitwardenOptions
	mu   sync.Mutex // bw rewrites its local data file on every write; one bw at a time per process
}

// NewBitwarden returns a backend using opts.
func NewBitwarden(opts BitwardenOptions) *Bitwarden {
	if opts.Runner == nil {
		opts.Runner = ExecRunner{}
	}
	return &Bitwarden{opts: opts}
}

// bitwardenItem is the subset of the CLI's item JSON the backend reads and
// writes. A Secure Note has type 2 and secureNote.type 0.
type bitwardenItem struct {
	ID             string        `json:"id,omitempty"`
	OrganizationID *string       `json:"organizationId"`
	CollectionIDs  []string      `json:"collectionIds"`
	FolderID       *string       `json:"folderId"`
	Type           int           `json:"type"`
	Name           string        `json:"name"`
	Notes          string        `json:"notes"`
	Favorite       bool          `json:"favorite"`
	SecureNote     bitwardenNote `json:"secureNote"`
	Reprompt       int           `json:"reprompt"`
	DeletedDate    *string       `json:"deletedDate,omitempty"`
}

type bitwardenNote struct {
	Type int `json:"type"`
}

func (b *Bitwarden) Name() string { return "bitwarden" }

func bitwardenTitle(name string) string { return bitwardenTitlePrefix + name }

// run executes bw with --nointeraction and the session key.
func (b *Bitwarden) run(ctx context.Context, stdin []byte, args ...string) ([]byte, error) {
	args = append(args, "--nointeraction")
	var env []string
	if b.opts.Session != "" {
		env = []string{"BW_SESSION=" + b.opts.Session}
	}
	return b.opts.Runner.Run(ctx, "bw", args, stdin, env)
}

func (b *Bitwarden) Probe(ctx context.Context) Probe {
	if _, err := b.opts.Runner.LookPath("bw"); err != nil {
		return Probe{Reason: "Bitwarden CLI (bw) is not installed; install it with npm install -g @bitwarden/cli (https://bitwarden.com/help/cli/) and run bw login"}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	out, err := b.run(ctx, nil, "status")
	if err != nil {
		return Probe{Reason: "bw status failed: " + shortErr(err)}
	}
	var st struct {
		ServerURL string `json:"serverUrl"`
		UserEmail string `json:"userEmail"`
		Status    string `json:"status"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(out), &st); err != nil {
		return Probe{Reason: "bw status returned unexpected output"}
	}
	who := ""
	if st.UserEmail != "" {
		who = " for " + st.UserEmail
	}
	switch st.Status {
	case "unlocked":
		reason := "vault unlocked" + who
		if st.ServerURL != "" {
			reason += " at " + st.ServerURL
		}
		return Probe{Available: true, Reason: reason, Rank: 94}
	case "locked":
		return Probe{Reason: "bw vault is locked" + who + "; run bw unlock and export BW_SESSION"}
	default:
		return Probe{Reason: "bw is not logged in; run bw login, then bw unlock and export BW_SESSION"}
	}
}

func (b *Bitwarden) Put(ctx context.Context, name string, value []byte, meta Metadata) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	if len(value) > BitwardenMaxValueBytes {
		return fmt.Errorf("%w: bitwarden notes hold at most %d bytes per value", ErrTooLarge, BitwardenMaxValueBytes)
	}
	meta.Name = name
	meta.Backend = b.Name()
	meta.SizeBytes = len(value)
	rec, err := encodeRecord(meta, value)
	if err != nil {
		return err
	}
	defer Zero(rec)
	if n := bitwardenEncryptedLength(len(rec)); n > bitwardenNotesLimit {
		return fmt.Errorf("%w: the record would encrypt to %d characters and Bitwarden allows %d per note", ErrTooLarge, n, bitwardenNotesLimit)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	existing, err := b.find(ctx, name)
	if err != nil {
		return err
	}
	item := bitwardenItem{Type: bitwardenTypeNote, Name: bitwardenTitle(name), Notes: string(rec), SecureNote: bitwardenNote{Type: 0}}
	if len(existing) > 0 {
		cur := existing[0]
		item.OrganizationID, item.FolderID, item.CollectionIDs = cur.OrganizationID, cur.FolderID, cur.CollectionIDs
		encoded, err := bitwardenEncode(item)
		if err != nil {
			return err
		}
		defer Zero(encoded)
		_, err = b.run(ctx, encoded, "edit", "item", cur.ID)
		return bitwardenClassify(err)
	}
	encoded, err := bitwardenEncode(item)
	if err != nil {
		return err
	}
	defer Zero(encoded)
	_, err = b.run(ctx, encoded, "create", "item")
	return bitwardenClassify(err)
}

// bitwardenEncode produces the base64 JSON that bw create and bw edit read
// from standard input (what "bw encode" would print).
func bitwardenEncode(item bitwardenItem) ([]byte, error) {
	raw, err := json.Marshal(item)
	if err != nil {
		return nil, err
	}
	defer Zero(raw)
	return []byte(base64.StdEncoding.EncodeToString(raw)), nil
}

// bitwardenEncryptedLength estimates the length of the string the client
// uploads for n plaintext bytes: "2.<iv>|<ciphertext>|<mac>" with AES-CBC
// (PKCS#7 padding), a 16 byte IV and a 32 byte MAC, all base64.
func bitwardenEncryptedLength(n int) int {
	padded := (n/16 + 1) * 16
	ciphertext := (padded + 2) / 3 * 4
	return 2 + 24 + 1 + ciphertext + 1 + 44
}

// find returns the live items named exactly like name's title. --search is
// a substring match, so the result is filtered on the exact name.
func (b *Bitwarden) find(ctx context.Context, name string) ([]bitwardenItem, error) {
	title := bitwardenTitle(name)
	items, err := b.search(ctx, title)
	if err != nil {
		return nil, err
	}
	var out []bitwardenItem
	for _, it := range items {
		if it.Name == title && it.DeletedDate == nil {
			out = append(out, it)
		}
	}
	return out, nil
}

func (b *Bitwarden) search(ctx context.Context, term string) ([]bitwardenItem, error) {
	out, err := b.run(ctx, nil, "list", "items", "--search", term)
	if err != nil {
		return nil, bitwardenClassify(err)
	}
	defer Zero(out)
	var items []bitwardenItem
	if err := json.Unmarshal(bytes.TrimSpace(out), &items); err != nil {
		return nil, fmt.Errorf("storage: bitwarden: unexpected output from bw list items: %w", err)
	}
	return items, nil
}

func (b *Bitwarden) Get(ctx context.Context, name string) ([]byte, Metadata, error) {
	if err := ValidateName(name); err != nil {
		return nil, Metadata{}, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	items, err := b.find(ctx, name)
	if err != nil {
		return nil, Metadata{}, err
	}
	if len(items) == 0 {
		return nil, Metadata{}, ErrNotFound
	}
	value, meta, err := decodeRecord([]byte(items[0].Notes))
	if err != nil {
		return nil, Metadata{}, err
	}
	if meta.Name != name {
		Zero(value)
		return nil, Metadata{}, fmt.Errorf("%w: item %q holds the record of %q", ErrNotFound, bitwardenTitle(name), meta.Name)
	}
	return value, meta, nil
}

// Delete removes every item carrying the name permanently rather than
// moving it to the trash, where it would stay readable for 30 days.
func (b *Bitwarden) Delete(ctx context.Context, name string) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	items, err := b.find(ctx, name)
	if err != nil {
		return err
	}
	if len(items) == 0 {
		return ErrNotFound
	}
	for _, it := range items {
		if _, err := b.run(ctx, nil, "delete", "item", it.ID, "--permanent"); err != nil {
			return bitwardenClassify(err)
		}
	}
	return nil
}

// List searches for the title prefix and decodes each record for its
// metadata. Values are decoded in memory and discarded.
func (b *Bitwarden) List(ctx context.Context) ([]Metadata, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	items, err := b.search(ctx, bitwardenTitlePrefix)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	out := make([]Metadata, 0, len(items))
	for _, it := range items {
		name, ok := strings.CutPrefix(it.Name, bitwardenTitlePrefix)
		if !ok || it.DeletedDate != nil || ValidateName(name) != nil || seen[name] {
			continue
		}
		value, meta, err := decodeRecord([]byte(it.Notes))
		Zero(value)
		if err != nil || meta.Name != name {
			continue // not a burndrop record; leave it alone
		}
		seen[name] = true
		out = append(out, meta)
	}
	sort.Slice(out, func(x, y int) bool { return out[x].Name < out[y].Name })
	return out, nil
}

// bitwardenClassify maps bw failures onto the storage errors. bw prints
// "Not found." for a missing object, "Vault is locked." without a session
// and "You are not logged in." without an account; the server rejects an
// oversized note with "exceeds the maximum encrypted value length".
func bitwardenClassify(err error) error {
	if err == nil {
		return nil
	}
	var exit *ExitError
	if errors.As(err, &exit) && strings.Contains(strings.ToLower(exit.Stderr), "exceeds the maximum encrypted value length") {
		return fmt.Errorf("%w: %v", ErrTooLarge, err)
	}
	return classifyExit(err, "not found.")
}
