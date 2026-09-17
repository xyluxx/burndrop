package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// The 1Password backend drives the 1Password CLI 2 (op). It was written
// against op 2.39.0 (August 2026) and these reference pages:
//
//	https://www.1password.dev/cli/reference/management-commands/item
//	https://www.1password.dev/cli/reference/commands/whoami
//	https://www.1password.dev/cli/item-template-json/
//
// The value never appears in an argument: "op item create -" and
// "op item edit <item>" both read a JSON item template from standard input,
// and the template carries the record in a concealed field.

// OnePasswordOptions configures the 1Password backend.
type OnePasswordOptions struct {
	// Vault is the vault name or ID items are filed in. Empty uses op's
	// default vault for new items and searches every vault.
	Vault string
	// Account selects the account (shorthand, sign-in address, or ID) when
	// several are signed in. Empty uses op's default.
	Account string
	// Runner executes op. Nil means ExecRunner{}.
	Runner Runner
}

// OnePassword stores each secret as a Secure Note item titled
// "burndrop/<name>", tagged "burndrop", with the JSON record in a concealed
// field labelled "record".
type OnePassword struct {
	opts OnePasswordOptions
	mu   sync.Mutex // serializes writers so two Puts of one name cannot both create
}

// NewOnePassword returns a backend using opts.
func NewOnePassword(opts OnePasswordOptions) *OnePassword {
	if opts.Runner == nil {
		opts.Runner = ExecRunner{}
	}
	return &OnePassword{opts: opts}
}

const (
	onePasswordTitlePrefix = "burndrop/"
	onePasswordTag         = "burndrop"
	onePasswordFieldLabel  = "record"
)

// onePasswordTemplate is the item JSON template op reads from stdin.
type onePasswordTemplate struct {
	Title    string             `json:"title"`
	Category string             `json:"category"`
	Tags     []string           `json:"tags"`
	Fields   []onePasswordField `json:"fields"`
}

type onePasswordField struct {
	ID    string `json:"id"`
	Type  string `json:"type"`
	Label string `json:"label"`
	Value string `json:"value"`
}

// onePasswordListItem is the part of "op item list --format json" output
// the backend uses. The list output carries no field values.
type onePasswordListItem struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

func (o *OnePassword) Name() string { return "onepassword" }

func onePasswordTitle(name string) string { return onePasswordTitlePrefix + name }

// run executes op, adding --account when one is configured.
func (o *OnePassword) run(ctx context.Context, stdin []byte, args ...string) ([]byte, error) {
	if o.opts.Account != "" {
		args = append(args, "--account", o.opts.Account)
	}
	return o.opts.Runner.Run(ctx, "op", args, stdin, nil)
}

// vaultArgs appends --vault when one is configured.
func (o *OnePassword) vaultArgs(args ...string) []string {
	if o.opts.Vault != "" {
		args = append(args, "--vault", o.opts.Vault)
	}
	return args
}

func (o *OnePassword) Probe(ctx context.Context) Probe {
	if _, err := o.opts.Runner.LookPath("op"); err != nil {
		return Probe{Reason: "1Password CLI (op) is not installed; install it from https://developer.1password.com/docs/cli/get-started/ and run op signin"}
	}
	out, err := o.run(ctx, nil, "whoami", "--format", "json")
	if err != nil {
		return Probe{Reason: "op is installed but not signed in (" + onePasswordErrText(err) + "); run op signin"}
	}
	var who struct {
		URL   string `json:"url"`
		Email string `json:"email"`
	}
	_ = json.Unmarshal(out, &who)
	reason := "signed in"
	switch {
	case who.Email != "" && who.URL != "":
		reason += " as " + who.Email + " at " + who.URL
	case who.Email != "":
		reason += " as " + who.Email
	case who.URL != "":
		reason += " to " + who.URL
	}
	if o.opts.Vault != "" {
		reason += ", vault " + o.opts.Vault
	}
	return Probe{Available: true, Reason: reason, Rank: 95}
}

func (o *OnePassword) Put(ctx context.Context, name string, value []byte, meta Metadata) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	meta.Name = name
	meta.Backend = o.Name()
	meta.SizeBytes = len(value)
	rec, err := encodeRecord(meta, value)
	if err != nil {
		return err
	}
	tmpl, err := json.Marshal(onePasswordTemplate{
		Title:    onePasswordTitle(name),
		Category: "SECURE_NOTE",
		Tags:     []string{onePasswordTag},
		Fields:   []onePasswordField{{ID: onePasswordFieldLabel, Type: "CONCEALED", Label: onePasswordFieldLabel, Value: string(rec)}},
	})
	Zero(rec)
	if err != nil {
		return err
	}
	defer Zero(tmpl)
	o.mu.Lock()
	defer o.mu.Unlock()
	id, err := o.find(ctx, name)
	if err != nil {
		return err
	}
	if id != "" {
		_, err = o.run(ctx, tmpl, o.vaultArgs("item", "edit", id)...)
	} else {
		_, err = o.run(ctx, tmpl, append(o.vaultArgs("item", "create"), "-")...)
	}
	return onePasswordClassify(err)
}

// find returns the ID of the item titled for name, or "" when there is none.
func (o *OnePassword) find(ctx context.Context, name string) (string, error) {
	items, err := o.list(ctx)
	if err != nil {
		return "", err
	}
	title := onePasswordTitle(name)
	for _, it := range items {
		if it.Title == title {
			return it.ID, nil
		}
	}
	return "", nil
}

// list enumerates the items tagged burndrop without reading any value.
func (o *OnePassword) list(ctx context.Context) ([]onePasswordListItem, error) {
	out, err := o.run(ctx, nil, o.vaultArgs("item", "list", "--tags", onePasswordTag, "--format", "json")...)
	if err != nil {
		return nil, onePasswordClassify(err)
	}
	if len(bytes.TrimSpace(out)) == 0 {
		return nil, nil
	}
	var items []onePasswordListItem
	if err := json.Unmarshal(out, &items); err != nil {
		return nil, fmt.Errorf("storage: onepassword: unexpected output from op item list: %w", err)
	}
	return items, nil
}

func (o *OnePassword) Get(ctx context.Context, name string) ([]byte, Metadata, error) {
	if err := ValidateName(name); err != nil {
		return nil, Metadata{}, err
	}
	raw, err := o.field(ctx, onePasswordTitle(name))
	if err != nil {
		return nil, Metadata{}, err
	}
	value, meta, err := decodeRecord(raw)
	Zero(raw)
	if err != nil {
		return nil, Metadata{}, err
	}
	if meta.Name != name {
		Zero(value)
		return nil, Metadata{}, fmt.Errorf("%w: item %q holds the record of %q", ErrNotFound, onePasswordTitle(name), meta.Name)
	}
	return value, meta, nil
}

// field reads the record field of an item, given by title or ID.
func (o *OnePassword) field(ctx context.Context, item string) ([]byte, error) {
	out, err := o.run(ctx, nil, o.vaultArgs("item", "get", item, "--fields", "label="+onePasswordFieldLabel, "--format", "json", "--reveal")...)
	if err != nil {
		return nil, onePasswordClassify(err)
	}
	defer Zero(out)
	return onePasswordFieldValue(out)
}

// onePasswordFieldValue extracts the value from "op item get --fields
// --format json" output: one field object, or an array when several fields
// were requested.
func onePasswordFieldValue(out []byte) ([]byte, error) {
	type field struct {
		Label string `json:"label"`
		Value string `json:"value"`
	}
	out = bytes.TrimSpace(out)
	if len(out) == 0 {
		return nil, errors.New("storage: onepassword: item has no record field")
	}
	if out[0] == '[' {
		var fields []field
		if err := json.Unmarshal(out, &fields); err != nil {
			return nil, fmt.Errorf("storage: onepassword: unexpected output from op item get: %w", err)
		}
		for _, f := range fields {
			if f.Label == onePasswordFieldLabel {
				return []byte(f.Value), nil
			}
		}
		return nil, errors.New("storage: onepassword: item has no record field")
	}
	var f field
	if err := json.Unmarshal(out, &f); err != nil {
		return nil, fmt.Errorf("storage: onepassword: unexpected output from op item get: %w", err)
	}
	return []byte(f.Value), nil
}

func (o *OnePassword) Delete(ctx context.Context, name string) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	_, err := o.run(ctx, nil, o.vaultArgs("item", "delete", onePasswordTitle(name))...)
	return onePasswordClassify(err)
}

// List enumerates the items tagged burndrop, then reads each record for its
// metadata. Values are decoded in memory and discarded.
func (o *OnePassword) List(ctx context.Context) ([]Metadata, error) {
	items, err := o.list(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Metadata, 0, len(items))
	for _, it := range items {
		name, ok := strings.CutPrefix(it.Title, onePasswordTitlePrefix)
		if !ok || ValidateName(name) != nil {
			continue
		}
		raw, err := o.field(ctx, it.ID)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				continue // removed between the two calls
			}
			return nil, err
		}
		value, meta, err := decodeRecord(raw)
		Zero(value)
		Zero(raw)
		if err != nil || meta.Name != name {
			continue // not a burndrop record; leave it alone
		}
		out = append(out, meta)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Name < out[b].Name })
	return out, nil
}

// onePasswordClassify maps op failures onto the storage errors. op reports
// a missing item as `"<ref>" isn't an item` and a missing session as
// "You are not currently signed in".
func onePasswordClassify(err error) error {
	if err == nil {
		return nil
	}
	var exit *ExitError
	if errors.As(err, &exit) {
		low := strings.ToLower(exit.Stderr)
		switch {
		case strings.Contains(low, "not currently signed in"), strings.Contains(low, "no accounts configured"),
			strings.Contains(low, "no account found"), strings.Contains(low, "session expired"):
			return fmt.Errorf("%w: %v", ErrPermission, err)
		case strings.Contains(low, "more than one item matches"):
			return fmt.Errorf("storage: onepassword: ambiguous item title, remove the duplicate in 1Password: %v", err)
		}
	}
	return classifyExit(err, "isn't an item")
}

// onePasswordErrText returns op's message without its "[ERROR] date time"
// prefix, first line only, truncated.
func onePasswordErrText(err error) string {
	var exit *ExitError
	if !errors.As(err, &exit) || exit.Stderr == "" {
		return shortErr(err)
	}
	s := exit.Stderr
	if strings.HasPrefix(s, "[ERROR]") {
		if parts := strings.SplitN(s, " ", 4); len(parts) == 4 {
			s = parts[3]
		}
	}
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return shortErr(errors.New(s))
}
