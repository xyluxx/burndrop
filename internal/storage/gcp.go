// Google Cloud Secret Manager backend, driven through the gcloud CLI.
//
// Written against the Google Cloud CLI (gcloud, September 2026) reference at
// https://docs.cloud.google.com/sdk/gcloud/reference/secrets/ (create,
// versions add, versions access, describe, delete, list), the auth list
// page, the Secret resource and its label rules at
// https://docs.cloud.google.com/secret-manager/docs/reference/rest/v1/projects.secrets
// and the quotas at https://docs.cloud.google.com/secret-manager/quotas.

package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// DefaultGCPPrefix is prepended to every burndrop name to form the secret ID.
const DefaultGCPPrefix = "burndrop-"

const (
	// gcpMaxRecordBytes is the secret payload limit (64 KiB).
	gcpMaxRecordBytes = 64 * 1024
	// gcpMaxValueBytes is the largest value whose record is sure to fit: the
	// base64 form grows the value by a third and about 1 KiB is kept for the
	// metadata part of the record.
	gcpMaxValueBytes = (gcpMaxRecordBytes - 1024) / 4 * 3
)

// gcpIDRe covers what a secret ID may contain: letters, digits, underscore
// and dash, up to 255 characters.
var gcpIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,255}$`)

// GCP stores records in Google Cloud Secret Manager through the gcloud CLI.
// One burndrop secret is one Secret Manager secret with ID Prefix+name,
// labelled burndrop=1, whose latest version holds the JSON record. The
// payload goes to gcloud on standard input (--data-file=-), never as an
// argument. Authentication is whatever gcloud is signed in with.
type GCP struct {
	Project string // passed as --project when set; otherwise the gcloud default
	Prefix  string // secret ID prefix; DefaultGCPPrefix if empty
	Runner  Runner // ExecRunner{} if nil
}

// NewGCP fills in the defaults.
func NewGCP(opts GCP) *GCP {
	if opts.Prefix == "" {
		opts.Prefix = DefaultGCPPrefix
	}
	if opts.Runner == nil {
		opts.Runner = ExecRunner{}
	}
	return &opts
}

func (g *GCP) Name() string { return "gcp" }

func (g *GCP) runner() Runner {
	if g.Runner == nil {
		return ExecRunner{}
	}
	return g.Runner
}

func (g *GCP) prefix() string {
	if g.Prefix == "" {
		return DefaultGCPPrefix
	}
	return g.Prefix
}

// remote maps a burndrop name to a secret ID. Secret IDs do not allow dots,
// so a name with a dot has its dots replaced by dashes and gets a short hash
// suffix that keeps distinct names distinct. The record carries the original
// name and Get checks it.
func (g *GCP) remote(name string) (string, error) {
	if err := ValidateName(name); err != nil {
		return "", err
	}
	id := g.prefix() + gcpMapName(name)
	if !gcpIDRe.MatchString(id) {
		return "", fmt.Errorf("%w: %q is not a valid Secret Manager secret ID (check GCP.Prefix)", ErrInvalidName, id)
	}
	return id, nil
}

func gcpMapName(name string) string {
	if !strings.Contains(name, ".") {
		return name
	}
	sum := sha256.Sum256([]byte(name))
	return strings.ReplaceAll(name, ".", "-") + "-" + hex.EncodeToString(sum[:4])
}

// run executes one gcloud command.
func (g *GCP) run(ctx context.Context, stdin []byte, args ...string) ([]byte, error) {
	return g.runner().Run(ctx, "gcloud", args, stdin, nil)
}

// secrets runs a gcloud secrets subcommand with the project flag when set.
func (g *GCP) secrets(ctx context.Context, stdin []byte, args ...string) ([]byte, error) {
	full := append([]string{"secrets"}, args...)
	if g.Project != "" {
		full = append(full, "--project="+g.Project)
	}
	return g.run(ctx, stdin, full...)
}

func (g *GCP) Probe(ctx context.Context) Probe {
	if _, err := g.runner().LookPath("gcloud"); err != nil {
		return Probe{Reason: "gcloud not found in PATH; install the Google Cloud CLI (https://cloud.google.com/sdk/docs/install)"}
	}
	if _, err := g.remote("probe"); err != nil {
		return Probe{Reason: err.Error()}
	}
	out, err := g.run(ctx, nil, "auth", "list", "--filter=status:ACTIVE", "--format=json")
	if err != nil {
		return Probe{Reason: "gcloud auth list failed: " + shortErr(err)}
	}
	var accounts []struct {
		Account string `json:"account"`
		Status  string `json:"status"`
	}
	if err := json.Unmarshal(out, &accounts); err != nil || len(accounts) == 0 || accounts[0].Account == "" {
		return Probe{Reason: "gcloud found but no account is signed in; run gcloud auth login"}
	}
	project := g.Project
	if project == "" {
		out, err := g.run(ctx, nil, "config", "get-value", "project")
		if err == nil {
			project = strings.TrimSpace(string(out))
		}
		if project == "" || project == "(unset)" {
			return Probe{Reason: "gcloud has no default project; set GCP.Project or run gcloud config set project PROJECT_ID"}
		}
	}
	return Probe{Available: true, Reason: fmt.Sprintf("Google Secret Manager as %s, project %s", accounts[0].Account, project), Rank: 91}
}

func (g *GCP) Put(ctx context.Context, name string, value []byte, meta Metadata) error {
	id, err := g.remote(name)
	if err != nil {
		return err
	}
	if len(value) > gcpMaxValueBytes {
		return ErrTooLarge
	}
	meta.Name = name
	meta.Backend = g.Name()
	meta.SizeBytes = len(value)
	rec, err := encodeRecord(meta, value)
	if err != nil {
		return err
	}
	if len(rec) > gcpMaxRecordBytes {
		return ErrTooLarge
	}
	// New names are the common case: create with the first version, and add
	// a version when the secret already exists. The payload travels on stdin.
	_, err = g.secrets(ctx, rec, "create", id, "--data-file=-", "--replication-policy=automatic", "--labels=burndrop=1")
	if err != nil && strings.Contains(gcpStderr(err), "already_exists") {
		_, err = g.secrets(ctx, rec, "versions", "add", id, "--data-file=-")
	}
	return gcpClassify(err)
}

// fetch returns the payload of the latest version.
func (g *GCP) fetch(ctx context.Context, id string) ([]byte, error) {
	out, err := g.secrets(ctx, nil, "versions", "access", "latest", "--secret="+id)
	if err != nil {
		return nil, gcpClassify(err)
	}
	return out, nil
}

func (g *GCP) Get(ctx context.Context, name string) ([]byte, Metadata, error) {
	id, err := g.remote(name)
	if err != nil {
		return nil, Metadata{}, err
	}
	rec, err := g.fetch(ctx, id)
	if err != nil {
		return nil, Metadata{}, err
	}
	value, m, err := decodeRecord(rec)
	if err != nil {
		return nil, Metadata{}, fmt.Errorf("storage: gcp: %s: %w", id, err)
	}
	if m.Name != name {
		return nil, Metadata{}, ErrNotFound
	}
	return value, m, nil
}

// Delete removes the secret and every version. The reference says deleting
// a missing secret is a no-op, so the secret is looked up first.
func (g *GCP) Delete(ctx context.Context, name string) error {
	id, err := g.remote(name)
	if err != nil {
		return err
	}
	if _, err := g.secrets(ctx, nil, "describe", id, "--format=json"); err != nil {
		return gcpClassify(err)
	}
	_, err = g.secrets(ctx, nil, "delete", id, "--quiet")
	return gcpClassify(err)
}

// List enumerates the secrets labelled burndrop=1 under the prefix. The list
// call returns names only, so this costs one versions access call per secret
// on top of it. Entries that are not burndrop records are skipped.
func (g *GCP) List(ctx context.Context) ([]Metadata, error) {
	if _, err := g.remote("probe"); err != nil {
		return nil, err
	}
	out, err := g.secrets(ctx, nil, "list", "--filter=labels.burndrop=1", "--format=json")
	if err != nil {
		return nil, gcpClassify(err)
	}
	var items []struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(out, &items); err != nil {
		return nil, fmt.Errorf("storage: gcp: unexpected secrets list output: %w", err)
	}
	list := make([]Metadata, 0, len(items))
	for _, item := range items {
		id := item.Name[strings.LastIndex(item.Name, "/")+1:]
		if !strings.HasPrefix(id, g.prefix()) {
			continue
		}
		rec, err := g.fetch(ctx, id)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if _, m, err := decodeRecord(rec); err == nil {
			if r, err := g.remote(m.Name); err == nil && r == id {
				list = append(list, m)
			}
		}
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	return list, nil
}

// gcpStderr returns the lower-cased stderr of a failed gcloud command, or ""
// when err is not an exit error.
func gcpStderr(err error) string {
	var exit *ExitError
	if errors.As(err, &exit) {
		return strings.ToLower(exit.Stderr)
	}
	return ""
}

// gcpClassify maps gcloud failures to storage errors. NOT_FOUND becomes
// ErrNotFound; a missing login, expired credentials or PERMISSION_DENIED
// become ErrPermission.
func gcpClassify(err error) error {
	if err == nil {
		return nil
	}
	low := gcpStderr(err)
	for _, hint := range []string{"active account", "permission_denied", "reauthentication", "invalid_grant", "could not find default credentials", "gcloud auth login"} {
		if strings.Contains(low, hint) {
			return fmt.Errorf("%w: %v", ErrPermission, err)
		}
	}
	return classifyExit(err, "NOT_FOUND")
}
