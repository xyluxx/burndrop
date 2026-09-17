// AWS Secrets Manager backend, driven through the aws CLI.
//
// Written against AWS CLI v2 (September 2026) and the command reference at
// https://docs.aws.amazon.com/cli/latest/reference/secretsmanager/ (the
// create-secret, put-secret-value, get-secret-value, describe-secret,
// delete-secret and list-secrets pages), the sts get-caller-identity page,
// the file:// parameter rules at
// https://docs.aws.amazon.com/cli/latest/userguide/cli-usage-parameters-file.html
// and the quotas at
// https://docs.aws.amazon.com/secretsmanager/latest/userguide/reference_limits.html.

package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

// DefaultAWSPrefix is prepended to every burndrop name to form the Secrets
// Manager secret name.
const DefaultAWSPrefix = "burndrop/"

const (
	// awsMaxRecordBytes is the SecretString limit.
	awsMaxRecordBytes = 65536
	// awsMaxValueBytes is the largest value whose record is sure to fit: the
	// base64 form grows the value by a third and about 1 KiB is kept for the
	// metadata part of the record.
	awsMaxValueBytes = (awsMaxRecordBytes - 1024) / 4 * 3
)

// awsNameRe covers the characters Secrets Manager allows in a secret name.
var awsNameRe = regexp.MustCompile(`^[A-Za-z0-9/_+=.@-]{1,512}$`)

// AWS stores records in AWS Secrets Manager through the aws CLI (v2). One
// burndrop secret is one Secrets Manager secret named Prefix+name whose
// SecretString is the JSON record. Credentials and the region come from the
// CLI's own configuration: profiles, environment variables, SSO sessions or
// an instance role. The record reaches the CLI through a temporary file
// (--secret-string file://...), never as an argument.
type AWS struct {
	Prefix  string // secret name prefix; DefaultAWSPrefix if empty
	Region  string // passed as --region when set
	Profile string // passed as --profile when set
	Runner  Runner // ExecRunner{} if nil
}

// NewAWS fills in the defaults.
func NewAWS(opts AWS) *AWS {
	if opts.Prefix == "" {
		opts.Prefix = DefaultAWSPrefix
	}
	if opts.Runner == nil {
		opts.Runner = ExecRunner{}
	}
	return &opts
}

func (a *AWS) Name() string { return "aws" }

func (a *AWS) runner() Runner {
	if a.Runner == nil {
		return ExecRunner{}
	}
	return a.Runner
}

func (a *AWS) prefix() string {
	if a.Prefix == "" {
		return DefaultAWSPrefix
	}
	return a.Prefix
}

// remote maps a burndrop name to the Secrets Manager name. Every character
// burndrop allows is allowed by Secrets Manager, so the name is kept as is.
func (a *AWS) remote(name string) (string, error) {
	if err := ValidateName(name); err != nil {
		return "", err
	}
	r := a.prefix() + name
	if !awsNameRe.MatchString(r) {
		return "", fmt.Errorf("%w: %q is not a valid Secrets Manager name (check AWS.Prefix)", ErrInvalidName, r)
	}
	return r, nil
}

// run executes one aws command with JSON output and the configured region
// and profile. AWS_CLI_FILE_ENCODING makes file:// parameters read as UTF-8
// on every platform; no secret goes through the environment.
func (a *AWS) run(ctx context.Context, args ...string) ([]byte, error) {
	full := append([]string(nil), args...)
	full = append(full, "--output", "json", "--no-cli-pager")
	if a.Region != "" {
		full = append(full, "--region", a.Region)
	}
	if a.Profile != "" {
		full = append(full, "--profile", a.Profile)
	}
	return a.runner().Run(ctx, "aws", full, nil, []string{"AWS_CLI_FILE_ENCODING=UTF-8"})
}

func (a *AWS) Probe(ctx context.Context) Probe {
	if _, err := a.runner().LookPath("aws"); err != nil {
		return Probe{Reason: "aws CLI not found in PATH; install AWS CLI v2 (https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)"}
	}
	if _, err := a.remote("probe"); err != nil {
		return Probe{Reason: err.Error()}
	}
	out, err := a.run(ctx, "sts", "get-caller-identity")
	if err != nil {
		return Probe{Reason: "aws CLI found but no usable credentials (run aws configure or aws sso login): " + shortErr(err)}
	}
	var id struct {
		Account string `json:"Account"`
		Arn     string `json:"Arn"`
	}
	if err := json.Unmarshal(out, &id); err != nil || id.Arn == "" {
		return Probe{Reason: "aws sts get-caller-identity returned no identity"}
	}
	reason := fmt.Sprintf("AWS Secrets Manager as %s (account %s)", id.Arn, id.Account)
	if a.Region != "" {
		reason += " in " + a.Region
	}
	return Probe{Available: true, Reason: reason, Rank: 85}
}

func (a *AWS) Put(ctx context.Context, name string, value []byte, meta Metadata) error {
	remote, err := a.remote(name)
	if err != nil {
		return err
	}
	if len(value) > awsMaxValueBytes {
		return ErrTooLarge
	}
	meta.Name = name
	meta.Backend = a.Name()
	meta.SizeBytes = len(value)
	rec, err := encodeRecord(meta, value)
	if err != nil {
		return err
	}
	if len(rec) > awsMaxRecordBytes {
		return ErrTooLarge
	}
	path, remove, err := awsTempFile(rec)
	if err != nil {
		return err
	}
	defer remove()
	arg := "file://" + path
	// New names are the common case: create first, add a version when the
	// secret already exists.
	_, err = a.run(ctx, "secretsmanager", "create-secret", "--name", remote, "--description", "burndrop record", "--secret-string", arg)
	if err == nil {
		return nil
	}
	low := awsStderr(err)
	switch {
	case strings.Contains(low, "resourceexistsexception"):
		_, err = a.run(ctx, "secretsmanager", "put-secret-value", "--secret-id", remote, "--secret-string", arg)
		return awsClassify(err)
	case strings.Contains(low, "scheduled for deletion"):
		return fmt.Errorf("storage: aws: secret %q is scheduled for deletion; restore it (aws secretsmanager restore-secret) or wait for its recovery window: %w", remote, err)
	}
	return awsClassify(err)
}

// fetch returns the SecretString of a secret.
func (a *AWS) fetch(ctx context.Context, remote string) ([]byte, error) {
	out, err := a.run(ctx, "secretsmanager", "get-secret-value", "--secret-id", remote)
	if err != nil {
		return nil, awsClassify(err)
	}
	var resp struct {
		SecretString string `json:"SecretString"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		return nil, fmt.Errorf("storage: aws: unexpected get-secret-value output: %w", err)
	}
	return []byte(resp.SecretString), nil
}

func (a *AWS) Get(ctx context.Context, name string) ([]byte, Metadata, error) {
	remote, err := a.remote(name)
	if err != nil {
		return nil, Metadata{}, err
	}
	rec, err := a.fetch(ctx, remote)
	if err != nil {
		return nil, Metadata{}, err
	}
	value, m, err := decodeRecord(rec)
	if err != nil {
		return nil, Metadata{}, fmt.Errorf("storage: aws: %s: %w", remote, err)
	}
	if m.Name != name {
		return nil, Metadata{}, ErrNotFound
	}
	return value, m, nil
}

// Delete removes the secret at once. The forced delete skips the recovery
// window so the name can be reused immediately; the price is that there is
// no undelete.
func (a *AWS) Delete(ctx context.Context, name string) error {
	remote, err := a.remote(name)
	if err != nil {
		return err
	}
	// A forced delete of a missing secret succeeds, so look first. A secret
	// already scheduled for deletion counts as gone.
	out, err := a.run(ctx, "secretsmanager", "describe-secret", "--secret-id", remote)
	if err != nil {
		return awsClassify(err)
	}
	if awsScheduledForDeletion(out) {
		return ErrNotFound
	}
	_, err = a.run(ctx, "secretsmanager", "delete-secret", "--secret-id", remote, "--force-delete-without-recovery")
	return awsClassify(err)
}

// List enumerates the secrets under the prefix. Secrets Manager lists names
// and tags only, so this costs one get-secret-value call per secret on top of
// the list call. Entries that are not burndrop records are skipped.
func (a *AWS) List(ctx context.Context) ([]Metadata, error) {
	if _, err := a.remote("probe"); err != nil {
		return nil, err
	}
	out, err := a.run(ctx, "secretsmanager", "list-secrets", "--filters", "Key=name,Values="+a.prefix())
	if err != nil {
		return nil, awsClassify(err)
	}
	var resp struct {
		SecretList []json.RawMessage `json:"SecretList"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		return nil, fmt.Errorf("storage: aws: unexpected list-secrets output: %w", err)
	}
	list := make([]Metadata, 0, len(resp.SecretList))
	for _, item := range resp.SecretList {
		var s struct {
			Name string `json:"Name"`
		}
		if json.Unmarshal(item, &s) != nil || !strings.HasPrefix(s.Name, a.prefix()) || awsScheduledForDeletion(item) {
			continue
		}
		name := strings.TrimPrefix(s.Name, a.prefix())
		if ValidateName(name) != nil {
			continue
		}
		rec, err := a.fetch(ctx, s.Name)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if _, m, err := decodeRecord(rec); err == nil && m.Name == name {
			list = append(list, m)
		}
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	return list, nil
}

// awsScheduledForDeletion reports whether a describe-secret or list-secrets
// entry carries a DeletedDate (printed as a string or a number depending on
// the CLI's timestamp format).
func awsScheduledForDeletion(item []byte) bool {
	var d struct {
		DeletedDate json.RawMessage `json:"DeletedDate"`
	}
	if err := json.Unmarshal(item, &d); err != nil {
		return false
	}
	return len(d.DeletedDate) > 0 && string(d.DeletedDate) != "null"
}

// awsTempFile writes rec to a fresh file with mode 0600 in the temporary
// directory. The caller removes it as soon as the CLI has returned.
func awsTempFile(rec []byte) (path string, remove func(), err error) {
	f, err := os.CreateTemp("", "burndrop-*.json")
	if err != nil {
		return "", nil, fmt.Errorf("storage: aws: temp file: %w", err)
	}
	remove = func() { _ = os.Remove(f.Name()) }
	if _, err := f.Write(rec); err != nil {
		_ = f.Close()
		remove()
		return "", nil, fmt.Errorf("storage: aws: temp file: %w", err)
	}
	if err := f.Close(); err != nil {
		remove()
		return "", nil, fmt.Errorf("storage: aws: temp file: %w", err)
	}
	return f.Name(), remove, nil
}

// awsStderr returns the lower-cased stderr of a failed aws command, or ""
// when err is not an exit error.
func awsStderr(err error) string {
	var exit *ExitError
	if errors.As(err, &exit) {
		return strings.ToLower(exit.Stderr)
	}
	return ""
}

// awsClassify maps aws CLI failures to storage errors. Credential problems
// that classifyExit does not know about are mapped to ErrPermission first.
func awsClassify(err error) error {
	if err == nil {
		return nil
	}
	low := awsStderr(err)
	for _, hint := range []string{"unable to locate credentials", "expiredtoken", "invalidclienttokenid", "unrecognizedclient", "security token", "not authorized", "sso session", "token has expired"} {
		if strings.Contains(low, hint) {
			return fmt.Errorf("%w: %v", ErrPermission, err)
		}
	}
	return classifyExit(err, "ResourceNotFoundException", "marked for deletion")
}
