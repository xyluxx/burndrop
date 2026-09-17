// Azure Key Vault backend, driven through the az CLI.
//
// Written against Azure CLI 2.x (reference dated 2026-06-29) at
// https://learn.microsoft.com/cli/azure/keyvault/secret (set, show, delete,
// purge, list) and https://learn.microsoft.com/cli/azure/account (show), the
// object name rules at
// https://learn.microsoft.com/azure/key-vault/general/about-keys-secrets-certificates,
// the secret limits at
// https://learn.microsoft.com/azure/key-vault/secrets/about-secrets and the
// soft delete rules at
// https://learn.microsoft.com/azure/key-vault/general/soft-delete-overview.

package storage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

// DefaultAzurePrefix is prepended to every burndrop name to form the Key
// Vault secret name.
const DefaultAzurePrefix = "burndrop-"

const (
	// azureMaxRecordBytes is the secret value limit (25 KB).
	azureMaxRecordBytes = 25 * 1024
	// azureMaxValueBytes is the largest value whose record is sure to fit:
	// the base64 form grows the value by a third and about 1 KiB is kept for
	// the metadata part of the record.
	azureMaxValueBytes = (azureMaxRecordBytes - 1024) / 4 * 3
)

var (
	// azureNameRe covers what a Key Vault object name may contain.
	azureNameRe = regexp.MustCompile(`^[A-Za-z0-9-]{1,127}$`)
	// azurePlainRe matches burndrop names that need no rewriting.
	azurePlainRe = regexp.MustCompile(`^[a-z0-9-]+$`)
)

// Azure stores records in an Azure Key Vault through the az CLI. One
// burndrop secret is one Key Vault secret named Prefix+name, tagged
// burndrop=1, whose value is the JSON record. The record reaches the CLI
// through a temporary file (--file), never as an argument. Authentication is
// whatever az is signed in with: az login, a service principal or a managed
// identity.
//
// Key Vault soft deletes secrets: after Delete the name stays reserved for
// the vault's retention period (7 to 90 days) unless the secret is purged.
// Set Purge to purge right after deleting; that needs the secrets/purge
// permission and is refused on vaults with purge protection.
type Azure struct {
	VaultName string // the key vault name (https://<VaultName>.vault.azure.net); required
	Prefix    string // secret name prefix; DefaultAzurePrefix if empty
	Purge     bool   // purge after delete so the name is free at once
	Runner    Runner // ExecRunner{} if nil
}

// NewAzure fills in the defaults.
func NewAzure(opts Azure) *Azure {
	if opts.Prefix == "" {
		opts.Prefix = DefaultAzurePrefix
	}
	if opts.Runner == nil {
		opts.Runner = ExecRunner{}
	}
	return &opts
}

func (z *Azure) Name() string { return "azure" }

func (z *Azure) runner() Runner {
	if z.Runner == nil {
		return ExecRunner{}
	}
	return z.Runner
}

func (z *Azure) prefix() string {
	if z.Prefix == "" {
		return DefaultAzurePrefix
	}
	return z.Prefix
}

// ready reports whether the backend is configured.
func (z *Azure) ready() error {
	if z.VaultName == "" {
		return fmt.Errorf("%w: Azure.VaultName is not set", ErrUnavailable)
	}
	if !azureNameRe.MatchString(z.prefix() + "x") {
		return fmt.Errorf("%w: Azure.Prefix %q must be letters, digits and dashes", ErrInvalidName, z.prefix())
	}
	return nil
}

// remote maps a burndrop name to a Key Vault secret name. Key Vault names
// are letters, digits and dashes and compare case-insensitively, so a name
// that is not already lower-case letters, digits and dashes is lower-cased,
// has every other character replaced by a dash, and gets a short hash
// suffix that keeps distinct names distinct. The record carries the original
// name and Get checks it.
func (z *Azure) remote(name string) (string, error) {
	if err := ValidateName(name); err != nil {
		return "", err
	}
	if err := z.ready(); err != nil {
		return "", err
	}
	r := z.prefix() + azureMapName(name)
	if !azureNameRe.MatchString(r) {
		return "", fmt.Errorf("%w: %q is not a valid Key Vault secret name (shorten Azure.Prefix)", ErrInvalidName, r)
	}
	return r, nil
}

func azureMapName(name string) string {
	if azurePlainRe.MatchString(name) {
		return name
	}
	sum := sha256.Sum256([]byte(name))
	mapped := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			return r
		case r >= 'A' && r <= 'Z':
			return r + ('a' - 'A')
		default:
			return '-'
		}
	}, name)
	return mapped + "-" + hex.EncodeToString(sum[:4])
}

// run executes one az command with JSON output.
func (z *Azure) run(ctx context.Context, args ...string) ([]byte, error) {
	full := append([]string(nil), args...)
	full = append(full, "--output", "json", "--only-show-errors")
	return z.runner().Run(ctx, "az", full, nil, nil)
}

func (z *Azure) Probe(ctx context.Context) Probe {
	if _, err := z.runner().LookPath("az"); err != nil {
		return Probe{Reason: "az not found in PATH; install the Azure CLI (https://learn.microsoft.com/cli/azure/install-azure-cli)"}
	}
	if z.VaultName == "" {
		return Probe{Reason: "Azure.VaultName is not set"}
	}
	if err := z.ready(); err != nil {
		return Probe{Reason: err.Error()}
	}
	out, err := z.run(ctx, "account", "show")
	if err != nil {
		return Probe{Reason: "az found but not signed in (run az login): " + shortErr(err)}
	}
	var acct struct {
		Name  string `json:"name"`
		State string `json:"state"`
		User  struct {
			Name string `json:"name"`
		} `json:"user"`
	}
	if err := json.Unmarshal(out, &acct); err != nil || acct.Name == "" {
		return Probe{Reason: "az account show returned no subscription"}
	}
	return Probe{Available: true, Reason: fmt.Sprintf("Azure Key Vault %s as %s, subscription %s (%s)", z.VaultName, acct.User.Name, acct.Name, acct.State), Rank: 91}
}

func (z *Azure) Put(ctx context.Context, name string, value []byte, meta Metadata) error {
	remote, err := z.remote(name)
	if err != nil {
		return err
	}
	if len(value) > azureMaxValueBytes {
		return ErrTooLarge
	}
	meta.Name = name
	meta.Backend = z.Name()
	meta.SizeBytes = len(value)
	rec, err := encodeRecord(meta, value)
	if err != nil {
		return err
	}
	if len(rec) > azureMaxRecordBytes {
		return ErrTooLarge
	}
	path, remove, err := azureTempFile(rec)
	if err != nil {
		return err
	}
	defer remove()
	_, err = z.run(ctx, "keyvault", "secret", "set", "--vault-name", z.VaultName, "--name", remote, "--file", path, "--encoding", "utf-8", "--tags", "burndrop=1")
	if err != nil && strings.Contains(azureStderr(err), "deleted but recoverable") {
		return fmt.Errorf("storage: azure: secret %q is soft deleted in vault %s and its name is reserved until it is purged or recovered (az keyvault secret purge --vault-name %s --name %s, or set Azure.Purge): %w", remote, z.VaultName, z.VaultName, remote, err)
	}
	return azureClassify(err)
}

// fetch returns the value of a secret.
func (z *Azure) fetch(ctx context.Context, remote string) ([]byte, error) {
	out, err := z.run(ctx, "keyvault", "secret", "show", "--vault-name", z.VaultName, "--name", remote)
	if err != nil {
		return nil, azureClassify(err)
	}
	var resp struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		return nil, fmt.Errorf("storage: azure: unexpected secret show output: %w", err)
	}
	return []byte(resp.Value), nil
}

func (z *Azure) Get(ctx context.Context, name string) ([]byte, Metadata, error) {
	remote, err := z.remote(name)
	if err != nil {
		return nil, Metadata{}, err
	}
	rec, err := z.fetch(ctx, remote)
	if err != nil {
		return nil, Metadata{}, err
	}
	value, m, err := decodeRecord(rec)
	if err != nil {
		return nil, Metadata{}, fmt.Errorf("storage: azure: %s: %w", remote, err)
	}
	if m.Name != name {
		return nil, Metadata{}, ErrNotFound
	}
	return value, m, nil
}

// Delete soft deletes the secret and, when Purge is set, purges it so the
// name can be reused at once.
func (z *Azure) Delete(ctx context.Context, name string) error {
	remote, err := z.remote(name)
	if err != nil {
		return err
	}
	if _, err := z.run(ctx, "keyvault", "secret", "delete", "--vault-name", z.VaultName, "--name", remote); err != nil {
		return azureClassify(err)
	}
	if !z.Purge {
		return nil
	}
	return z.purge(ctx, remote)
}

// purge removes a soft deleted secret for good. Key Vault finishes the soft
// delete asynchronously, so a purge that arrives too early is retried a few
// times with a growing pause.
func (z *Azure) purge(ctx context.Context, remote string) error {
	var err error
	for attempt := 0; attempt < 5; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(attempt) * time.Second):
			}
		}
		_, err = z.run(ctx, "keyvault", "secret", "purge", "--vault-name", z.VaultName, "--name", remote)
		if err == nil {
			return nil
		}
		low := azureStderr(err)
		if !strings.Contains(low, "being deleted") && !strings.Contains(low, "conflict") {
			break
		}
	}
	return fmt.Errorf("storage: azure: %q is deleted but could not be purged, so its name stays reserved until the retention period ends (purge it with az keyvault secret purge): %w", remote, azureClassify(err))
}

// List enumerates the secrets tagged burndrop=1 under the prefix. The list
// call returns names and tags only, so this costs one secret show call per
// secret on top of it. Entries that are not burndrop records are skipped.
func (z *Azure) List(ctx context.Context) ([]Metadata, error) {
	if err := z.ready(); err != nil {
		return nil, err
	}
	out, err := z.run(ctx, "keyvault", "secret", "list", "--vault-name", z.VaultName, "--query", "[?tags.burndrop=='1']")
	if err != nil {
		return nil, azureClassify(err)
	}
	var items []struct {
		ID   string            `json:"id"`
		Name string            `json:"name"`
		Tags map[string]string `json:"tags"`
	}
	if err := json.Unmarshal(out, &items); err != nil {
		return nil, fmt.Errorf("storage: azure: unexpected secret list output: %w", err)
	}
	list := make([]Metadata, 0, len(items))
	for _, item := range items {
		name := item.Name
		if name == "" {
			name = item.ID[strings.LastIndex(item.ID, "/")+1:]
		}
		if item.Tags["burndrop"] != "1" || !strings.HasPrefix(strings.ToLower(name), strings.ToLower(z.prefix())) {
			continue
		}
		rec, err := z.fetch(ctx, name)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if _, m, err := decodeRecord(rec); err == nil {
			if r, err := z.remote(m.Name); err == nil && strings.EqualFold(r, name) {
				list = append(list, m)
			}
		}
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	return list, nil
}

// azureTempFile writes rec to a fresh file with mode 0600 in the temporary
// directory. The caller removes it as soon as the CLI has returned.
func azureTempFile(rec []byte) (path string, remove func(), err error) {
	f, err := os.CreateTemp("", "burndrop-*.json")
	if err != nil {
		return "", nil, fmt.Errorf("storage: azure: temp file: %w", err)
	}
	remove = func() { _ = os.Remove(f.Name()) }
	if _, err := f.Write(rec); err != nil {
		_ = f.Close()
		remove()
		return "", nil, fmt.Errorf("storage: azure: temp file: %w", err)
	}
	if err := f.Close(); err != nil {
		remove()
		return "", nil, fmt.Errorf("storage: azure: temp file: %w", err)
	}
	return f.Name(), remove, nil
}

// azureStderr returns the lower-cased stderr of a failed az command, or ""
// when err is not an exit error.
func azureStderr(err error) string {
	var exit *ExitError
	if errors.As(err, &exit) {
		return strings.ToLower(exit.Stderr)
	}
	return ""
}

// azureClassify maps az CLI failures to storage errors. SecretNotFound
// becomes ErrNotFound; a missing login, an expired token or a Forbidden
// answer from the vault become ErrPermission.
func azureClassify(err error) error {
	if err == nil {
		return nil
	}
	low := azureStderr(err)
	for _, hint := range []string{"az login", "authenticationfailed", "aadsts", "interactive authentication", "invalidauthenticationtoken"} {
		if strings.Contains(low, hint) {
			return fmt.Errorf("%w: %v", ErrPermission, err)
		}
	}
	return classifyExit(err, "SecretNotFound")
}
