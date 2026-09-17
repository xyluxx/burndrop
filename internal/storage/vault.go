// HashiCorp Vault backend, KV version 2 over the HTTP API.
//
// Written against the KV v2 API at
// https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2, the token
// endpoints at https://developer.hashicorp.com/vault/api-docs/auth/token,
// the API conventions (status codes, X-Vault-Token, X-Vault-Namespace, the
// LIST method) at https://developer.hashicorp.com/vault/api-docs and the CLI
// environment (VAULT_ADDR, VAULT_TOKEN, VAULT_NAMESPACE, ~/.vault-token) at
// https://developer.hashicorp.com/vault/docs/commands. No vendor SDK is used.

package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Defaults for the Vault backend.
const (
	DefaultVaultMount = "secret"
	DefaultVaultPath  = "burndrop"
	vaultTimeout      = 10 * time.Second
	vaultMaxBody      = 4 << 20
)

// errVaultNoRecord marks a KV entry that exists but was not written by
// burndrop.
var errVaultNoRecord = errors.New("storage: vault: entry holds no burndrop record")

// Vault stores records in a HashiCorp Vault KV version 2 engine through the
// HTTP API. One burndrop secret is one KV entry at Mount/data/Path/name whose
// data is {"record": <the JSON record>}. The value travels only in the TLS
// request body. The token is resolved on every call (Token, then VAULT_TOKEN,
// then ~/.vault-token) so a fresh vault login is picked up without a restart.
type Vault struct {
	Address    string       // VAULT_ADDR if empty; https unless the host is localhost
	Token      string       // VAULT_TOKEN, then ~/.vault-token, if empty
	Namespace  string       // VAULT_NAMESPACE if empty; sent as X-Vault-Namespace
	Mount      string       // KV v2 mount; DefaultVaultMount if empty
	Path       string       // path under the mount; DefaultVaultPath if empty
	HTTPClient *http.Client // a client with a 10 second timeout if nil
}

// NewVault fills in the defaults from the environment.
func NewVault(opts Vault) *Vault {
	if opts.Address == "" {
		opts.Address = os.Getenv("VAULT_ADDR")
	}
	if opts.Namespace == "" {
		opts.Namespace = os.Getenv("VAULT_NAMESPACE")
	}
	if opts.Mount == "" {
		opts.Mount = DefaultVaultMount
	}
	if opts.Path == "" {
		opts.Path = DefaultVaultPath
	}
	if opts.HTTPClient == nil {
		opts.HTTPClient = &http.Client{Timeout: vaultTimeout}
	}
	return &opts
}

func (v *Vault) Name() string { return "vault" }

func (v *Vault) client() *http.Client {
	if v.HTTPClient == nil {
		return &http.Client{Timeout: vaultTimeout}
	}
	return v.HTTPClient
}

func (v *Vault) mount() string {
	if m := strings.Trim(v.Mount, "/"); m != "" {
		return m
	}
	return DefaultVaultMount
}

func (v *Vault) path() string {
	if p := strings.Trim(v.Path, "/"); p != "" {
		return p
	}
	return DefaultVaultPath
}

func (v *Vault) dataPath(name string) string { return v.mount() + "/data/" + v.path() + "/" + name }

func (v *Vault) metaPath(name string) string {
	if name == "" {
		return v.mount() + "/metadata/" + v.path()
	}
	return v.mount() + "/metadata/" + v.path() + "/" + name
}

// baseURL validates the address: https, or http for the local host only.
func (v *Vault) baseURL() (string, error) {
	addr := strings.TrimRight(v.Address, "/")
	if addr == "" {
		return "", fmt.Errorf("%w: vault address is not set (VAULT_ADDR)", ErrUnavailable)
	}
	u, err := url.Parse(addr)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("%w: vault address %q is not a URL", ErrUnavailable, addr)
	}
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && vaultLocalHost(u.Hostname()):
	default:
		return "", fmt.Errorf("%w: vault address %q must use https (plain http is allowed for localhost only)", ErrUnavailable, addr)
	}
	return addr, nil
}

func vaultLocalHost(host string) bool {
	switch strings.ToLower(host) {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}

// token resolves the token: the Token field, VAULT_TOKEN, then the token
// helper file ~/.vault-token written by vault login.
func (v *Vault) token() (string, error) {
	if v.Token != "" {
		return v.Token, nil
	}
	if t := os.Getenv("VAULT_TOKEN"); t != "" {
		return t, nil
	}
	if home, err := os.UserHomeDir(); err == nil {
		if b, err := os.ReadFile(filepath.Join(home, ".vault-token")); err == nil {
			if t := strings.TrimSpace(string(b)); t != "" {
				return t, nil
			}
		}
	}
	return "", fmt.Errorf("%w: no vault token: set VAULT_TOKEN or run vault login", ErrPermission)
}

// call sends one request and returns the status and body. Transport
// failures are ErrUnavailable.
func (v *Vault) call(ctx context.Context, method, p string, body any) (int, []byte, error) {
	base, err := v.baseURL()
	if err != nil {
		return 0, nil, err
	}
	token, err := v.token()
	if err != nil {
		return 0, nil, err
	}
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, base+"/v1/"+p, rdr)
	if err != nil {
		return 0, nil, fmt.Errorf("storage: vault: %w", err)
	}
	req.Header.Set("X-Vault-Token", token)
	if v.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", v.Namespace)
	}
	if rdr != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := v.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("%w: vault: %v", ErrUnavailable, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, vaultMaxBody))
	if err != nil {
		return 0, nil, fmt.Errorf("%w: vault: %v", ErrUnavailable, err)
	}
	return resp.StatusCode, data, nil
}

// vaultError maps a non-2xx response to a storage error: 404 is not found,
// 403 is permission denied, 503 (sealed or down) is unavailable.
func vaultError(status int, body []byte) error {
	msg := vaultMessages(body)
	switch status {
	case http.StatusNotFound:
		return ErrNotFound
	case http.StatusForbidden:
		return fmt.Errorf("%w: vault: %s", ErrPermission, msg)
	case http.StatusServiceUnavailable:
		return fmt.Errorf("%w: vault: %s", ErrUnavailable, msg)
	default:
		return fmt.Errorf("storage: vault: HTTP %d: %s", status, msg)
	}
}

func vaultMessages(body []byte) string {
	var e struct {
		Errors []string `json:"errors"`
	}
	if json.Unmarshal(body, &e) == nil && len(e.Errors) > 0 {
		return strings.Join(e.Errors, "; ")
	}
	return "no error detail"
}

// vaultReason strips the sentinel prefix from an error for a probe reason.
func vaultReason(err error) string {
	s := err.Error()
	for _, sentinel := range []error{ErrUnavailable, ErrPermission} {
		s = strings.TrimPrefix(s, sentinel.Error()+": ")
	}
	return s
}

func (v *Vault) Probe(ctx context.Context) Probe {
	base, err := v.baseURL()
	if err != nil {
		return Probe{Reason: vaultReason(err)}
	}
	if _, err := v.token(); err != nil {
		return Probe{Reason: vaultReason(err)}
	}
	status, body, err := v.call(ctx, http.MethodGet, "auth/token/lookup-self", nil)
	if err != nil {
		return Probe{Reason: "Vault at " + base + " is unreachable: " + vaultReason(err)}
	}
	if status != http.StatusOK {
		return Probe{Reason: fmt.Sprintf("Vault at %s rejected the token: HTTP %d: %s", base, status, vaultMessages(body))}
	}
	var resp struct {
		Data struct {
			DisplayName string   `json:"display_name"`
			Policies    []string `json:"policies"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return Probe{Reason: "Vault at " + base + " returned an unreadable token lookup"}
	}
	reason := fmt.Sprintf("Vault KV v2 at %s (%s/%s) as token %q", base, v.mount(), v.path(), resp.Data.DisplayName)
	if len(resp.Data.Policies) > 0 {
		reason += " with policies " + strings.Join(resp.Data.Policies, ", ")
	}
	if v.Namespace != "" {
		reason += " in namespace " + v.Namespace
	}
	return Probe{Available: true, Reason: reason, Rank: 85}
}

func (v *Vault) Put(ctx context.Context, name string, value []byte, meta Metadata) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	meta.Name = name
	meta.Backend = v.Name()
	meta.SizeBytes = len(value)
	rec, err := encodeRecord(meta, value)
	if err != nil {
		return err
	}
	body := map[string]any{"data": map[string]string{"record": string(rec)}}
	status, out, err := v.call(ctx, http.MethodPost, v.dataPath(name), body)
	if err != nil {
		return err
	}
	if status/100 != 2 {
		return vaultError(status, out)
	}
	return nil
}

// fetch returns the record stored at name.
func (v *Vault) fetch(ctx context.Context, name string) ([]byte, error) {
	status, body, err := v.call(ctx, http.MethodGet, v.dataPath(name), nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, vaultError(status, body)
	}
	var resp struct {
		Data struct {
			Data struct {
				Record string `json:"record"`
			} `json:"data"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("storage: vault: unexpected read response: %w", err)
	}
	if resp.Data.Data.Record == "" {
		return nil, fmt.Errorf("%w: %s", errVaultNoRecord, v.dataPath(name))
	}
	return []byte(resp.Data.Data.Record), nil
}

func (v *Vault) Get(ctx context.Context, name string) ([]byte, Metadata, error) {
	if err := ValidateName(name); err != nil {
		return nil, Metadata{}, err
	}
	rec, err := v.fetch(ctx, name)
	if err != nil {
		return nil, Metadata{}, err
	}
	value, m, err := decodeRecord(rec)
	if err != nil {
		return nil, Metadata{}, fmt.Errorf("storage: vault: %s: %w", v.dataPath(name), err)
	}
	if m.Name != name {
		return nil, Metadata{}, ErrNotFound
	}
	return value, m, nil
}

// Delete removes the metadata and every version. Deleting missing metadata
// succeeds in Vault, so the entry is looked up first.
func (v *Vault) Delete(ctx context.Context, name string) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	status, body, err := v.call(ctx, http.MethodGet, v.metaPath(name), nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return vaultError(status, body)
	}
	status, body, err = v.call(ctx, http.MethodDelete, v.metaPath(name), nil)
	if err != nil {
		return err
	}
	if status/100 != 2 {
		return vaultError(status, body)
	}
	return nil
}

// List enumerates the keys under the path with the LIST method and reads
// each one for its metadata, so it costs one read per secret on top of the
// list call. Entries that are not burndrop records are skipped.
func (v *Vault) List(ctx context.Context) ([]Metadata, error) {
	status, body, err := v.call(ctx, "LIST", v.metaPath(""), nil)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return []Metadata{}, nil
	}
	if status != http.StatusOK {
		return nil, vaultError(status, body)
	}
	var resp struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("storage: vault: unexpected list response: %w", err)
	}
	list := make([]Metadata, 0, len(resp.Data.Keys))
	for _, key := range resp.Data.Keys {
		if strings.HasSuffix(key, "/") || ValidateName(key) != nil {
			continue
		}
		rec, err := v.fetch(ctx, key)
		if errors.Is(err, ErrNotFound) || errors.Is(err, errVaultNoRecord) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if _, m, err := decodeRecord(rec); err == nil && m.Name == key {
			list = append(list, m)
		}
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	return list, nil
}
