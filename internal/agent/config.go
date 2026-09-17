package agent

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/xyluxx/burndrop/internal/link"
	"github.com/xyluxx/burndrop/internal/storage"
)

// Config is the agent configuration file (docs/design.md section 8.5).
type Config struct {
	Relay            string `toml:"relay"`
	PageOrigin       string `toml:"page_origin,omitempty"`
	AgentKey         string `toml:"agent_key,omitempty"`
	Storage          string `toml:"storage"`
	DefaultTTL       string `toml:"default_ttl,omitempty"`
	DefaultRetention string `toml:"default_retention,omitempty"`

	RunWithSecret RunConfig     `toml:"run_with_secret,omitempty"`
	Audit         AuditConfig   `toml:"audit,omitempty"`
	Backends      BackendConfig `toml:"backends,omitempty"`
}

// RunConfig restricts run_with_secret.
type RunConfig struct {
	AllowedCommands []string `toml:"allowed_commands,omitempty"`
	MaxOutputBytes  int      `toml:"max_output_bytes,omitempty"`
}

// AuditConfig locates the audit log; an empty path means the state
// directory default and "off" disables it.
type AuditConfig struct {
	Path string `toml:"path,omitempty"`
}

// BackendConfig holds per-backend options. Only the table for the selected
// backend is read.
type BackendConfig struct {
	Keychain    KeychainConfig    `toml:"keychain,omitempty"`
	AgeVault    AgeVaultConfig    `toml:"agevault,omitempty"`
	Dotenv      DotenvConfig      `toml:"dotenv,omitempty"`
	OnePassword OnePasswordConfig `toml:"onepassword,omitempty"`
	Bitwarden   BitwardenConfig   `toml:"bitwarden,omitempty"`
	Vault       VaultConfig       `toml:"vault,omitempty"`
	Infisical   InfisicalConfig   `toml:"infisical,omitempty"`
	Doppler     DopplerConfig     `toml:"doppler,omitempty"`
	AWS         AWSConfig         `toml:"aws,omitempty"`
	GCP         GCPConfig         `toml:"gcp,omitempty"`
	Azure       AzureConfig       `toml:"azure,omitempty"`
}

type KeychainConfig struct {
	Service string `toml:"service,omitempty"`
}

type AgeVaultConfig struct {
	Path          string `toml:"path,omitempty"`
	IdentityFile  string `toml:"identity_file,omitempty"`
	PassphraseEnv string `toml:"passphrase_env,omitempty"`
}

type DotenvConfig struct {
	Path string `toml:"path,omitempty"`
}

type OnePasswordConfig struct {
	Vault   string `toml:"vault,omitempty"`
	Account string `toml:"account,omitempty"`
}

type BitwardenConfig struct {
	// SessionEnv names the variable holding the "bw unlock --raw" session
	// key. Empty lets bw read BW_SESSION from its own environment.
	SessionEnv string `toml:"session_env,omitempty"`
}

type VaultConfig struct {
	Address   string `toml:"address,omitempty"`
	Mount     string `toml:"mount,omitempty"`
	Path      string `toml:"path,omitempty"`
	Namespace string `toml:"namespace,omitempty"`
	TokenEnv  string `toml:"token_env,omitempty"`
}

type InfisicalConfig struct {
	ProjectID   string `toml:"project_id,omitempty"`
	Environment string `toml:"environment,omitempty"`
	Path        string `toml:"path,omitempty"`
}

type DopplerConfig struct {
	Project string `toml:"project,omitempty"`
	Config  string `toml:"config,omitempty"`
}

type AWSConfig struct {
	Region  string `toml:"region,omitempty"`
	Profile string `toml:"profile,omitempty"`
	Prefix  string `toml:"prefix,omitempty"`
}

type GCPConfig struct {
	Project string `toml:"project,omitempty"`
	Prefix  string `toml:"prefix,omitempty"`
}

type AzureConfig struct {
	VaultName string `toml:"vault_name,omitempty"`
	Prefix    string `toml:"prefix,omitempty"`
	// Purge removes soft-deleted secrets right away so a name can be reused.
	Purge bool `toml:"purge,omitempty"`
}

// Defaults.
const (
	DefaultTTL          = time.Hour
	DefaultRetention    = storage.RetentionUntilRevoked
	DefaultMaxOutput    = 32 * 1024
	DefaultAgentKeyRef  = "keychain:" + AppName + "/agent-key"
	DefaultAgentKeyEnv  = "BURNDROP_API_KEY"
	KeychainAgentKeyRef = "agent-key"
)

// ErrNoConfig is returned when the config file does not exist.
var ErrNoConfig = errors.New("no configuration file; run the init command first")

// LoadConfig reads and validates the file at path.
func LoadConfig(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Config{}, ErrNoConfig
	}
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	md, err := toml.Decode(string(b), &cfg)
	if err != nil {
		return Config{}, fmt.Errorf("parse %s: %w", path, err)
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, 0, len(undecoded))
		for _, k := range undecoded {
			keys = append(keys, k.String())
		}
		return Config{}, fmt.Errorf("%s: unknown keys: %s", path, strings.Join(keys, ", "))
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

// SaveConfig writes the file with owner-only permissions.
func SaveConfig(path string, cfg Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	var buf bytes.Buffer
	buf.WriteString("# burndrop agent configuration. Values in this file are never secrets;\n# the agent key lives in the keychain or an environment variable.\n\n")
	if err := toml.NewEncoder(&buf).Encode(cfg); err != nil {
		return err
	}
	return writeFile0600(path, buf.Bytes())
}

func writeFile0600(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".config.*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := os.Chmod(name, 0o600); err != nil && !errors.Is(err, os.ErrPermission) {
		_ = os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		_ = os.Remove(name)
		return err
	}
	return nil
}

// KnownBackends lists every backend name the agent can open.
var KnownBackends = []string{"keychain", "agevault", "memory", "dotenv", "onepassword", "bitwarden", "vault", "infisical", "doppler", "aws", "gcp", "azure"}

// Validate checks the values that do not need the network.
func (c *Config) Validate() error {
	if c.Relay == "" {
		return errors.New("relay is required")
	}
	if _, err := link.NormalizeOrigin(c.Relay); err != nil {
		return fmt.Errorf("relay: %w", err)
	}
	if c.PageOrigin != "" {
		if _, err := link.NormalizeOrigin(c.PageOrigin); err != nil {
			return fmt.Errorf("page_origin: %w", err)
		}
	}
	if c.Storage == "" {
		return errors.New("storage is required")
	}
	known := false
	for _, k := range KnownBackends {
		if k == c.Storage {
			known = true
		}
	}
	if !known {
		return fmt.Errorf("storage %q is not one of %s", c.Storage, strings.Join(KnownBackends, ", "))
	}
	if c.AgentKey != "" && c.AgentKey != AgentKeyNone && !strings.HasPrefix(c.AgentKey, "keychain:") && !strings.HasPrefix(c.AgentKey, "env:") {
		return errors.New("agent_key must be keychain:<service>/<entry>, env:<VARIABLE>, or none; never a plain value")
	}
	if _, err := c.TTL(); err != nil {
		return err
	}
	if _, err := storage.ParseRetention(c.Retention(), time.Now()); err != nil && c.DefaultRetention != "" {
		return fmt.Errorf("default_retention: %w", err)
	}
	if c.RunWithSecret.MaxOutputBytes < 0 {
		return errors.New("run_with_secret.max_output_bytes must not be negative")
	}
	return nil
}

// TTL returns the default request lifetime.
func (c *Config) TTL() (time.Duration, error) {
	if c.DefaultTTL == "" {
		return DefaultTTL, nil
	}
	d, err := time.ParseDuration(c.DefaultTTL)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("default_ttl %q is not a positive duration such as 1h or 30m", c.DefaultTTL)
	}
	return d, nil
}

// Retention returns the default retention policy.
func (c *Config) Retention() string {
	if c.DefaultRetention == "" {
		return DefaultRetention
	}
	return c.DefaultRetention
}

// MaxOutput returns the run_with_secret output cap.
func (c *Config) MaxOutput() int {
	if c.RunWithSecret.MaxOutputBytes == 0 {
		return DefaultMaxOutput
	}
	return c.RunWithSecret.MaxOutputBytes
}

// ResolveAgentKey returns the relay API key from the configured reference:
// env:<VAR> reads an environment variable; keychain:<service>/<entry> reads
// the OS credential store. With no reference, the BURNDROP_API_KEY
// variable is tried first, then the keychain default. The second result
// names the source for diagnostics.
// AgentKeyNone in agent_key records that the relay was set up without agent
// auth, so no key is looked up and no Authorization header is sent.
const AgentKeyNone = "none"

func (c *Config) ResolveAgentKey(getenv func(string) string, keychain func(service, entry string) (string, error)) (string, string, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	ref := c.AgentKey
	if ref == "" {
		if v := getenv(DefaultAgentKeyEnv); v != "" {
			return strings.TrimSpace(v), "env:" + DefaultAgentKeyEnv, nil
		}
		ref = DefaultAgentKeyRef
	}
	if ref == AgentKeyNone {
		return "", ref, nil
	}
	switch {
	case strings.HasPrefix(ref, "env:"):
		name := strings.TrimPrefix(ref, "env:")
		v := strings.TrimSpace(getenv(name))
		if v == "" {
			return "", ref, fmt.Errorf("environment variable %s is empty", name)
		}
		return v, ref, nil
	case strings.HasPrefix(ref, "keychain:"):
		service, entry, ok := strings.Cut(strings.TrimPrefix(ref, "keychain:"), "/")
		if !ok || service == "" || entry == "" {
			return "", ref, errors.New("agent_key keychain reference must be keychain:<service>/<entry>")
		}
		if keychain == nil {
			return "", ref, errors.New("keychain lookups are not available")
		}
		v, err := keychain(service, entry)
		if err != nil {
			return "", ref, fmt.Errorf("agent key not found in the keychain (%s): %w", ref, err)
		}
		return strings.TrimSpace(v), ref, nil
	default:
		return "", ref, errors.New("agent_key must start with env: or keychain:")
	}
}

// BackendOpener builds a storage backend from configuration.
type BackendOpener func(cfg Config, paths Paths, getenv func(string) string) (storage.Backend, error)

// OpenBackend constructs the configured backend. Construction never talks
// to the manager; Probe does that. Names not built in can be added through
// RegisterBackend.
func OpenBackend(cfg Config, paths Paths, getenv func(string) string) (storage.Backend, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	b := cfg.Backends
	switch cfg.Storage {
	case "onepassword":
		return storage.NewOnePassword(storage.OnePasswordOptions{Vault: b.OnePassword.Vault, Account: b.OnePassword.Account}), nil
	case "bitwarden":
		opts := storage.BitwardenOptions{}
		if env := b.Bitwarden.SessionEnv; env != "" {
			opts.Session = getenv(env)
			if opts.Session == "" {
				return nil, fmt.Errorf("bitwarden session variable %s is empty", env)
			}
		}
		return storage.NewBitwarden(opts), nil
	case "vault":
		opts := storage.Vault{Address: b.Vault.Address, Namespace: b.Vault.Namespace, Mount: b.Vault.Mount, Path: b.Vault.Path}
		if env := b.Vault.TokenEnv; env != "" {
			opts.Token = getenv(env)
			if opts.Token == "" {
				return nil, fmt.Errorf("vault token variable %s is empty", env)
			}
		}
		return storage.NewVault(opts), nil
	case "infisical":
		return storage.NewInfisical(storage.InfisicalOptions{ProjectID: b.Infisical.ProjectID, Environment: b.Infisical.Environment, Path: b.Infisical.Path}), nil
	case "doppler":
		return storage.NewDoppler(storage.DopplerOptions{Project: b.Doppler.Project, Config: b.Doppler.Config}), nil
	case "aws":
		return storage.NewAWS(storage.AWS{Region: b.AWS.Region, Profile: b.AWS.Profile, Prefix: b.AWS.Prefix}), nil
	case "gcp":
		return storage.NewGCP(storage.GCP{Project: b.GCP.Project, Prefix: b.GCP.Prefix}), nil
	case "azure":
		return storage.NewAzure(storage.Azure{VaultName: b.Azure.VaultName, Prefix: b.Azure.Prefix, Purge: b.Azure.Purge}), nil
	case "memory":
		return storage.NewMemory(), nil
	case "keychain":
		return storage.NewKeychain(cfg.Backends.Keychain.Service), nil
	case "dotenv":
		path := cfg.Backends.Dotenv.Path
		if path == "" {
			path = paths.DotenvFile()
		}
		return storage.NewDotenv(path), nil
	case "agevault":
		path := cfg.Backends.AgeVault.Path
		if path == "" {
			path = paths.VaultFile()
		}
		opts := storage.AgeVaultOptions{IdentityFile: cfg.Backends.AgeVault.IdentityFile}
		if env := cfg.Backends.AgeVault.PassphraseEnv; env != "" {
			opts.Passphrase = getenv(env)
			if opts.Passphrase == "" {
				return nil, fmt.Errorf("agevault passphrase variable %s is empty", env)
			}
		}
		if opts.IdentityFile == "" && opts.Passphrase == "" {
			opts.Keychain = storage.NewKeychain(cfg.Backends.Keychain.Service)
		}
		return storage.OpenAgeVault(path, opts)
	}
	if open, ok := externalBackends[cfg.Storage]; ok {
		return open(cfg, paths, getenv)
	}
	return nil, fmt.Errorf("storage backend %q is not available in this build", cfg.Storage)
}

var externalBackends = map[string]BackendOpener{}

// RegisterBackend adds an opener for a backend name.
func RegisterBackend(name string, open BackendOpener) {
	externalBackends[name] = open
}
