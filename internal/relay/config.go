package relay

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/burndrop/burndrop/internal/crypto"
	"github.com/burndrop/burndrop/internal/link"
)

// EnvPrefix is prepended to every configuration variable name.
const EnvPrefix = "BURNDROP_"

// Hard limits that configuration cannot exceed.
const (
	AbsoluteMaxTTL     = 7 * 24 * time.Hour
	AbsoluteMaxBody    = 4 << 20 // 4 MiB request body, before base64 decoding
	MinTTL             = 60 * time.Second
	MaxLongPoll        = 30 * time.Second
	DefaultCiphertext  = crypto.MaxPlaintext + crypto.PadBlock + crypto.SealedOverhead
	DefaultMaxLive     = 10000
	DefaultMaxBytes    = 256 << 20
	DefaultMaxWaiters  = 1000
	DefaultShutdownTTL = 10 * time.Second
)

// AgentKey is a configured relay client credential: an identifier and the
// SHA-256 hash of the key. The key itself is never stored.
type AgentKey struct {
	ID   string
	Hash crypto.Hash
}

// Config is the relay configuration. Every field has an environment variable
// named EnvPrefix plus the field's tag.
type Config struct {
	Listen             string        `env:"LISTEN"`
	PublicOrigin       string        `env:"PUBLIC_ORIGIN"`
	PageOrigins        []string      `env:"PAGE_ORIGINS"`
	ServePage          bool          `env:"SERVE_PAGE"`
	DefaultTTL         time.Duration `env:"DEFAULT_TTL"`
	MaxTTL             time.Duration `env:"MAX_TTL"`
	MaxCiphertextBytes int           `env:"MAX_CIPHERTEXT_BYTES"`
	MaxLiveDrops       int           `env:"MAX_LIVE_DROPS"`
	MaxTotalBytes      int64         `env:"MAX_TOTAL_BYTES"`
	MaxWaiters         int           `env:"MAX_WAITERS"`
	Store              string        `env:"STORE"`
	RedisURL           string        `env:"REDIS_URL"`
	AgentAuth          string        `env:"AGENT_AUTH"`
	AgentKeys          []AgentKey    `env:"AGENT_KEYS"`
	RatePagePerMin     float64       `env:"RATE_PAGE_PER_MIN"`
	RateAgentPerMin    float64       `env:"RATE_AGENT_PER_MIN"`
	RateGlobalPerSec   float64       `env:"RATE_GLOBAL_PER_SEC"`
	TrustedProxies     []*net.IPNet  `env:"TRUSTED_PROXIES"`
	LogLevel           string        `env:"LOG_LEVEL"`
	LogFormat          string        `env:"LOG_FORMAT"`
	LogClientIP        bool          `env:"LOG_CLIENT_IP"`
	ShutdownTimeout    time.Duration `env:"SHUTDOWN_TIMEOUT"`
}

// DefaultConfig returns the documented defaults. PublicOrigin has no default.
func DefaultConfig() Config {
	return Config{
		Listen:             ":8080",
		ServePage:          true,
		DefaultTTL:         time.Hour,
		MaxTTL:             24 * time.Hour,
		MaxCiphertextBytes: DefaultCiphertext,
		MaxLiveDrops:       DefaultMaxLive,
		MaxTotalBytes:      DefaultMaxBytes,
		MaxWaiters:         DefaultMaxWaiters,
		Store:              "memory",
		AgentAuth:          "required",
		RatePagePerMin:     60,
		RateAgentPerMin:    30,
		RateGlobalPerSec:   500,
		LogLevel:           "info",
		LogFormat:          "text",
		ShutdownTimeout:    DefaultShutdownTTL,
	}
}

// LoadConfig reads configuration from the environment via getenv (os.Getenv in
// production) on top of DefaultConfig and validates it.
func LoadConfig(getenv func(string) string) (Config, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	c := DefaultConfig()
	get := func(name string) string { return strings.TrimSpace(getenv(EnvPrefix + name)) }
	var err error
	set := func(name string, f func(v string) error) {
		if err != nil {
			return
		}
		if v := get(name); v != "" {
			if e := f(v); e != nil {
				err = fmt.Errorf("%s%s: %w", EnvPrefix, name, e)
			}
		}
	}
	str := func(dst *string) func(string) error { return func(v string) error { *dst = v; return nil } }
	dur := func(dst *time.Duration) func(string) error {
		return func(v string) error {
			d, e := time.ParseDuration(v)
			if e != nil {
				return fmt.Errorf("want a duration such as 30m or 1h: %v", e)
			}
			*dst = d
			return nil
		}
	}
	integer := func(dst *int) func(string) error {
		return func(v string) error { n, e := strconv.Atoi(v); *dst = n; return e }
	}
	boolean := func(dst *bool) func(string) error {
		return func(v string) error { b, e := strconv.ParseBool(v); *dst = b; return e }
	}
	float := func(dst *float64) func(string) error {
		return func(v string) error { f, e := strconv.ParseFloat(v, 64); *dst = f; return e }
	}

	set("LISTEN", str(&c.Listen))
	set("PUBLIC_ORIGIN", str(&c.PublicOrigin))
	set("PAGE_ORIGINS", func(v string) error { c.PageOrigins = splitList(v); return nil })
	set("SERVE_PAGE", boolean(&c.ServePage))
	set("DEFAULT_TTL", dur(&c.DefaultTTL))
	set("MAX_TTL", dur(&c.MaxTTL))
	set("MAX_CIPHERTEXT_BYTES", integer(&c.MaxCiphertextBytes))
	set("MAX_LIVE_DROPS", integer(&c.MaxLiveDrops))
	set("MAX_TOTAL_BYTES", func(v string) error { n, e := strconv.ParseInt(v, 10, 64); c.MaxTotalBytes = n; return e })
	set("MAX_WAITERS", integer(&c.MaxWaiters))
	set("STORE", str(&c.Store))
	set("REDIS_URL", str(&c.RedisURL))
	set("AGENT_AUTH", str(&c.AgentAuth))
	set("AGENT_KEYS", func(v string) error { keys, e := ParseAgentKeys(v); c.AgentKeys = keys; return e })
	set("RATE_PAGE_PER_MIN", float(&c.RatePagePerMin))
	set("RATE_AGENT_PER_MIN", float(&c.RateAgentPerMin))
	set("RATE_GLOBAL_PER_SEC", float(&c.RateGlobalPerSec))
	set("TRUSTED_PROXIES", func(v string) error { nets, e := parseCIDRs(v); c.TrustedProxies = nets; return e })
	set("LOG_LEVEL", str(&c.LogLevel))
	set("LOG_FORMAT", str(&c.LogFormat))
	set("LOG_CLIENT_IP", boolean(&c.LogClientIP))
	set("SHUTDOWN_TIMEOUT", dur(&c.ShutdownTimeout))
	if err != nil {
		return Config{}, err
	}
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

// Validate checks ranges and cross-field rules and normalizes origins.
func (c *Config) Validate() error {
	if c.PublicOrigin == "" {
		return fmt.Errorf("%sPUBLIC_ORIGIN is required, for example https://drop.example.com", EnvPrefix)
	}
	origin, err := link.NormalizeOrigin(c.PublicOrigin)
	if err != nil {
		return fmt.Errorf("%sPUBLIC_ORIGIN: %w", EnvPrefix, err)
	}
	c.PublicOrigin = origin
	if len(c.PageOrigins) == 0 {
		c.PageOrigins = []string{origin}
	}
	for i, o := range c.PageOrigins {
		n, err := link.NormalizeOrigin(o)
		if err != nil {
			return fmt.Errorf("%sPAGE_ORIGINS: %w", EnvPrefix, err)
		}
		c.PageOrigins[i] = n
	}
	if c.DefaultTTL < MinTTL || c.MaxTTL < MinTTL {
		return fmt.Errorf("TTLs must be at least %s", MinTTL)
	}
	if c.MaxTTL > AbsoluteMaxTTL {
		return fmt.Errorf("%sMAX_TTL cannot exceed %s", EnvPrefix, AbsoluteMaxTTL)
	}
	if c.DefaultTTL > c.MaxTTL {
		return fmt.Errorf("%sDEFAULT_TTL cannot exceed %sMAX_TTL", EnvPrefix, EnvPrefix)
	}
	if c.MaxCiphertextBytes < 1024 || c.MaxCiphertextBytes > AbsoluteMaxBody {
		return fmt.Errorf("%sMAX_CIPHERTEXT_BYTES must be between 1024 and %d", EnvPrefix, AbsoluteMaxBody)
	}
	if c.MaxLiveDrops < 1 || c.MaxTotalBytes < int64(c.MaxCiphertextBytes) || c.MaxWaiters < 1 {
		return fmt.Errorf("capacity limits must be positive and consistent")
	}
	switch c.Store {
	case "memory":
	case "redis":
		if c.RedisURL == "" {
			return fmt.Errorf("%sREDIS_URL is required when %sSTORE=redis", EnvPrefix, EnvPrefix)
		}
	default:
		return fmt.Errorf("%sSTORE must be memory or redis", EnvPrefix)
	}
	switch c.AgentAuth {
	case "required":
		if len(c.AgentKeys) == 0 {
			return fmt.Errorf("%sAGENT_KEYS is required when %sAGENT_AUTH=required (generate one with: burndrop-relay keygen)", EnvPrefix, EnvPrefix)
		}
	case "off":
	default:
		return fmt.Errorf("%sAGENT_AUTH must be required or off", EnvPrefix)
	}
	if c.RatePagePerMin <= 0 || c.RateAgentPerMin <= 0 || c.RateGlobalPerSec <= 0 {
		return fmt.Errorf("rate limits must be positive")
	}
	switch c.LogFormat {
	case "text", "json":
	default:
		return fmt.Errorf("%sLOG_FORMAT must be text or json", EnvPrefix)
	}
	switch strings.ToLower(c.LogLevel) {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("%sLOG_LEVEL must be debug, info, warn, or error", EnvPrefix)
	}
	return nil
}

// AuthRequired reports whether slot creation needs an agent key.
func (c *Config) AuthRequired() bool { return c.AgentAuth == "required" }

// ClampTTL applies the default and maximum TTL to a requested value in seconds.
func (c *Config) ClampTTL(seconds int64) time.Duration {
	if seconds <= 0 {
		return c.DefaultTTL
	}
	ttl := time.Duration(seconds) * time.Second
	if ttl < MinTTL {
		return MinTTL
	}
	if ttl > c.MaxTTL {
		return c.MaxTTL
	}
	return ttl
}

// ParseAgentKeys parses "id:sha256:<base64url hash>" entries separated by
// commas. Whitespace around entries is ignored. Identifiers must be unique.
func ParseAgentKeys(s string) ([]AgentKey, error) {
	var keys []AgentKey
	seen := make(map[string]bool)
	for _, entry := range splitList(s) {
		parts := strings.SplitN(entry, ":", 3)
		if len(parts) != 3 || parts[1] != "sha256" || parts[0] == "" {
			return nil, fmt.Errorf("agent key entry %q must look like id:sha256:<hash>", entry)
		}
		if seen[parts[0]] {
			return nil, fmt.Errorf("duplicate agent key id %q", parts[0])
		}
		h, err := crypto.ParseHash(parts[2])
		if err != nil {
			return nil, fmt.Errorf("agent key %q: %w", parts[0], err)
		}
		seen[parts[0]] = true
		keys = append(keys, AgentKey{ID: parts[0], Hash: h})
	}
	return keys, nil
}

// FormatAgentKey renders a config entry for a freshly generated key.
func FormatAgentKey(id, key string) string {
	return id + ":sha256:" + crypto.HashToken(key).Encode()
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseCIDRs(s string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, p := range splitList(s) {
		if !strings.Contains(p, "/") {
			if strings.Contains(p, ":") {
				p += "/128"
			} else {
				p += "/32"
			}
		}
		_, n, err := net.ParseCIDR(p)
		if err != nil {
			return nil, fmt.Errorf("trusted proxy %q: %w", p, err)
		}
		out = append(out, n)
	}
	return out, nil
}
