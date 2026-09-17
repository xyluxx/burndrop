package relay

import (
	"strings"
	"testing"
	"time"

	"github.com/xyluxx/burndrop/internal/crypto"
)

func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[strings.TrimPrefix(k, EnvPrefix)] }
}

func TestLoadConfigDefaultsAndOverrides(t *testing.T) {
	key, _ := crypto.RandomAgentKey()
	entry := FormatAgentKey("ci", key)
	cfg, err := LoadConfig(envMap(map[string]string{"PUBLIC_ORIGIN": "https://Drop.Example.com/", "AGENT_KEYS": entry}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PublicOrigin != "https://drop.example.com" || cfg.PageOrigins[0] != "https://drop.example.com" || cfg.DefaultTTL != time.Hour || cfg.MaxTTL != 24*time.Hour || cfg.Store != "memory" || !cfg.AuthRequired() || cfg.AgentKeys[0].ID != "ci" {
		t.Fatalf("defaults: %+v", cfg)
	}
	cfg, err = LoadConfig(envMap(map[string]string{
		"PUBLIC_ORIGIN": "https://drop.example.com", "PAGE_ORIGINS": "https://page.example.org, https://drop.example.com",
		"AGENT_AUTH": "off", "DEFAULT_TTL": "30m", "MAX_TTL": "2h", "MAX_CIPHERTEXT_BYTES": "4096", "MAX_LIVE_DROPS": "5",
		"MAX_TOTAL_BYTES": "8192", "MAX_WAITERS": "7", "RATE_PAGE_PER_MIN": "10", "RATE_AGENT_PER_MIN": "5.5", "RATE_GLOBAL_PER_SEC": "50",
		"TRUSTED_PROXIES": "10.0.0.0/8, 192.168.1.1, ::1", "LOG_LEVEL": "debug", "LOG_FORMAT": "json", "LOG_CLIENT_IP": "true", "SERVE_PAGE": "false", "LISTEN": "127.0.0.1:9999", "SHUTDOWN_TIMEOUT": "3s",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.PageOrigins) != 2 || cfg.AuthRequired() || cfg.DefaultTTL != 30*time.Minute || cfg.MaxTTL != 2*time.Hour || cfg.MaxCiphertextBytes != 4096 ||
		cfg.MaxLiveDrops != 5 || cfg.MaxTotalBytes != 8192 || cfg.MaxWaiters != 7 || cfg.RatePagePerMin != 10 || cfg.RateAgentPerMin != 5.5 || cfg.RateGlobalPerSec != 50 ||
		len(cfg.TrustedProxies) != 3 || cfg.LogLevel != "debug" || cfg.LogFormat != "json" || !cfg.LogClientIP || cfg.ServePage || cfg.Listen != "127.0.0.1:9999" || cfg.ShutdownTimeout != 3*time.Second {
		t.Fatalf("overrides: %+v", cfg)
	}
	if cfg.ClampTTL(0) != 30*time.Minute || cfg.ClampTTL(5) != MinTTL || cfg.ClampTTL(3*3600) != 2*time.Hour || cfg.ClampTTL(600) != 10*time.Minute {
		t.Fatal("clamp")
	}
}

func TestLoadConfigErrors(t *testing.T) {
	key, _ := crypto.RandomAgentKey()
	entry := FormatAgentKey("a", key)
	base := map[string]string{"PUBLIC_ORIGIN": "https://drop.example.com", "AGENT_KEYS": entry}
	cases := map[string]map[string]string{
		"missing origin":        {"AGENT_KEYS": entry},
		"http origin":           {"PUBLIC_ORIGIN": "http://drop.example.com", "AGENT_KEYS": entry},
		"origin with path":      {"PUBLIC_ORIGIN": "https://drop.example.com/x", "AGENT_KEYS": entry},
		"bad page origin":       {"PAGE_ORIGINS": "not-an-origin"},
		"bad duration":          {"DEFAULT_TTL": "soon"},
		"default over max":      {"DEFAULT_TTL": "25h"},
		"max over absolute":     {"MAX_TTL": "200h"},
		"ttl too small":         {"DEFAULT_TTL": "10s"},
		"ciphertext too small":  {"MAX_CIPHERTEXT_BYTES": "10"},
		"ciphertext too big":    {"MAX_CIPHERTEXT_BYTES": "99999999"},
		"bad int":               {"MAX_LIVE_DROPS": "many"},
		"zero live":             {"MAX_LIVE_DROPS": "0"},
		"total below one":       {"MAX_TOTAL_BYTES": "100"},
		"bad store":             {"STORE": "postgres"},
		"redis without url":     {"STORE": "redis"},
		"bad auth":              {"AGENT_AUTH": "maybe"},
		"required without keys": {"AGENT_KEYS": ""},
		"bad key entry":         {"AGENT_KEYS": "nohash"},
		"bad key hash":          {"AGENT_KEYS": "a:sha256:zz"},
		"duplicate key id":      {"AGENT_KEYS": entry + "," + entry},
		"zero rate":             {"RATE_PAGE_PER_MIN": "0"},
		"bad float":             {"RATE_PAGE_PER_MIN": "fast"},
		"bad bool":              {"SERVE_PAGE": "yes please"},
		"bad proxy":             {"TRUSTED_PROXIES": "10.0.0.0/99"},
		"bad log format":        {"LOG_FORMAT": "xml"},
		"bad log level":         {"LOG_LEVEL": "loud"},
	}
	for name, over := range cases {
		m := map[string]string{}
		for k, v := range base {
			m[k] = v
		}
		for k, v := range over {
			m[k] = v
		}
		if name == "missing origin" {
			delete(m, "PUBLIC_ORIGIN")
		}
		if name == "required without keys" {
			delete(m, "AGENT_KEYS")
		}
		if _, err := LoadConfig(envMap(m)); err == nil {
			t.Fatalf("%s: expected error", name)
		}
	}
	// os.Getenv path: the prefix is applied.
	t.Setenv(EnvPrefix+"PUBLIC_ORIGIN", "https://env.example.com")
	t.Setenv(EnvPrefix+"AGENT_AUTH", "off")
	cfg, err := LoadConfig(nil)
	if err != nil || cfg.PublicOrigin != "https://env.example.com" {
		t.Fatalf("os env: %v %+v", err, cfg)
	}
}

func TestAgentKeyRoundTrip(t *testing.T) {
	key, _ := crypto.RandomAgentKey()
	keys, err := ParseAgentKeys(" one:sha256:" + crypto.HashToken(key).Encode() + " , " + FormatAgentKey("two", "other-key") + " ")
	if err != nil || len(keys) != 2 || keys[0].ID != "one" || !crypto.HashEqual(keys[0].Hash, crypto.HashToken(key)) || keys[1].ID != "two" {
		t.Fatalf("parse: %v %+v", err, keys)
	}
	if keys, err := ParseAgentKeys(""); err != nil || len(keys) != 0 {
		t.Fatal("empty list")
	}
	for _, bad := range []string{"one", "one:md5:abc", ":sha256:abc", "one:sha256:"} {
		if _, err := ParseAgentKeys(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

func TestNullOriginIsRejected(t *testing.T) {
	cfg := DefaultConfig()
	cfg.PublicOrigin = "https://drop.example.com"
	cfg.AgentAuth = "off"
	cfg.PageOrigins = []string{"null"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("the null origin must be rejected: a file:// page cannot be distinguished from any other null-origin document")
	}
}
