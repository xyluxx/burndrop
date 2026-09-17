// Package agent implements the flows behind the MCP tools and the CLI:
// requesting a secret from a human, fetching and storing it, sending one
// back, running a command with secrets in its environment, and the audit
// and redaction that wrap every operation. Values never appear in any
// return value of this package that is meant for a language model.
package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// AppName is used for directories, keychain entries, and file names.
const AppName = "burndrop"

// Paths locates the config file and the state directory.
type Paths struct {
	ConfigFile string
	StateDir   string
}

// DefaultPaths resolves the platform defaults, honoring the overrides
// BURNDROP_CONFIG (a file) and BURNDROP_STATE_DIR (a directory).
func DefaultPaths(getenv func(string) string) (Paths, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	var p Paths
	if v := getenv("BURNDROP_CONFIG"); v != "" {
		p.ConfigFile = v
	} else {
		dir, err := userConfigDir(getenv)
		if err != nil {
			return Paths{}, err
		}
		p.ConfigFile = filepath.Join(dir, AppName, "config.toml")
	}
	if v := getenv("BURNDROP_STATE_DIR"); v != "" {
		p.StateDir = v
	} else {
		dir, err := userStateDir(getenv)
		if err != nil {
			return Paths{}, err
		}
		p.StateDir = filepath.Join(dir, AppName)
	}
	return p, nil
}

func home(getenv func(string) string) (string, error) {
	if h := getenv("HOME"); h != "" {
		return h, nil
	}
	if runtime.GOOS == "windows" {
		if h := getenv("USERPROFILE"); h != "" {
			return h, nil
		}
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine the home directory: %w", err)
	}
	return h, nil
}

func userConfigDir(getenv func(string) string) (string, error) {
	switch runtime.GOOS {
	case "windows":
		if v := getenv("APPDATA"); v != "" {
			return v, nil
		}
		h, err := home(getenv)
		if err != nil {
			return "", err
		}
		return filepath.Join(h, "AppData", "Roaming"), nil
	case "darwin":
		h, err := home(getenv)
		if err != nil {
			return "", err
		}
		return filepath.Join(h, "Library", "Application Support"), nil
	default:
		if v := getenv("XDG_CONFIG_HOME"); v != "" {
			return v, nil
		}
		h, err := home(getenv)
		if err != nil {
			return "", err
		}
		return filepath.Join(h, ".config"), nil
	}
}

func userStateDir(getenv func(string) string) (string, error) {
	switch runtime.GOOS {
	case "windows":
		if v := getenv("LOCALAPPDATA"); v != "" {
			return v, nil
		}
		h, err := home(getenv)
		if err != nil {
			return "", err
		}
		return filepath.Join(h, "AppData", "Local"), nil
	case "darwin":
		h, err := home(getenv)
		if err != nil {
			return "", err
		}
		return filepath.Join(h, "Library", "Application Support"), nil
	default:
		if v := getenv("XDG_STATE_HOME"); v != "" {
			return v, nil
		}
		h, err := home(getenv)
		if err != nil {
			return "", err
		}
		return filepath.Join(h, ".local", "state"), nil
	}
}

// IndexFile, VaultFile, AuditFile, and DotenvFile are the state files.
func (p Paths) IndexFile() string  { return filepath.Join(p.StateDir, "index.json") }
func (p Paths) VaultFile() string  { return filepath.Join(p.StateDir, "vault.age") }
func (p Paths) AuditFile() string  { return filepath.Join(p.StateDir, "audit.log") }
func (p Paths) DotenvFile() string { return filepath.Join(p.StateDir, ".env") }

// EnsureStateDir creates the state directory with owner-only permissions.
func (p Paths) EnsureStateDir() error {
	return os.MkdirAll(p.StateDir, 0o700)
}
