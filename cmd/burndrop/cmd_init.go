package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/burndrop/burndrop/internal/agent"
	"github.com/burndrop/burndrop/internal/client"
	"github.com/burndrop/burndrop/internal/storage"
)

// candidateBackends builds one instance of every backend for detection.
// Backends that need configuration to be meaningful are still probed with
// defaults so the table shows whether their tooling is present.
func (a *app) candidateBackends(paths agent.Paths) []storage.Backend {
	cfg := agent.Config{Relay: "https://relay.invalid", Storage: "memory"}
	var out []storage.Backend
	for _, name := range agent.KnownBackends {
		cfg.Storage = name
		if name == "agevault" {
			cfg.Backends.AgeVault.IdentityFile = paths.VaultFile() + ".key"
		}
		b, err := agent.OpenBackend(cfg, paths, a.getenv)
		if err != nil {
			continue
		}
		out = append(out, b)
	}
	return out
}

func (a *app) cmdInit(ctx context.Context, args []string) error {
	fs := a.flags("init", "-relay URL [-storage NAME] [-agent-key-from env|keychain|prompt] [-page-origin URL] [-allow-dotenv] [-yes]")
	relay := fs.String("relay", "", "relay origin, for example https://relay.example")
	storageName := fs.String("storage", "", "backend to use (default: strongest available)")
	keyFrom := fs.String("agent-key-from", "", "where the relay agent key comes from: env (BURNDROP_API_KEY at run time), keychain (stored now, read with a hidden prompt), or prompt (same as keychain)")
	pageOrigin := fs.String("page-origin", "", "origin of the drop page when it is not the relay")
	allowDotenv := fs.Bool("allow-dotenv", false, "permit the dotenv backend, which stores values in a plain file")
	yes := fs.Bool("yes", false, "accept the recommendation without asking")
	if err := a.parse(fs, args); err != nil {
		return err
	}
	paths, err := agent.DefaultPaths(a.getenv)
	if err != nil {
		return err
	}
	if err := paths.EnsureStateDir(); err != nil {
		return err
	}
	if *relay == "" {
		fs.Usage()
		return errUsage
	}
	rc, err := client.New(*relay, "", "burndrop-cli/"+a.version)
	if err != nil {
		return err
	}
	info, err := rc.Info(ctx)
	if err != nil {
		return fmt.Errorf("the relay at %s did not answer: %w", rc.Origin, err)
	}
	fmt.Fprintf(a.stdout, "relay %s: version %s, default link lifetime %ds, agent auth %s\n", rc.Origin, info.Version, info.DefaultTTLSeconds, info.AgentAuth)

	fmt.Fprintln(a.stdout, "\nprobing storage backends...")
	candidates := storage.Detect(ctx, a.candidateBackends(paths))
	tw := tabwriter.NewWriter(a.stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "BACKEND\tAVAILABLE\tNOTE")
	for _, c := range candidates {
		avail := "no"
		if c.Probe.Available {
			avail = "yes"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", c.Backend.Name(), avail, c.Probe.Reason)
	}
	_ = tw.Flush()

	chosen := *storageName
	if chosen == "" {
		rec := storage.Recommend(candidates)
		if rec == nil {
			return errors.New("no storage backend is available; install a credential store or use -storage agevault")
		}
		chosen = rec.Backend.Name()
		if chosen == "dotenv" && !*allowDotenv {
			return errors.New("only the dotenv backend is available; pass -allow-dotenv to accept a plain file, or -storage agevault")
		}
		fmt.Fprintf(a.stdout, "\nrecommended: %s (%s)\n", chosen, rec.Probe.Reason)
		ok, err := a.confirm("Use it?", *yes)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("cancelled; rerun with -storage NAME")
		}
	} else {
		found := false
		for _, c := range candidates {
			if c.Backend.Name() == chosen {
				found = true
				if !c.Probe.Available {
					fmt.Fprintf(a.stderr, "warning: %s is not available right now: %s\n", chosen, c.Probe.Reason)
				}
			}
		}
		if !found {
			return fmt.Errorf("unknown storage backend %q; choose one of %s", chosen, strings.Join(agent.KnownBackends, ", "))
		}
		if chosen == "dotenv" && !*allowDotenv {
			return errors.New("the dotenv backend stores values in a plain file; pass -allow-dotenv to accept that")
		}
	}

	cfg := agent.Config{Relay: rc.Origin, Storage: chosen, PageOrigin: *pageOrigin, DefaultTTL: "1h", DefaultRetention: agent.DefaultRetention}
	if chosen == "dotenv" {
		cfg.Backends.Dotenv.Path = paths.DotenvFile()
	}
	if info.AgentAuth != "off" {
		switch *keyFrom {
		case "", "keychain", "prompt":
			key, err := a.readSecret("Agent key from the relay operator (not echoed): ")
			if err != nil {
				return err
			}
			trimmed := strings.TrimSpace(string(key))
			if trimmed == "" {
				return errors.New("an agent key is required because the relay requires agent auth; rerun with -agent-key-from env to supply it at run time")
			}
			if err := a.keychainSet(agent.AppName, agent.KeychainAgentKeyRef, trimmed); err != nil {
				return fmt.Errorf("could not store the agent key in the keychain (%v); rerun with -agent-key-from env", err)
			}
			cfg.AgentKey = agent.DefaultAgentKeyRef
			fmt.Fprintln(a.stdout, "agent key stored in the keychain")
		case "env":
			cfg.AgentKey = "env:" + agent.DefaultAgentKeyEnv
			fmt.Fprintf(a.stdout, "the agent key will be read from %s at run time\n", agent.DefaultAgentKeyEnv)
		default:
			return fmt.Errorf("-agent-key-from must be env, keychain, or prompt")
		}
	}
	if err := agent.SaveConfig(paths.ConfigFile, cfg); err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "\nwrote %s\nstorage: %s\nnext: add the MCP server to your agent (burndrop instructions -format mcp-json) and paste the instructions (burndrop instructions)\n", paths.ConfigFile, chosen)
	return nil
}
