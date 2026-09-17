package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/burndrop/burndrop/internal/agent"
	"github.com/burndrop/burndrop/internal/client"
	"github.com/burndrop/burndrop/web"
)

// cmdVerifyPage fetches the hosted drop page and compares its hash with the
// hash the relay reports, the hash embedded in this binary, and an optional
// expected value from the release notes.
func (a *app) cmdVerifyPage(ctx context.Context, args []string) error {
	fs := a.flags("verify-page", "[-relay URL] [-expect SHA256]")
	relay := fs.String("relay", "", "relay origin (default from config)")
	expect := fs.String("expect", "", "expected hex SHA-256 of the page, from the release notes or page.sha256")
	if err := a.parse(fs, args); err != nil {
		return err
	}
	origin := *relay
	if origin == "" {
		paths, err := agent.DefaultPaths(a.getenv)
		if err != nil {
			return err
		}
		cfg, err := agent.LoadConfig(paths.ConfigFile)
		if err != nil {
			return fmt.Errorf("pass -relay or run init first: %w", err)
		}
		origin = cfg.Relay
	}
	rc, err := client.New(origin, "", "burndrop-cli/"+a.version)
	if err != nil {
		return err
	}
	served, err := rc.PageHash(ctx)
	if err != nil {
		return fmt.Errorf("could not fetch the page: %w", err)
	}
	info, err := rc.Info(ctx)
	if err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "served page:    %s\n", served)
	fmt.Fprintf(a.stdout, "relay reports:  %s (page version %s)\n", info.PageSHA256, info.PageVersion)
	failed := false
	if info.PageSHA256 != served {
		fmt.Fprintln(a.stdout, "MISMATCH: the relay serves a page whose hash differs from what it reports")
		failed = true
	}
	if page, err := web.Load(); err == nil {
		fmt.Fprintf(a.stdout, "this binary:    %s (page version %s)\n", page.Meta.SHA256, page.Meta.Version)
		if page.Meta.SHA256 != served {
			fmt.Fprintln(a.stdout, "note: the served page differs from the one embedded in this binary (different release or a modified relay)")
		}
	} else if errors.Is(err, web.ErrNotBuilt) {
		fmt.Fprintln(a.stdout, "this binary:    no page embedded")
	}
	if *expect != "" {
		fmt.Fprintf(a.stdout, "expected:       %s\n", *expect)
		if *expect != served {
			fmt.Fprintln(a.stdout, "MISMATCH: the served page is not the expected release page")
			failed = true
		}
	}
	if failed {
		return errors.New("page verification failed; do not use this relay's page until the operator explains the difference")
	}
	fmt.Fprintln(a.stdout, "ok")
	return nil
}

// cmdDoctor checks every moving part and prints one line per check.
func (a *app) cmdDoctor(ctx context.Context, args []string) int {
	fs := a.flags("doctor", "")
	if err := a.parse(fs, args); err != nil {
		if errors.Is(err, errUsage) {
			return 2
		}
		return 0
	}
	problems := 0
	check := func(name string, err error, detail string) {
		if err != nil {
			problems++
			fmt.Fprintf(a.stdout, "FAIL  %-14s %v\n", name, err)
			return
		}
		fmt.Fprintf(a.stdout, "ok    %-14s %s\n", name, detail)
	}
	paths, err := agent.DefaultPaths(a.getenv)
	check("paths", err, paths.ConfigFile)
	if err != nil {
		return 1
	}
	cfg, err := agent.LoadConfig(paths.ConfigFile)
	check("config", err, "relay "+cfg.Relay+", storage "+cfg.Storage)
	if err != nil {
		return 1
	}
	if info, err := os.Stat(paths.ConfigFile); err == nil && info.Mode().Perm()&0o077 != 0 && os.Getenv("OS") != "Windows_NT" {
		check("config mode", fmt.Errorf("%s is readable by other users (mode %o); chmod 600 it", paths.ConfigFile, info.Mode().Perm()), "")
	}
	_, src, err := cfg.ResolveAgentKey(a.getenv, a.keychainGet)
	keyNote := "from " + src
	if src == agent.AgentKeyNone {
		keyNote = "none needed (the relay was set up without agent auth)"
	}
	check("agent key", err, keyNote)
	rc, err := client.New(cfg.Relay, "", "burndrop-cli/"+a.version)
	check("relay origin", err, rc.Origin)
	if err == nil {
		info, err := rc.Info(ctx)
		detail := ""
		if err == nil {
			detail = fmt.Sprintf("version %s, page served %v, agent auth %s", info.Version, info.PageServed, info.AgentAuth)
		}
		check("relay", err, detail)
		if err == nil && info.PageServed {
			served, err := rc.PageHash(ctx)
			if err == nil && served != info.PageSHA256 {
				err = errors.New("served page hash differs from the hash the relay reports")
			}
			check("page hash", err, served)
		}
	}
	check("state dir", paths.EnsureStateDir(), paths.StateDir)
	backend, err := agent.OpenBackend(cfg, paths, a.getenv)
	check("backend open", err, cfg.Storage)
	if err == nil {
		p := backend.Probe(ctx)
		var perr error
		if !p.Available {
			perr = errors.New(p.Reason)
		}
		check("backend probe", perr, p.Reason)
	}
	l, err := a.load(false)
	check("agent", err, "")
	if err == nil {
		defer l.agent.Store.Close()
		n, err := l.agent.Store.PurgeExpired(ctx)
		check("purge expired", err, fmt.Sprintf("%d removed", n))
		pending, err := l.agent.Pending(ctx)
		check("pending", err, fmt.Sprintf("%d outstanding", len(pending)))
		list, err := l.agent.List(ctx)
		check("secrets", err, fmt.Sprintf("%d stored", len(list)))
		check("audit log", nil, l.agent.Audit.Path())
	}
	if problems > 0 {
		fmt.Fprintf(a.stdout, "\n%d problem(s)\n", problems)
		return 1
	}
	fmt.Fprintln(a.stdout, "\nall checks passed")
	return 0
}
