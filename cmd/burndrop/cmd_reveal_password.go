package main

import (
	"context"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/xyluxx/burndrop/internal/agent"
	"github.com/xyluxx/burndrop/internal/crypto"
)

// cmdRevealPassword manages the password that reveal links ask for. The
// password is typed here, in a terminal, and kept in the keychain; it never
// passes through the chat, the model, or the config file.
func (a *app) cmdRevealPassword(_ context.Context, args []string) error {
	fs := a.flags("reveal-password", "[status|set|on|off|clear]")
	if err := a.parse(fs, args); err != nil {
		return err
	}
	sub := fs.Arg(0)
	if sub == "" {
		sub = "status"
	}
	paths, err := agent.DefaultPaths(a.getenv)
	if err != nil {
		return err
	}
	cfg, err := agent.LoadConfig(paths.ConfigFile)
	if err != nil {
		return err
	}
	switch sub {
	case "status":
		a.printRevealPasswordStatus(cfg)
		return nil
	case "set":
		pw, err := a.readSecret(fmt.Sprintf("New reveal password (not echoed, at least %d characters): ", crypto.MinPasswordLen))
		if err != nil {
			return err
		}
		if utf8.RuneCount(pw) < crypto.MinPasswordLen {
			zero(pw)
			return fmt.Errorf("the reveal password must be at least %d characters", crypto.MinPasswordLen)
		}
		again, err := a.readSecret("Type it again (not echoed): ")
		if err != nil {
			zero(pw)
			return err
		}
		same := string(pw) == string(again)
		zero(again)
		if !same {
			zero(pw)
			return errors.New("the two passwords differ; nothing changed")
		}
		err = a.keychainSet(agent.AppName, agent.KeychainRevealPasswordRef, string(pw))
		zero(pw)
		if err != nil {
			return fmt.Errorf("could not store the reveal password in the keychain: %v", err)
		}
		cfg.RevealPassword = agent.DefaultRevealPasswordRef
		cfg.RevealPasswordRequired = true
	case "on":
		if err := cfg.SetRevealPasswordRequired(true); err != nil {
			return err
		}
	case "off":
		if err := cfg.SetRevealPasswordRequired(false); err != nil {
			return err
		}
	case "clear":
		if cfg.RevealPassword == agent.DefaultRevealPasswordRef {
			if err := a.keychainDelete(agent.AppName, agent.KeychainRevealPasswordRef); err != nil {
				fmt.Fprintf(a.stderr, "warning: could not remove the keychain entry: %v\n", err)
			}
		}
		cfg.RevealPassword = ""
		cfg.RevealPasswordRequired = false
	default:
		fs.Usage()
		return errUsage
	}
	if err := agent.SaveConfig(paths.ConfigFile, cfg); err != nil {
		return err
	}
	a.printRevealPasswordStatus(cfg)
	return nil
}

func (a *app) printRevealPasswordStatus(cfg agent.Config) {
	switch {
	case cfg.RevealPasswordRequired:
		fmt.Fprintln(a.stdout, "reveal password: on (every reveal link asks for it before showing the value)")
	case cfg.RevealPassword != "":
		fmt.Fprintln(a.stdout, "reveal password: set but off (turn it on with: burndrop reveal-password on)")
	default:
		fmt.Fprintln(a.stdout, "reveal password: not set (set one with: burndrop reveal-password set)")
	}
}
