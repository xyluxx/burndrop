package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/xyluxx/burndrop/internal/agent"
	"github.com/xyluxx/burndrop/internal/client"
	"github.com/xyluxx/burndrop/internal/storage"
)

type app struct {
	stdin   io.Reader
	stdout  io.Writer
	stderr  io.Writer
	getenv  func(string) string
	version string
	now     func() time.Time
	// keychainGet reads the agent key from the credential store.
	keychainGet    func(service, entry string) (string, error)
	keychainSet    func(service, entry, value string) error
	keychainDelete func(service, entry string) error
	// isTerminal reports whether stdin is interactive (for prompts).
	isTerminal func() bool
	// readSecret reads a line without echo when interactive.
	readSecret func(prompt string) ([]byte, error)
	// lines buffers stdin once, so consecutive prompts do not lose input.
	lines *bufio.Reader
}

// reader returns the shared buffered reader over stdin.
func (a *app) reader() *bufio.Reader {
	if a.lines == nil {
		a.lines = bufio.NewReader(a.stdin)
	}
	return a.lines
}

func newApp(stdin io.Reader, stdout, stderr io.Writer, getenv func(string) string) *app {
	a := &app{stdin: stdin, stdout: stdout, stderr: stderr, getenv: getenv, version: "dev", now: time.Now}
	kc := storage.NewKeychain("")
	a.keychainGet = func(service, entry string) (string, error) {
		if service != agent.AppName {
			return "", fmt.Errorf("keychain service %q is not supported; use %s", service, agent.AppName)
		}
		return kc.GetRaw(entry)
	}
	a.keychainSet = func(service, entry, value string) error {
		if service != agent.AppName {
			return fmt.Errorf("keychain service %q is not supported; use %s", service, agent.AppName)
		}
		return kc.SetRaw(entry, value)
	}
	a.keychainDelete = func(service, entry string) error {
		if service != agent.AppName {
			return fmt.Errorf("keychain service %q is not supported; use %s", service, agent.AppName)
		}
		return kc.DeleteRaw(entry)
	}
	a.isTerminal = func() bool {
		f, ok := stdin.(*os.File)
		return ok && term.IsTerminal(int(f.Fd()))
	}
	a.readSecret = func(prompt string) ([]byte, error) {
		fmt.Fprint(stderr, prompt)
		if f, ok := stdin.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
			b, err := term.ReadPassword(int(f.Fd()))
			fmt.Fprintln(stderr)
			return b, err
		}
		line, err := a.reader().ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
		return []byte(strings.TrimRight(line, "\r\n")), nil
	}
	return a
}

const usageText = `burndrop: one-time, end-to-end encrypted secret exchange between humans and agents

Agent side:
  init            detect storage backends and write the config file
  mcp             run the MCP server on standard input and output
  request         create a one-time link for a human to submit a secret
  fetch           wait for a submission and store it
  send            create a one-time link that reveals a sendable secret to a human
  run             run a command with secrets injected as environment variables
  list            list stored secrets (never values)
  delete          delete a stored secret
  pending         list outstanding requests
  revoke          revoke a pending request
  audit           show the audit log
  reveal-password set, turn on or off, or clear the password that reveal links ask for

Human side (terminal alternative to the drop page):
  drop            submit a secret for a drop link
  open            open a reveal link and print the value

Maintenance:
  verify-page     check the hosted page hash against the published one
  doctor          check configuration, relay, storage, and audit
  instructions    print the agent instruction snippet
  version         print the version

Run "burndrop <command> -h" for the flags of a command.
`

func (a *app) run(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(a.stdout, usageText)
		return 2
	}
	cmd, rest := args[0], args[1:]
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	var err error
	switch cmd {
	case "help", "-h", "--help":
		fmt.Fprint(a.stdout, usageText)
		return 0
	case "version", "--version":
		fmt.Fprintln(a.stdout, "burndrop", a.version)
		return 0
	case "init":
		err = a.cmdInit(ctx, rest)
	case "mcp":
		err = a.cmdMCP(ctx, rest)
	case "request":
		err = a.cmdRequest(ctx, rest)
	case "fetch":
		err = a.cmdFetch(ctx, rest)
	case "send":
		err = a.cmdSend(ctx, rest)
	case "run":
		return a.cmdRun(ctx, rest)
	case "list":
		err = a.cmdList(ctx, rest)
	case "delete":
		err = a.cmdDelete(ctx, rest)
	case "pending":
		err = a.cmdPending(ctx, rest)
	case "revoke":
		err = a.cmdRevoke(ctx, rest)
	case "audit":
		err = a.cmdAudit(ctx, rest)
	case "reveal-password":
		err = a.cmdRevealPassword(ctx, rest)
	case "drop":
		err = a.cmdDrop(ctx, rest)
	case "open":
		err = a.cmdOpen(ctx, rest)
	case "verify-page":
		err = a.cmdVerifyPage(ctx, rest)
	case "doctor":
		return a.cmdDoctor(ctx, rest)
	case "instructions":
		err = a.cmdInstructions(rest)
	default:
		fmt.Fprintf(a.stderr, "unknown command %q\n\n", cmd)
		fmt.Fprint(a.stderr, usageText)
		return 2
	}
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		if errors.Is(err, errUsage) {
			return 2
		}
		fmt.Fprintln(a.stderr, "error:", err)
		return 1
	}
	return 0
}

var errUsage = errors.New("usage")

// flags builds a FlagSet whose usage and errors go to the app's streams.
func (a *app) flags(name, synopsis string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	fs.Usage = func() {
		fmt.Fprintf(a.stderr, "usage: burndrop %s %s\n", name, synopsis)
		fs.PrintDefaults()
	}
	return fs
}

func (a *app) parse(fs *flag.FlagSet, args []string) error {
	return a.parseWith(fs, args, false)
}

// parseCommand is parse for commands whose positional arguments are a
// program and its own flags: permuting stops at the first positional.
func (a *app) parseCommand(fs *flag.FlagSet, args []string) error {
	return a.parseWith(fs, args, true)
}

func (a *app) parseWith(fs *flag.FlagSet, args []string, stopAtPositional bool) error {
	err := fs.Parse(permute(fs, args, stopAtPositional))
	if errors.Is(err, flag.ErrHelp) {
		return err
	}
	if err != nil {
		return errUsage
	}
	return nil
}

// permute lets flags appear after positional arguments, as people expect
// from "burndrop drop LINK -yes". Everything after "--" stays positional.
// Unknown flags are left for the parser to reject.
func permute(fs *flag.FlagSet, args []string, stopAtPositional bool) []string {
	var flags, positional []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if len(arg) < 2 || arg[0] != '-' || (stopAtPositional && len(positional) > 0) {
			positional = append(positional, arg)
			if stopAtPositional {
				positional = append(positional, args[i+1:]...)
				break
			}
			continue
		}
		name := strings.TrimLeft(arg, "-")
		name, _, hasValue := strings.Cut(name, "=")
		f := fs.Lookup(name)
		flags = append(flags, arg)
		if f != nil && !hasValue && !isBoolFlag(f) && i+1 < len(args) {
			i++
			flags = append(flags, args[i])
		}
	}
	if len(positional) == 0 {
		return flags
	}
	return append(append(flags, "--"), positional...)
}

func isBoolFlag(f *flag.Flag) bool {
	b, ok := f.Value.(interface{ IsBoolFlag() bool })
	return ok && b.IsBoolFlag()
}

// loaded is everything a command needs once the config is read.
type loaded struct {
	paths  agent.Paths
	cfg    agent.Config
	agent  *agent.Agent
	relay  *client.Client
	keySrc string
}

// load reads the config, resolves the agent key, opens the backend, and
// wires an agent. needKey is false for commands that only read local state.
func (a *app) load(needKey bool) (*loaded, error) {
	paths, err := agent.DefaultPaths(a.getenv)
	if err != nil {
		return nil, err
	}
	cfg, err := agent.LoadConfig(paths.ConfigFile)
	if err != nil {
		return nil, err
	}
	key, src, err := cfg.ResolveAgentKey(a.getenv, a.keychainGet)
	if err != nil && needKey {
		return nil, fmt.Errorf("%w (run burndrop init, or set %s)", err, agent.DefaultAgentKeyEnv)
	}
	rc, err := client.New(cfg.Relay, key, "burndrop-cli/"+a.version)
	if err != nil {
		return nil, err
	}
	if err := paths.EnsureStateDir(); err != nil {
		return nil, err
	}
	backend, err := agent.OpenBackend(cfg, paths, a.getenv)
	if err != nil {
		return nil, err
	}
	idx, err := storage.OpenIndex(paths.IndexFile())
	if err != nil {
		return nil, err
	}
	manager := storage.NewManager(backend, idx, a.now)
	auditPath := cfg.Audit.Path
	if auditPath == "" {
		auditPath = paths.AuditFile()
	}
	audit, err := agent.NewAudit(auditPath, a.now)
	if err != nil {
		return nil, fmt.Errorf("audit log: %w", err)
	}
	ag := agent.New(cfg, rc, manager, audit)
	ag.Now = a.now
	if cfg.RevealPassword != "" {
		ag.PasswordSource = func() ([]byte, error) { return cfg.ResolveRevealPassword(a.getenv, a.keychainGet) }
	}
	return &loaded{paths: paths, cfg: cfg, agent: ag, relay: rc, keySrc: src}, nil
}

func (a *app) printJSON(v any) error {
	enc := json.NewEncoder(a.stdout)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false) // links carry "&"; keep them copyable
	return enc.Encode(v)
}

// readValue reads a secret from a file, from standard input when it is not
// a terminal, or from a hidden prompt.
func (a *app) readValue(file string) ([]byte, error) {
	if file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		return b, nil
	}
	if !a.isTerminal() {
		b, err := io.ReadAll(io.LimitReader(a.reader(), storage.MaxValueBytes+1))
		if err != nil {
			return nil, err
		}
		if len(b) > storage.MaxValueBytes {
			return nil, storage.ErrTooLarge
		}
		return []byte(strings.TrimRight(string(b), "\r\n")), nil
	}
	return a.readSecret("Secret value (not echoed): ")
}

func (a *app) confirm(prompt string, yes bool) (bool, error) {
	if yes {
		return true, nil
	}
	if !a.isTerminal() {
		return false, errors.New("confirmation needed; pass -yes when not running interactively")
	}
	fmt.Fprint(a.stderr, prompt+" [y/N] ")
	line, err := a.reader().ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	line = strings.ToLower(strings.TrimSpace(line))
	return line == "y" || line == "yes", nil
}
