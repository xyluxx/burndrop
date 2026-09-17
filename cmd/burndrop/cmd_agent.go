package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/xyluxx/burndrop/internal/agent"
	"github.com/xyluxx/burndrop/internal/mcpserver"
	"github.com/xyluxx/burndrop/internal/storage"
)

func (a *app) cmdMCP(ctx context.Context, args []string) error {
	fs := a.flags("mcp", "[-no-confirm]")
	noConfirm := fs.Bool("no-confirm", false, "do not ask the human to confirm send_secret through elicitation")
	if err := a.parse(fs, args); err != nil {
		return err
	}
	l, err := a.load(true)
	if err != nil {
		return err
	}
	defer l.agent.Store.Close()
	confirm := !*noConfirm
	apply := func(required bool) error {
		if err := l.cfg.SetRevealPasswordRequired(required); err != nil {
			return err
		}
		if err := agent.SaveConfig(l.paths.ConfigFile, l.cfg); err != nil {
			return err
		}
		l.agent.Config.RevealPasswordRequired = required
		return nil
	}
	server := mcpserver.New(l.agent, mcpserver.Options{Version: a.version, ConfirmSend: &confirm, ApplyRevealPassword: apply})
	fmt.Fprintf(a.stderr, "burndrop %s: MCP server on stdio, relay %s, storage %s\n", a.version, l.cfg.Relay, l.cfg.Storage)
	return server.Run(ctx, &mcp.StdioTransport{})
}

func (a *app) cmdRequest(ctx context.Context, args []string) error {
	fs := a.flags("request", "-name NAME -purpose TEXT [-retention POLICY] [-ttl DURATION] [-sendable] [-json]")
	name := fs.String("name", "", "reference name, for example openai-api-key")
	purpose := fs.String("purpose", "", "one sentence shown to the human")
	retention := fs.String("retention", "", "session, until-revoked, or until:<RFC 3339 date> (default from config)")
	ttl := fs.String("ttl", "", "link lifetime, for example 30m (default from config)")
	sendable := fs.Bool("sendable", false, "allow the secret to be sent back to a human later")
	asJSON := fs.Bool("json", false, "print the result as JSON")
	if err := a.parse(fs, args); err != nil {
		return err
	}
	if *name == "" || *purpose == "" {
		fs.Usage()
		return errUsage
	}
	l, err := a.load(true)
	if err != nil {
		return err
	}
	defer l.agent.Store.Close()
	out, err := l.agent.Request(ctx, agent.RequestInput{Name: *name, Purpose: *purpose, Retention: *retention, TTL: *ttl, Sendable: *sendable})
	if err != nil {
		return err
	}
	if *asJSON {
		return a.printJSON(out)
	}
	fmt.Fprintln(a.stdout, out.Message)
	fmt.Fprintf(a.stdout, "\nrequest id: %s\n", out.RequestID)
	if out.Retention == storage.RetentionSession {
		fmt.Fprintln(a.stderr, "note: retention session keeps the value only in the process that fetches it, so with one-shot CLI commands it is gone when fetch returns; use -retention until-revoked or until:<date>, or run the MCP server")
	}
	return nil
}

func (a *app) cmdFetch(ctx context.Context, args []string) error {
	fs := a.flags("fetch", "[REQUEST_ID] [-wait SECONDS] [-json]")
	wait := fs.Int("wait", 30, "seconds to wait for the submission, 1 to 300 (0 means the default of 30)")
	asJSON := fs.Bool("json", false, "print the result as JSON")
	if err := a.parse(fs, args); err != nil {
		return err
	}
	id := fs.Arg(0)
	l, err := a.load(true)
	if err != nil {
		return err
	}
	defer l.agent.Store.Close()
	out, err := l.agent.Fetch(ctx, agent.FetchInput{RequestID: id, WaitSeconds: *wait})
	if err != nil {
		return err
	}
	if *asJSON {
		return a.printJSON(out)
	}
	fmt.Fprintf(a.stdout, "%s: %s\n", out.Status, out.Message)
	if out.Status == agent.StatusWaiting {
		return errors.New("still waiting; run fetch again")
	}
	return nil
}

func (a *app) cmdSend(ctx context.Context, args []string) error {
	fs := a.flags("send", "NAME [-ttl DURATION] [-delete-after] [-yes] [-json]")
	ttl := fs.String("ttl", "", "link lifetime, for example 30m (default from config)")
	deleteAfter := fs.Bool("delete-after", false, "delete the agent's copy once the link exists")
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	asJSON := fs.Bool("json", false, "print the result as JSON")
	if err := a.parse(fs, args); err != nil {
		return err
	}
	name := fs.Arg(0)
	if name == "" {
		fs.Usage()
		return errUsage
	}
	l, err := a.load(true)
	if err != nil {
		return err
	}
	defer l.agent.Store.Close()
	if err := l.agent.CanSend(ctx, name); err != nil {
		return err
	}
	ok, err := a.confirm(fmt.Sprintf("Create a one-time link that reveals %q to whoever opens it?", name), *yes)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("cancelled")
	}
	out, err := l.agent.Send(ctx, agent.SendInput{Name: name, TTL: *ttl, DeleteAfter: *deleteAfter})
	if err != nil {
		return err
	}
	if *asJSON {
		return a.printJSON(out)
	}
	fmt.Fprintln(a.stdout, out.Message)
	return nil
}

// envFlags collects repeated -env VAR=NAME flags.
type envFlags map[string]string

func (e envFlags) String() string { return "" }

func (e envFlags) Set(v string) error {
	k, name, ok := strings.Cut(v, "=")
	if !ok || k == "" || name == "" {
		return fmt.Errorf("expected VAR=secret-name, got %q", v)
	}
	e[k] = name
	return nil
}

func (a *app) cmdRun(ctx context.Context, args []string) int {
	fs := a.flags("run", "[-env VAR=NAME ...] [-capture-as NAME [-capture-pattern REGEXP] [-capture-retention POLICY]] [-consume] [-timeout SECONDS] [-cwd DIR] -- COMMAND [ARGS...]")
	env := envFlags{}
	fs.Var(env, "env", "inject secret NAME as environment variable VAR (repeatable)")
	captureAs := fs.String("capture-as", "", "store the command's output as a new sendable secret instead of printing it")
	pattern := fs.String("capture-pattern", "", "regular expression with one group to extract the captured value")
	retention := fs.String("capture-retention", "", "retention for the captured secret (default from config)")
	timeout := fs.Int("timeout", 0, "seconds before the command is stopped (default 120)")
	cwd := fs.String("cwd", "", "working directory")
	consume := fs.Bool("consume", false, "delete the used secrets after the run")
	if err := a.parseCommand(fs, args); err != nil {
		if errors.Is(err, errUsage) {
			return 2
		}
		return 0
	}
	command := fs.Args()
	if len(command) == 0 {
		fs.Usage()
		return 2
	}
	l, err := a.load(true)
	if err != nil {
		fmt.Fprintln(a.stderr, "error:", err)
		return 1
	}
	defer l.agent.Store.Close()
	in := agent.RunInput{Command: command, Env: env, Cwd: *cwd, TimeoutSeconds: *timeout, Consume: *consume}
	if *captureAs != "" {
		in.CaptureAs = &agent.CaptureSpec{Name: *captureAs, Pattern: *pattern, Retention: *retention}
	}
	out, err := l.agent.Run(ctx, in)
	if err != nil {
		fmt.Fprintln(a.stderr, "error:", err)
		return 1
	}
	if out.Stdout != "" {
		fmt.Fprint(a.stdout, out.Stdout)
	}
	if out.Stderr != "" {
		fmt.Fprint(a.stderr, out.Stderr)
	}
	if out.Message != "" {
		fmt.Fprintln(a.stderr, out.Message)
	}
	if out.TimedOut {
		return 124
	}
	if out.ExitCode < 0 {
		return 1
	}
	return out.ExitCode
}

func (a *app) cmdList(ctx context.Context, args []string) error {
	fs := a.flags("list", "[-json]")
	asJSON := fs.Bool("json", false, "print as JSON")
	if err := a.parse(fs, args); err != nil {
		return err
	}
	l, err := a.load(false)
	if err != nil {
		return err
	}
	defer l.agent.Store.Close()
	list, err := l.agent.List(ctx)
	if err != nil {
		return err
	}
	if *asJSON {
		return a.printJSON(list)
	}
	if len(list) == 0 {
		fmt.Fprintln(a.stdout, "no stored secrets")
		return nil
	}
	tw := tabwriter.NewWriter(a.stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tSTORAGE\tRETENTION\tCREATED\tEXPIRES\tSENDABLE\tSOURCE\tBYTES")
	for _, m := range list {
		expires := "-"
		if !m.ExpiresAt.IsZero() {
			expires = m.ExpiresAt.UTC().Format(time.RFC3339)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%v\t%s\t%d\n", m.Name, m.Backend, m.Retention, m.CreatedAt.UTC().Format(time.RFC3339), expires, m.Sendable, m.Source, m.SizeBytes)
	}
	return tw.Flush()
}

func (a *app) cmdDelete(ctx context.Context, args []string) error {
	fs := a.flags("delete", "NAME")
	if err := a.parse(fs, args); err != nil {
		return err
	}
	name := fs.Arg(0)
	if name == "" {
		fs.Usage()
		return errUsage
	}
	l, err := a.load(false)
	if err != nil {
		return err
	}
	defer l.agent.Store.Close()
	if err := l.agent.Delete(ctx, name); err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "deleted %s\n", name)
	return nil
}

func (a *app) cmdPending(ctx context.Context, args []string) error {
	fs := a.flags("pending", "[-json]")
	asJSON := fs.Bool("json", false, "print as JSON")
	if err := a.parse(fs, args); err != nil {
		return err
	}
	l, err := a.load(false)
	if err != nil {
		return err
	}
	defer l.agent.Store.Close()
	pending, err := l.agent.Pending(ctx)
	if err != nil {
		return err
	}
	if *asJSON {
		return a.printJSON(pending)
	}
	if len(pending) == 0 {
		fmt.Fprintln(a.stdout, "no pending requests")
		return nil
	}
	tw := tabwriter.NewWriter(a.stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "REQUEST ID\tNAME\tFINGERPRINT\tRETENTION\tEXPIRES")
	for _, p := range pending {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", p.RequestID, p.Name, p.Fingerprint, p.Retention, p.ExpiresAt.UTC().Format(time.RFC3339))
	}
	return tw.Flush()
}

func (a *app) cmdRevoke(ctx context.Context, args []string) error {
	fs := a.flags("revoke", "REQUEST_ID")
	if err := a.parse(fs, args); err != nil {
		return err
	}
	id := fs.Arg(0)
	if id == "" {
		fs.Usage()
		return errUsage
	}
	l, err := a.load(true)
	if err != nil {
		return err
	}
	defer l.agent.Store.Close()
	state, err := l.agent.Revoke(ctx, id)
	if err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "request %s is now %s\n", id, state)
	return nil
}

func (a *app) cmdAudit(_ context.Context, args []string) error {
	fs := a.flags("audit", "[-n COUNT] [-json]")
	n := fs.Int("n", 50, "number of most recent events to show")
	asJSON := fs.Bool("json", false, "print as JSON")
	if err := a.parse(fs, args); err != nil {
		return err
	}
	l, err := a.load(false)
	if err != nil {
		return err
	}
	defer l.agent.Store.Close()
	events, err := l.agent.Audit.Read(*n)
	if err != nil {
		return err
	}
	if *asJSON {
		return a.printJSON(events)
	}
	if len(events) == 0 {
		fmt.Fprintln(a.stdout, "no audit events")
		return nil
	}
	tw := tabwriter.NewWriter(a.stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "TIME\tEVENT\tNAME\tREQUEST\tRESULT\tDETAIL")
	for _, e := range events {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", e.Time.UTC().Format(time.RFC3339), e.Event, e.Name, e.DropID, e.Result, e.Detail)
	}
	return tw.Flush()
}

func (a *app) cmdInstructions(args []string) error {
	fs := a.flags("instructions", "[-format text|claude|cursor|agents|mcp-json|vscode-mcp-json]")
	format := fs.String("format", "text", "text, claude (CLAUDE.md section), cursor (.cursor/rules file), agents (AGENTS.md section), mcp-json (client configuration), or vscode-mcp-json (.vscode/mcp.json)")
	if err := a.parse(fs, args); err != nil {
		return err
	}
	switch *format {
	case "text":
		fmt.Fprintln(a.stdout, mcpserver.Instructions)
	case "claude", "agents":
		fmt.Fprint(a.stdout, "## Secrets: use burndrop\n\n")
		fmt.Fprintln(a.stdout, mcpserver.Instructions)
	case "cursor":
		fmt.Fprint(a.stdout, "---\ndescription: How to handle secrets with the burndrop MCP tools\nalwaysApply: true\n---\n\n")
		fmt.Fprintln(a.stdout, mcpserver.Instructions)
	case "mcp-json":
		fmt.Fprintln(a.stdout, `{
  "mcpServers": {
    "burndrop": {
      "command": "burndrop",
      "args": ["mcp"]
    }
  }
}`)
	case "vscode-mcp-json":
		fmt.Fprintln(a.stdout, `{
  "servers": {
    "burndrop": {
      "type": "stdio",
      "command": "burndrop",
      "args": ["mcp"]
    }
  }
}`)
	default:
		fs.Usage()
		return errUsage
	}
	return nil
}
