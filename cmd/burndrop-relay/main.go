// Command burndrop-relay runs the zero-knowledge relay.
//
//	burndrop-relay serve      start the relay (default)
//	burndrop-relay keygen     print a new agent key and its config entry
//	burndrop-relay version    print the version
//
// Configuration comes from BURNDROP_* environment variables; see
// docs/self-hosting.md or run with BURNDROP_PUBLIC_ORIGIN unset for the list.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/burndrop/burndrop/internal/crypto"
	"github.com/burndrop/burndrop/internal/relay"
	"github.com/burndrop/burndrop/web"
)

// version is set at build time with -ldflags "-X main.version=v1.2.3".
var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
}

func run(args []string, getenv func(string) string, stdout, stderr *os.File) int {
	cmd := "serve"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	switch cmd {
	case "serve":
		return serve(args, getenv, stderr)
	case "keygen":
		return keygen(args, stdout, stderr)
	case "version":
		fmt.Fprintln(stdout, "burndrop-relay", version)
		return 0
	case "help", "-h", "--help":
		usage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n", cmd)
		usage(stderr)
		return 2
	}
}

func usage(w *os.File) {
	fmt.Fprint(w, `burndrop-relay: zero-knowledge relay for one-time secret drops

Commands:
  serve      Start the relay (default). Configured by BURNDROP_* variables.
  keygen     Generate an agent key. Prints the key once and the config entry.
  version    Print the version.

Required: BURNDROP_PUBLIC_ORIGIN (for example https://drop.example.com)
          BURNDROP_AGENT_KEYS   (unless BURNDROP_AGENT_AUTH=off)
`)
}

func keygen(args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	id := fs.String("id", "agent1", "identifier for the key in BURNDROP_AGENT_KEYS")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if strings.ContainsAny(*id, ":, \t\n") || *id == "" {
		fmt.Fprintln(stderr, "id must not be empty or contain ':', ',' or whitespace")
		return 2
	}
	key, err := crypto.RandomAgentKey()
	if err != nil {
		fmt.Fprintln(stderr, "could not generate key:", err)
		return 1
	}
	fmt.Fprintf(stdout, "Agent key for %q (shown once, give it to the agent):\n\n  %s\n\n", *id, key)
	fmt.Fprintf(stdout, "Relay configuration (only the hash is stored):\n\n  BURNDROP_AGENT_KEYS=%s\n", relay.FormatAgentKey(*id, key))
	return 0
}

func serve(args []string, getenv func(string) string, stderr *os.File) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := relay.LoadConfig(getenv)
	if err != nil {
		fmt.Fprintln(stderr, "configuration error:", err)
		return 2
	}
	logger := newLogger(cfg, stderr)

	store, err := relay.NewStore(cfg, time.Now)
	if err != nil {
		logger.Error("store", "err", err.Error())
		return 1
	}
	defer func() { _ = store.Close() }()

	var page *web.Page
	if cfg.ServePage {
		page, err = web.Load()
		if err != nil {
			if errors.Is(err, web.ErrNotBuilt) {
				logger.Warn("drop page not built into this binary; /drop and /reveal will return 503")
			} else {
				logger.Error("drop page", "err", err.Error())
				return 1
			}
		}
	}

	srv := relay.New(cfg, store, relay.Options{Page: page, Version: version, Logger: logger})
	httpServer := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      relay.MaxLongPoll + 15*time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go srv.Sweeper(ctx, 10*time.Second)

	errCh := make(chan error, 1)
	go func() { errCh <- httpServer.ListenAndServe() }()
	logger.Info("relay started", "version", version, "listen", cfg.Listen, "public_origin", cfg.PublicOrigin,
		"store", cfg.Store, "agent_auth", cfg.AgentAuth, "page_served", page != nil, "default_ttl", cfg.DefaultTTL.String(), "max_ttl", cfg.MaxTTL.String())

	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("listen", "err", err.Error())
			return 1
		}
	case <-ctx.Done():
		logger.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			logger.Warn("shutdown", "err", err.Error())
		}
	}
	return 0
}

func newLogger(cfg relay.Config, w *os.File) *slog.Logger {
	var level slog.Level
	switch strings.ToLower(cfg.LogLevel) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: level}
	if cfg.LogFormat == "json" {
		return slog.New(slog.NewJSONHandler(w, opts))
	}
	return slog.New(slog.NewTextHandler(w, opts))
}
