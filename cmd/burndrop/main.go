// Command burndrop is the agent-side tool: it runs the MCP server, drives
// the request, fetch, send, and run flows from the command line, and gives
// humans a terminal alternative to the drop page.
//
// Run burndrop help for the command list.
package main

import (
	"os"
)

// version is set at build time with -ldflags "-X main.version=v1.2.3".
var version = "dev"

func main() {
	a := newApp(os.Stdin, os.Stdout, os.Stderr, os.Getenv)
	a.version = version
	os.Exit(a.run(os.Args[1:]))
}
