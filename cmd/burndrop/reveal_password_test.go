package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRevealPassword(t *testing.T) {
	c := newCLI(t).initialized()
	sh := shellArgs(t)

	out := c.mustRun("reveal-password")
	if !strings.Contains(out, "not set") {
		t.Fatalf("status: %s", out)
	}
	if code, _, errOut := c.run("reveal-password", "on"); code != 1 || !strings.Contains(errOut, "no reveal password is set") {
		t.Fatalf("on without a password: %d %s", code, errOut)
	}
	c.secret = "short"
	if code, _, errOut := c.run("reveal-password", "set"); code != 1 || !strings.Contains(errOut, "at least 8") {
		t.Fatalf("short password: %d %s", code, errOut)
	}
	c.secret = "correct horse battery staple"
	out = c.mustRun("reveal-password", "set")
	if !strings.Contains(out, "reveal password: on") {
		t.Fatalf("set: %s", out)
	}
	if code, _, _ := c.run("reveal-password", "bogus"); code != 2 {
		t.Fatal("unknown subcommand must be a usage error")
	}

	// A captured secret is sendable; its link now carries a salt.
	c.mustRun(append([]string{"run", "-capture-as", "gen", "--"}, append(sh, "echo hello-from-agent")...)...)
	out = c.mustRun("send", "gen", "-yes", "-json")
	var sent map[string]any
	if err := json.Unmarshal([]byte(out), &sent); err != nil {
		t.Fatalf("send json: %v\n%s", err, out)
	}
	link, _ := sent["link"].(string)
	message, _ := sent["message"].(string)
	if sent["password_protected"] != true || !strings.Contains(link, "&s=") || !strings.Contains(message, "reveal password") {
		t.Fatalf("send: %s", out)
	}

	// The human opens it with the password; the link is spent afterwards.
	out = c.mustRun("open", link, "-yes")
	if strings.TrimSpace(out) != "hello-from-agent" {
		t.Fatalf("open: %q", out)
	}
	if code, _, errOut := c.run("open", link, "-yes"); code != 1 || !strings.Contains(errOut, "already used") {
		t.Fatalf("open twice: %d %s", code, errOut)
	}

	// A wrong password, five times, gives up without printing anything.
	out = c.mustRun("send", "gen", "-yes", "-json")
	if err := json.Unmarshal([]byte(out), &sent); err != nil {
		t.Fatal(err)
	}
	link, _ = sent["link"].(string)
	c.secret = "not the password"
	if code, stdout, errOut := c.run("open", link, "-yes"); code != 1 || stdout != "" || !strings.Contains(errOut, "wrong password") || !strings.Contains(errOut, "Wrong password. The relay copy") {
		t.Fatalf("wrong password: %d %q %s", code, stdout, errOut)
	}

	// Off: plain links again. On: salted links again. Clear: nothing set.
	c.secret = "correct horse battery staple"
	out = c.mustRun("reveal-password", "off")
	if !strings.Contains(out, "set but off") {
		t.Fatalf("off: %s", out)
	}
	out = c.mustRun("send", "gen", "-yes", "-json")
	if strings.Contains(out, "&s=") || strings.Contains(out, `"password_protected": true`) {
		t.Fatalf("send after off: %s", out)
	}
	c.mustRun("reveal-password", "on")
	out = c.mustRun("send", "gen", "-yes", "-json")
	if !strings.Contains(out, "&s=") {
		t.Fatalf("send after on: %s", out)
	}
	out = c.mustRun("reveal-password", "clear")
	if !strings.Contains(out, "not set") {
		t.Fatalf("clear: %s", out)
	}
	if code, _, _ := c.run("reveal-password", "on"); code != 1 {
		t.Fatal("on after clear must fail")
	}
	if _, ok := c.kc["reveal-password"]; ok {
		t.Fatal("clear left the keychain entry behind")
	}
}
