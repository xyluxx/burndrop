import { describe, expect, it } from "vitest";

import { BurndropError, Redactor, ValidationError, runWithSecret } from "../src/index.js";
import { utf8 } from "./helpers.js";

const node = process.execPath;

describe("runWithSecret", () => {
  it("injects the value into the child and redacts it on the way back", async () => {
    const out = await runWithSecret(node, ["-e", 'console.log("key=" + process.env.API_KEY); console.error("err=" + process.env.API_KEY)'], {
      API_KEY: utf8("super-secret-value"),
    });
    expect(out.exitCode).toBe(0);
    expect(out.timedOut).toBe(false);
    expect(out.stdout).toContain("key=[redacted:API_KEY]");
    expect(out.stderr).toContain("err=[redacted:API_KEY]");
    expect(out.stdout).not.toContain("super-secret-value");
    expect(out.stderr).not.toContain("super-secret-value");
    expect(out.durationMs).toBeGreaterThanOrEqual(0);
  });

  it("redacts encoded forms and values known to a shared redactor", async () => {
    const redactor = new Redactor();
    redactor.add("db-password", "earlier-known-value");
    const out = await runWithSecret(
      node,
      ["-e", 'console.log(Buffer.from(process.env.API_KEY).toString("base64")); console.log("earlier-known-value")'],
      { API_KEY: "super-secret-value" },
      { redactor },
    );
    expect(out.stdout).not.toContain("c3VwZXItc2VjcmV0LXZhbHVl");
    expect(out.stdout).toContain("[redacted:API_KEY]");
    expect(out.stdout).toContain("[redacted:db-password]");
  });

  it("reports exit codes and honors discardOutput", async () => {
    const out = await runWithSecret(node, ["-e", 'console.log("visible"); process.exit(3)'], {}, { discardOutput: true });
    expect(out.exitCode).toBe(3);
    expect(out.stdout).toBe("");
    const shown = await runWithSecret(node, ["-e", 'console.log("visible")'], {});
    expect(shown.stdout.trim()).toBe("visible");
  });

  it("truncates long output after redaction", async () => {
    const out = await runWithSecret(node, ["-e", 'console.log("a".repeat(500))'], {}, { maxOutputBytes: 50 });
    expect(out.truncated).toBe(true);
    expect(out.stdout.endsWith("\n[truncated]")).toBe(true);
    expect(out.stdout.length).toBe(50 + "\n[truncated]".length);
  });

  it("stops the child at the timeout", async () => {
    const out = await runWithSecret(node, ["-e", "setTimeout(() => {}, 20000)"], {}, { timeoutMs: 300 });
    expect(out.timedOut).toBe(true);
    expect(out.exitCode).toBe(-1);
  });

  it("feeds standard input and the working directory", async () => {
    const out = await runWithSecret(node, ["-e", "process.stdin.pipe(process.stdout)"], {}, { stdin: "line one\nline two\n" });
    expect(out.stdout).toBe("line one\nline two\n");
    const bytes = await runWithSecret(node, ["-e", "process.stdin.pipe(process.stdout)"], {}, { stdin: utf8("bytes") });
    expect(bytes.stdout).toBe("bytes");
    const cwd = await runWithSecret(node, ["-e", "console.log(process.cwd())"], {}, { cwd: process.cwd() });
    expect(cwd.stdout.trim().toLowerCase()).toBe(process.cwd().toLowerCase());
  });

  it("builds the child environment from baseEnv plus the secrets", async () => {
    const out = await runWithSecret(node, ["-e", 'console.log(process.env.FOO + ":" + process.env.SECRET_X + ":" + (process.env.NOT_SET === undefined))'], { SECRET_X: "value-of-x-here" }, {
      baseEnv: { FOO: "bar", PATH: process.env.PATH ?? "", SECRET_X: "overridden" },
    });
    expect(out.stdout.trim()).toBe("bar:[redacted:SECRET_X]:true");
  });

  it("rejects bad arguments and programs that cannot start", async () => {
    await expect(runWithSecret("", [], {})).rejects.toBeInstanceOf(ValidationError);
    await expect(runWithSecret(node, [], { "1BAD": "value-value" })).rejects.toBeInstanceOf(ValidationError);
    await expect(runWithSecret(node, [], { "A=B": "value-value" })).rejects.toBeInstanceOf(ValidationError);
    await expect(runWithSecret("definitely-not-a-program-xyz", [], { KEY: "super-secret-value" })).rejects.toThrow(BurndropError);
    await expect(runWithSecret("definitely-not-a-program-xyz", [], { KEY: "super-secret-value" })).rejects.toThrow(/could not start/);
  });
});
