/**
 * Runs a command with secret values injected as environment variables and
 * returns its output with every injected value (and its common encodings)
 * replaced by [redacted:<variable name>]. Mirrors the run_with_secret flow
 * of internal/agent/run.go for programs that hold the values themselves.
 *
 * This module uses Node's child_process and is not for the browser.
 */
import { spawn } from "node:child_process";

import { BurndropError, ValidationError } from "./errors.js";
import { Redactor } from "./redact.js";

export interface RunOptions {
  /** Working directory of the child. */
  cwd?: string;
  /** Text or bytes written to the child's standard input. */
  stdin?: string | Uint8Array;
  /** Default 120000 (two minutes), maximum 3600000 (one hour). */
  timeoutMs?: number;
  /** Cap on each returned stream after redaction; default 32768 characters. */
  maxOutputBytes?: number;
  /** Redactor to use; injected values are added to it. Default: a fresh one. */
  redactor?: Redactor;
  /** Return only the exit code. */
  discardOutput?: boolean;
  /** Environment the child inherits; default process.env. */
  baseEnv?: NodeJS.ProcessEnv;
}

export interface RunResult {
  /** The child's exit code, or -1 when it was killed or timed out. */
  exitCode: number;
  stdout: string;
  stderr: string;
  /** Whether stdout or stderr was cut to maxOutputBytes. */
  truncated: boolean;
  timedOut: boolean;
  durationMs: number;
}

const DEFAULT_TIMEOUT_MS = 120_000;
const MAX_TIMEOUT_MS = 3_600_000;
const DEFAULT_MAX_OUTPUT = 32 * 1024;
const MAX_CAPTURED_BYTES = 1 << 20;

const ENV_NAME_RE = /^[A-Za-z_][A-Za-z0-9_]{0,255}$/;

class LimitedBuffer {
  private chunks: Buffer[] = [];
  private size = 0;

  constructor(private readonly max: number) {}

  write(chunk: Buffer): void {
    const room = this.max - this.size;
    if (room <= 0) {
      return;
    }
    const part = chunk.length > room ? chunk.subarray(0, room) : chunk;
    this.chunks.push(part);
    this.size += part.length;
  }

  toString(): string {
    return Buffer.concat(this.chunks).toString("utf8");
  }
}

function truncate(s: string, max: number, result: RunResult): string {
  if (s.length > max) {
    result.truncated = true;
    return s.slice(0, max) + "\n[truncated]";
  }
  return s;
}

/**
 * Executes command with args. Each entry of secrets becomes an environment
 * variable of the child; the values never appear in the returned output.
 * Every injected value is registered with the redactor, so later calls to
 * redactor.redact hide it as well. The child process receives the values in
 * plain form, which is the point: the program that needs the credential gets
 * it, the caller (and any language model reading the result) does not.
 */
export async function runWithSecret(
  command: string,
  args: readonly string[],
  secrets: Record<string, Uint8Array | string>,
  options: RunOptions = {},
): Promise<RunResult> {
  if (command.trim() === "") {
    throw new ValidationError("command must have at least the program name");
  }
  const redactor = options.redactor ?? new Redactor();
  const timeoutMs = Math.min(MAX_TIMEOUT_MS, options.timeoutMs !== undefined && options.timeoutMs > 0 ? options.timeoutMs : DEFAULT_TIMEOUT_MS);
  const maxOutput = options.maxOutputBytes !== undefined && options.maxOutputBytes > 0 ? options.maxOutputBytes : DEFAULT_MAX_OUTPUT;

  const injected: Record<string, string> = {};
  for (const [envName, value] of Object.entries(secrets)) {
    if (!ENV_NAME_RE.test(envName)) {
      throw new ValidationError('"' + envName + '" is not a valid environment variable name');
    }
    redactor.add(envName, value);
    injected[envName] = typeof value === "string" ? value : new TextDecoder("utf-8").decode(value);
  }
  const env: Record<string, string> = {};
  for (const [k, v] of Object.entries(options.baseEnv ?? process.env)) {
    if (v !== undefined && !Object.hasOwn(injected, k)) {
      env[k] = v;
    }
  }
  Object.assign(env, injected);

  const stdout = new LimitedBuffer(MAX_CAPTURED_BYTES);
  const stderr = new LimitedBuffer(MAX_CAPTURED_BYTES);
  const start = Date.now();
  const result: RunResult = { exitCode: -1, stdout: "", stderr: "", truncated: false, timedOut: false, durationMs: 0 };

  await new Promise<void>((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      env,
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
    });
    let settled = false;
    const timer = setTimeout(() => {
      result.timedOut = true;
      child.kill("SIGKILL");
    }, timeoutMs);
    child.stdout.on("data", (chunk: Buffer) => {
      stdout.write(chunk);
    });
    child.stderr.on("data", (chunk: Buffer) => {
      stderr.write(chunk);
    });
    child.on("error", (err) => {
      clearTimeout(timer);
      if (!settled) {
        settled = true;
        reject(new BurndropError("could not start " + command + ": " + redactor.redact(err.message)));
      }
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      if (!settled) {
        settled = true;
        result.exitCode = code ?? -1;
        resolve();
      }
    });
    const stdin = options.stdin;
    child.stdin.on("error", () => {
      // The child may exit before reading its input; that is not an error here.
    });
    if (stdin !== undefined && stdin.length > 0) {
      child.stdin.end(typeof stdin === "string" ? stdin : Buffer.from(stdin));
    } else {
      child.stdin.end();
    }
  });

  result.durationMs = Date.now() - start;
  if (result.timedOut) {
    result.exitCode = -1;
  }
  if (!options.discardOutput) {
    result.stdout = truncate(redactor.redact(stdout.toString()), maxOutput, result);
    result.stderr = truncate(redactor.redact(stderr.toString()), maxOutput, result);
  }
  return result;
}
