/**
 * The agent side of both flows: request a secret from a human, receive it,
 * and send a secret to a human. Mirrors internal/agent/agent.go, with one
 * difference that follows from being a library rather than an MCP server:
 * there is no storage manager, so fetchSecret returns the value to the
 * calling program. The program is responsible for keeping that value out
 * of any language model's context; use runWithSecret to hand it to a
 * subprocess and get redacted output back.
 *
 * Uses Node's child_process through runWithSecret; everything else is
 * portable.
 */
import {
  commitment,
  encryptEnvelope,
  fingerprint,
  generateKeyPair,
  newSalt,
  newSymmetricKey,
  openEnvelope,
  parseRfc3339,
  revealAad,
  revealKeyWithPassword,
  secretBytes,
  secretField,
  validateText,
  zero,
  type Envelope,
  type SecretFormat,
} from "./crypto.js";
import { BurndropError, RelayError, ValidationError, isRelayCode } from "./errors.js";
import { buildDropLink, buildRevealLink, isValidToken, normalizeOrigin, type DropLink, type RevealLink } from "./link.js";
import { Redactor } from "./redact.js";
import { DeadlineExceededError, RelayClient, RelayCode, SlotState, type RelayClientOptions, type Status } from "./relay.js";
import { runWithSecret, type RunOptions, type RunResult } from "./run.js";

/** Default request lifetime in seconds (one hour). */
export const DEFAULT_TTL_SECONDS = 3600;
/** Default retention policy shown to the human. */
export const DEFAULT_RETENTION = "until-revoked";
/** Default description of where the value goes, shown to the human. */
export const DEFAULT_STORAGE = "the agent's process memory only";
/** Default and maximum wait of one fetchSecret call, in seconds. */
export const DEFAULT_FETCH_WAIT_SECONDS = 30;
export const MAX_FETCH_WAIT_SECONDS = 300;

const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/;

export interface AgentOptions extends RelayClientOptions {
  /** Relay origin, for example https://relay.example. Ignored when client is given. */
  relay?: string;
  /** Agent API key for the relay, when the relay requires one. */
  apiKey?: string;
  /** A prepared relay client to use instead of relay and apiKey. */
  client?: RelayClient;
  /** Origin of the drop page in links; default the relay origin. */
  pageOrigin?: string;
  /** Default link lifetime in seconds; the relay clamps it to its maximum. */
  defaultTtlSeconds?: number;
  /** Default retention policy: "session", "until-revoked", or "until:<RFC 3339>". */
  defaultRetention?: string;
  /** Default description of where the value will be kept, shown to the human. */
  defaultStorage?: string;
  /** Clock, for tests. */
  now?: () => Date;
}

export interface RequestOptions {
  /** What the human is told about how long the value is kept. */
  retention?: string;
  /** What the human is told about where the value is kept. */
  storage?: string;
  /** Link lifetime in seconds. */
  ttlSeconds?: number;
  signal?: AbortSignal;
}

export interface RequestResult {
  requestId: string;
  name: string;
  purpose: string;
  link: string;
  fingerprint: string;
  expiresAt: Date;
  storage: string;
  retention: string;
  /** The disclosure text to relay to the human, with the link and fingerprint. */
  message: string;
}

/** A pending request without its keys. */
export interface PendingRequest {
  requestId: string;
  name: string;
  purpose: string;
  fingerprint: string;
  retention: string;
  storage: string;
  createdAt: Date;
  expiresAt: Date;
}

export type FetchStatus = "waiting" | "received" | "expired" | "revoked" | "rejected" | "gone";

export interface FetchResult {
  status: FetchStatus;
  requestId: string;
  name: string;
  purpose: string;
  storage: string;
  retention: string;
  fingerprint: string;
  expiresAt: Date;
  /** A description of the outcome without the value. */
  message: string;
  /** The secret, only when status is "received". Never put it in a model's context. */
  value?: Uint8Array;
  format?: SecretFormat;
  sizeBytes?: number;
}

export interface SendOptions {
  /** Link lifetime in seconds. */
  ttlSeconds?: number;
  /** Whether the human is told that the agent keeps its own copy; default true. */
  keepsCopy?: boolean;
  /** Protect the link with this reveal password: the page asks for it before showing the value. */
  password?: string | Uint8Array;
  signal?: AbortSignal;
}

export interface SendResult {
  requestId: string;
  name: string;
  link: string;
  expiresAt: Date;
  keepsCopy: boolean;
  /** Whether the page asks for the reveal password before showing the value. */
  passwordProtected: boolean;
  /** Token that revokes the reveal before it is opened; pass the result to revoke. */
  revokeToken: string;
  /** The text to relay to the human, with the link and the disclosures. */
  message: string;
}

interface PendingRecord {
  requestId: string;
  fetchToken: string;
  uploadToken: string;
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  name: string;
  purpose: string;
  retention: string;
  storage: string;
  fingerprint: string;
  createdAt: Date;
  expiresAt: Date;
}

function pad2(n: number): string {
  return String(n).padStart(2, "0");
}

/** Formats a date as "2006-01-02 15:04 UTC", as the Go messages do. */
export function formatUtcMinute(d: Date): string {
  return (
    String(d.getUTCFullYear()) + "-" + pad2(d.getUTCMonth() + 1) + "-" + pad2(d.getUTCDate()) + " " + pad2(d.getUTCHours()) + ":" + pad2(d.getUTCMinutes()) + " UTC"
  );
}

/** Formats a date as RFC 3339 without fractional seconds. */
export function formatRfc3339(d: Date): string {
  return d.toISOString().replace(/\.\d{3}Z$/, "Z");
}

function describeRetention(retention: string): string {
  if (retention === "session") {
    return "kept only until the agent process exits";
  }
  if (retention === "until-revoked") {
    return "kept until deleted";
  }
  if (retention.startsWith("until:")) {
    return "kept until " + retention.slice("until:".length);
  }
  return retention;
}

/** Validates a secret reference name with the storage rules of the Go agent. */
export function validateSecretName(name: string): void {
  if (!NAME_RE.test(name)) {
    throw new ValidationError('invalid secret name: "' + name + '" must be 1 to 100 characters of letters, digits, dot, underscore, or dash, starting with a letter or digit');
  }
  if (name.includes("..")) {
    throw new ValidationError('invalid secret name: "' + name + '" must not contain a double dot');
  }
}

/** Validates a retention policy and checks that an until: date is in the future. */
export function validateRetentionPolicy(policy: string, now: Date): void {
  if (policy === "session" || policy === "until-revoked") {
    return;
  }
  if (policy.startsWith("until:")) {
    const t = parseRfc3339(policy.slice("until:".length));
    if (t === undefined) {
      throw new ValidationError("invalid retention policy: date must be RFC 3339, for example until:2027-01-31T00:00:00Z");
    }
    if (t.getTime() <= now.getTime()) {
      throw new ValidationError("invalid retention policy: date is in the past");
    }
    return;
  }
  throw new ValidationError('invalid retention policy: "' + policy + '" (use session, until-revoked, or until:<RFC 3339 date>)');
}

function ttlOf(value: number | undefined, fallback: number): number {
  if (value === undefined) {
    return fallback;
  }
  if (!Number.isFinite(value) || value <= 0) {
    throw new ValidationError("ttlSeconds must be a positive number of seconds");
  }
  return Math.floor(value);
}

function requestMessage(out: RequestResult): string {
  return (
    "Please share " +
    out.name +
    " using this one-time secure link: " +
    out.link +
    "\n\nWhat it is for: " +
    out.purpose +
    "\nWhere it will be stored: " +
    out.storage +
    " (" +
    describeRetention(out.retention) +
    ").\nThe link works once and expires at " +
    formatUtcMinute(out.expiresAt) +
    ". Before submitting, check that the page shows fingerprint " +
    out.fingerprint +
    ". The secret is encrypted in your browser and only this agent can decrypt it; the relay never sees it. I will never see the value itself."
  );
}

function sendMessage(out: SendResult): string {
  const copyNote = out.keepsCopy ? "I keep my copy of it." : "I have deleted my copy of it.";
  const passwordNote = out.passwordProtected ? " The page asks for your reveal password before it shows the value." : "";
  return (
    "Here is " +
    out.name +
    ": " +
    out.link +
    "\n\nThe link reveals the value once, after you press the button on the page, and then it is gone." +
    passwordNote +
    " It expires at " +
    formatUtcMinute(out.expiresAt) +
    ". " +
    copyNote +
    " Copy the value somewhere safe before closing the page."
  );
}

/**
 * Checks the decrypted envelope against the request, exactly as the Go
 * agent does. The page fills the envelope from the link it was given, so
 * any difference means the link the human used was not the one this agent
 * made. Returns the reason for rejection, or an empty string.
 */
export function checkEnvelope(env: Envelope, rec: { name: string; fingerprint: string; retention: string; purpose: string; storage: string }): string {
  if (env.type !== "drop") {
    return "the envelope is not a drop";
  }
  if (env.name !== rec.name) {
    return "the secret name in the submission does not match the request";
  }
  if ((env.fingerprint ?? "") !== "" && env.fingerprint !== rec.fingerprint) {
    return "the fingerprint shown to the human does not match this request";
  }
  if ((env.retention ?? "") !== rec.retention) {
    return "the retention shown to the human does not match the request";
  }
  if ((env.purpose ?? "") !== rec.purpose) {
    return "the purpose shown to the human does not match the request";
  }
  if ((env.storage ?? "") !== rec.storage) {
    return "the storage description shown to the human does not match the request";
  }
  return "";
}

/** Implements the agent flows over a relay client. */
export class Agent {
  readonly client: RelayClient;
  readonly pageOrigin: string;
  /** Learns every value that passes through the agent; use redact on any text that leaves the program. */
  readonly redactor = new Redactor();
  private readonly defaultTtlSeconds: number;
  private readonly defaultRetention: string;
  private readonly defaultStorage: string;
  private readonly now: () => Date;
  private readonly pendingRecords = new Map<string, PendingRecord>();

  constructor(options: AgentOptions) {
    if (options.client !== undefined) {
      this.client = options.client;
    } else {
      if (options.relay === undefined) {
        throw new ValidationError("relay (or client) is required");
      }
      const clientOptions: RelayClientOptions = {};
      if (options.clientName !== undefined) {
        clientOptions.clientName = options.clientName;
      }
      if (options.fetch !== undefined) {
        clientOptions.fetch = options.fetch;
      }
      if (options.timeoutMs !== undefined) {
        clientOptions.timeoutMs = options.timeoutMs;
      }
      this.client = new RelayClient(options.relay, options.apiKey ?? "", clientOptions);
    }
    this.pageOrigin = options.pageOrigin === undefined ? this.client.origin : normalizeOrigin(options.pageOrigin);
    this.defaultTtlSeconds = ttlOf(options.defaultTtlSeconds, DEFAULT_TTL_SECONDS);
    this.defaultRetention = options.defaultRetention ?? DEFAULT_RETENTION;
    this.defaultStorage = options.defaultStorage ?? DEFAULT_STORAGE;
    this.now = options.now ?? (() => new Date());
    validateRetentionPolicy(this.defaultRetention, this.now());
    validateText("storage", this.defaultStorage);
  }

  /**
   * Creates a drop slot and returns a one-time link for the human together
   * with the fingerprint and a message that discloses everything the human
   * must know. The private key stays in memory until fetchSecret, revoke,
   * or the request's expiry.
   */
  async requestSecret(name: string, purpose: string, options: RequestOptions = {}): Promise<RequestResult> {
    validateSecretName(name);
    validateText("purpose", purpose);
    if (purpose.trim() === "") {
      throw new ValidationError("purpose is required so the human knows what the secret is for");
    }
    const retention = options.retention ?? this.defaultRetention;
    const now = this.now();
    validateRetentionPolicy(retention, now);
    const storage = options.storage ?? this.defaultStorage;
    validateText("storage", storage);
    const ttl = ttlOf(options.ttlSeconds, this.defaultTtlSeconds);

    const keys = await generateKeyPair();
    const created = await this.client.createDrop(await commitment(keys.publicKey), ttl, options.signal);
    const fp = await fingerprint(keys.publicKey);
    const drop: DropLink = {
      id: created.id,
      uploadToken: created.uploadToken,
      recipientKey: keys.publicKey,
      name,
      purpose,
      storage,
      retention,
    };
    if (this.client.origin !== this.pageOrigin) {
      drop.relay = this.client.origin;
    }
    let link: string;
    try {
      link = buildDropLink(drop, this.pageOrigin);
    } catch (err) {
      zero(keys.privateKey);
      await this.client.revokeDrop(created.id, created.uploadToken).catch(() => undefined);
      throw err;
    }
    this.pendingRecords.set(created.id, {
      requestId: created.id,
      fetchToken: created.fetchToken,
      uploadToken: created.uploadToken,
      privateKey: keys.privateKey,
      publicKey: keys.publicKey,
      name,
      purpose,
      retention,
      storage,
      fingerprint: fp,
      createdAt: now,
      expiresAt: created.expiresAt,
    });
    const out: RequestResult = {
      requestId: created.id,
      name,
      purpose,
      link,
      fingerprint: fp,
      expiresAt: created.expiresAt,
      storage,
      retention,
      message: "",
    };
    out.message = requestMessage(out);
    return out;
  }

  /** Lists outstanding requests, oldest first, without their keys. */
  pending(): PendingRequest[] {
    return [...this.pendingRecords.values()]
      .sort((a, b) => a.createdAt.getTime() - b.createdAt.getTime())
      .map((r) => ({
        requestId: r.requestId,
        name: r.name,
        purpose: r.purpose,
        fingerprint: r.fingerprint,
        retention: r.retention,
        storage: r.storage,
        createdAt: r.createdAt,
        expiresAt: r.expiresAt,
      }));
  }

  private loadPending(request: string | { requestId: string }): PendingRecord {
    const id = typeof request === "string" ? request : request.requestId;
    if (!isValidToken(id)) {
      throw new ValidationError("no pending request with that id: malformed request id");
    }
    const rec = this.pendingRecords.get(id);
    if (rec === undefined) {
      throw new ValidationError("no pending request with that id");
    }
    return rec;
  }

  private forget(rec: PendingRecord): void {
    zero(rec.privateKey);
    this.pendingRecords.delete(rec.requestId);
  }

  /**
   * Waits up to waitSeconds (default 30, maximum 300) for the human's
   * upload, then downloads, decrypts, and verifies the submission. On
   * "received" the value is in the result and the request is forgotten;
   * the private key is zeroed in every outcome that ends the request.
   */
  async fetchSecret(request: string | { requestId: string }, waitSeconds = DEFAULT_FETCH_WAIT_SECONDS, signal?: AbortSignal): Promise<FetchResult> {
    const rec = this.loadPending(request);
    let wait = waitSeconds > 0 ? waitSeconds : DEFAULT_FETCH_WAIT_SECONDS;
    if (wait > MAX_FETCH_WAIT_SECONDS) {
      wait = MAX_FETCH_WAIT_SECONDS;
    }
    const out: FetchResult = {
      status: "waiting",
      requestId: rec.requestId,
      name: rec.name,
      purpose: rec.purpose,
      storage: rec.storage,
      retention: rec.retention,
      fingerprint: rec.fingerprint,
      expiresAt: rec.expiresAt,
      message: "",
    };
    let st: Status | undefined;
    try {
      st = await this.client.waitForUpload(rec.requestId, this.now().getTime() + wait * 1000, signal);
    } catch (err) {
      if (err instanceof DeadlineExceededError) {
        st = err.lastStatus;
      } else if (isRelayCode(err, RelayCode.NotFound)) {
        this.forget(rec);
        out.status = "expired";
        out.message = "The request is no longer known to the relay; it expired. Ask again with requestSecret if you still need it.";
        return out;
      } else {
        throw err;
      }
    }
    switch (st?.state ?? "") {
      case SlotState.Created:
      case "":
        out.status = "waiting";
        out.message =
          "The human has not submitted " + rec.name + " yet. The link is valid until " + formatRfc3339(rec.expiresAt) + ". Call fetchSecret again to keep waiting.";
        return out;
      case SlotState.Revoked:
        this.forget(rec);
        out.status = "revoked";
        out.message = "The request was revoked before the human submitted anything.";
        return out;
      case SlotState.Expired:
        this.forget(rec);
        out.status = "expired";
        out.message = "The request expired before the human submitted anything. Ask again with requestSecret if you still need it.";
        return out;
      case SlotState.Fetched:
        this.forget(rec);
        out.status = "gone";
        out.message = "The submission was already fetched. If it was not received by this agent, treat the secret as exposed and ask the human to rotate it.";
        return out;
      case SlotState.Uploaded:
        return this.fetchUploaded(rec, out, signal);
      default:
        throw new BurndropError('unexpected relay state "' + (st?.state ?? "") + '"');
    }
  }

  private async fetchUploaded(rec: PendingRecord, out: FetchResult, signal?: AbortSignal): Promise<FetchResult> {
    let ciphertext: Uint8Array;
    try {
      ({ ciphertext } = await this.client.fetch(rec.requestId, rec.fetchToken, signal));
    } catch (err) {
      if (isRelayCode(err, RelayCode.Gone)) {
        this.forget(rec);
        out.status = "gone";
        out.message = "The submission was fetched by someone else before this agent could. Treat the secret as exposed and ask the human to rotate it.";
        return out;
      }
      throw err;
    }
    let env: Envelope;
    try {
      env = await openEnvelope(rec.publicKey, rec.privateKey, ciphertext);
    } catch {
      this.forget(rec);
      out.status = "rejected";
      out.message =
        "The submission could not be decrypted with this request's key. The relay or the page may have been tampered with. Ask the human to try again with a fresh link and to compare fingerprints.";
      return out;
    }
    const reason = checkEnvelope(env, rec);
    if (reason !== "") {
      this.forget(rec);
      out.status = "rejected";
      out.message = "The submission was rejected: " + reason + ". Ask the human to try again with a fresh link.";
      return out;
    }
    const value = secretBytes(env);
    this.redactor.add(rec.name, value);
    this.forget(rec);
    out.status = "received";
    out.value = value;
    out.format = env.format;
    out.sizeBytes = value.length;
    out.message =
      "Received " +
      rec.name +
      " (" +
      String(value.length) +
      " bytes). The value is returned to the calling program only; never place it in a language model's context. Use runWithSecret to hand it to a subprocess.";
    return out;
  }

  /**
   * Encrypts a value for a human and returns a one-time link. keepsCopy
   * (default true) is a statement to the human about what the calling
   * program does with its own copy; pass false only when that is true.
   */
  async sendSecret(name: string, value: Uint8Array | string, options: SendOptions = {}): Promise<SendResult> {
    validateSecretName(name);
    const ttl = ttlOf(options.ttlSeconds, this.defaultTtlSeconds);
    const bytes = typeof value === "string" ? new TextEncoder().encode(value) : value;
    const keepsCopy = options.keepsCopy ?? true;
    this.redactor.add(name, bytes);
    const key = await newSymmetricKey();
    let encKey = key;
    let salt: Uint8Array | undefined;
    try {
      if (options.password !== undefined) {
        salt = await newSalt();
        encKey = await revealKeyWithPassword(key, options.password, salt);
      }
      const env: Envelope = { v: 1, type: "reveal", name, ...secretField(bytes) };
      const ciphertext = await encryptEnvelope(encKey, env, revealAad(name, keepsCopy));
      const created = await this.client.createReveal(ciphertext, ttl, options.signal);
      const reveal: RevealLink = { id: created.id, revealToken: created.revealToken, key, name, keepsCopy };
      if (salt !== undefined) {
        reveal.salt = salt;
      }
      if (this.client.origin !== this.pageOrigin) {
        reveal.relay = this.client.origin;
      }
      let link: string;
      try {
        link = buildRevealLink(reveal, this.pageOrigin);
      } catch (err) {
        await this.client.revokeReveal(created.id, created.revokeToken).catch(() => undefined);
        throw err;
      }
      const out: SendResult = {
        requestId: created.id,
        name,
        link,
        expiresAt: created.expiresAt,
        keepsCopy,
        passwordProtected: salt !== undefined,
        revokeToken: created.revokeToken,
        message: "",
      };
      out.message = sendMessage(out);
      return out;
    } finally {
      zero(key);
      if (encKey !== key) {
        zero(encKey);
      }
    }
  }

  /**
   * Cancels a pending request on the relay and forgets it locally, or, when
   * given a sendSecret result, deletes the unopened reveal. Returns the
   * resulting relay state ("revoked", or the terminal state the slot was
   * already in).
   */
  async revoke(request: string | { requestId: string; revokeToken?: string }, signal?: AbortSignal): Promise<string> {
    if (typeof request !== "string" && request.revokeToken !== undefined) {
      try {
        await this.client.revokeReveal(request.requestId, request.revokeToken, signal);
        return SlotState.Revoked;
      } catch (err) {
        return stateOfError(err);
      }
    }
    const rec = this.loadPending(request);
    let state: string = SlotState.Revoked;
    try {
      await this.client.revokeDrop(rec.requestId, rec.uploadToken, signal);
    } catch (err) {
      state = stateOfError(err);
    }
    this.forget(rec);
    return state;
  }

  /**
   * Runs a command with secrets injected as environment variables and
   * returns redacted output. Values the agent has seen are redacted too.
   */
  runWithSecret(command: string, args: readonly string[], secrets: Record<string, Uint8Array | string>, options: RunOptions = {}): Promise<RunResult> {
    return runWithSecret(command, args, secrets, { ...options, redactor: options.redactor ?? this.redactor });
  }

  /** Replaces every value the agent has seen, in any common encoding, with [redacted:<name>]. */
  redact(text: string): string {
    return this.redactor.redact(text);
  }
}

function stateOfError(err: unknown): string {
  if (err instanceof RelayError && err.state !== "") {
    return err.state;
  }
  if (isRelayCode(err, RelayCode.NotFound)) {
    return SlotState.Expired;
  }
  throw err;
}
