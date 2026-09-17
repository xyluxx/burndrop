/**
 * Test helpers: the shared vectors and an in-memory fake relay that answers
 * the API with the same states and error codes as the Go relay, so the agent
 * and human flows can be tested without Go. The integration test uses the
 * real relay.
 */
import { readFileSync } from "node:fs";

import { decodeBase64Url, encodeBase64Url } from "../src/index.js";

export interface SealedVector {
  name: string;
  recipient_public_key: string;
  recipient_secret_key: string;
  sealed: string;
  padded_plaintext: string;
  plaintext: string;
}

export interface AeadVector {
  name: string;
  key: string;
  nonce: string;
  aad: string;
  plaintext: string;
  blob: string;
}

export interface PadVector {
  block: number;
  unpadded: string;
  padded: string;
}

export interface FingerprintVector {
  public_key: string;
  fingerprint: string;
  commitment: string;
}

export interface EnvelopeVector {
  name: string;
  envelope: Record<string, unknown>;
  valid: boolean;
}

export interface AadVector {
  name: string;
  keeps_copy: boolean;
  aad: string;
}

export interface TokenVector {
  token: string;
  sha256: string;
  valid: boolean;
}

export interface Vectors {
  version: number;
  description: string;
  pad_block: number;
  sealed_box: SealedVector[];
  xchacha20poly1305: AeadVector[];
  padding: PadVector[];
  fingerprint: FingerprintVector[];
  envelope: EnvelopeVector[];
  reveal_aad: AadVector[];
  tokens: TokenVector[];
}

export const vectorsPath = new URL("../../../spec/vectors.json", import.meta.url);

export function loadVectors(): Vectors {
  return JSON.parse(readFileSync(vectorsPath, "utf8")) as Vectors;
}

export const b64 = decodeBase64Url;

export function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

export function text(b: Uint8Array): string {
  return new TextDecoder().decode(b);
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

export function randomToken(): string {
  const b = new Uint8Array(16);
  globalThis.crypto.getRandomValues(b);
  return encodeBase64Url(b);
}

type Kind = "drop" | "reveal";
type State = "created" | "uploaded" | "fetched" | "opened" | "revoked" | "expired";

interface Slot {
  id: string;
  kind: Kind;
  state: State;
  ciphertext: string;
  commitment: string;
  tokenA: string;
  tokenB: string;
  createdAt: number;
  expiresAt: number;
  uploadedAt: number;
  fetchedAt: number;
  revokedAt: number;
}

export interface RecordedRequest {
  method: string;
  url: string;
  headers: Record<string, string>;
  body: Record<string, unknown> | undefined;
}

function rfc3339(ms: number): string {
  return new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z");
}

function terminal(state: State): boolean {
  return state === "fetched" || state === "opened" || state === "revoked" || state === "expired";
}

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

/** An in-memory relay with the API of the Go relay. */
export class FakeRelay {
  readonly origin = "https://relay.example";
  readonly slots = new Map<string, Slot>();
  readonly requests: RecordedRequest[] = [];
  /** Agent keys accepted on agent endpoints; empty means auth is off. */
  readonly apiKeys = new Set<string>();
  /** Responses injected ahead of normal handling: [status, body]. */
  readonly failures: [number, unknown][] = [];
  now: () => number = () => Date.now();
  pollIntervalMs = 15;
  maxCiphertextBytes = 64 * 1024 + 256 + 48;

  readonly fetch: typeof globalThis.fetch = async (input, init) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    const method = init?.method ?? "GET";
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries((init?.headers ?? {}) as Record<string, string>)) {
      headers[k.toLowerCase()] = v;
    }
    let body: Record<string, unknown> | undefined;
    if (typeof init?.body === "string") {
      body = JSON.parse(init.body) as Record<string, unknown>;
    }
    this.requests.push({ method, url, headers, body });
    const injected = this.failures.shift();
    if (injected !== undefined) {
      return json(injected[0], injected[1]);
    }
    if (!url.startsWith(this.origin + "/")) {
      return json(404, { error: "not_found" });
    }
    const path = url.slice(this.origin.length);
    if (path === "/api/v1/info" && method === "GET") {
      return json(200, {
        version: "fake",
        api: "v1",
        default_ttl_seconds: 3600,
        max_ttl_seconds: 86400,
        max_ciphertext_bytes: this.maxCiphertextBytes,
        long_poll_max_seconds: 30,
        agent_auth: this.apiKeys.size > 0 ? "required" : "off",
        page_served: false,
        page_version: "",
        page_sha256: "",
      });
    }
    if (method !== "POST") {
      return json(405, { error: "method_not_allowed" });
    }
    if ((headers["x-client"] ?? "") === "") {
      return json(400, { error: "missing_client_header", header: "X-Client" });
    }
    if (!(headers["content-type"] ?? "").startsWith("application/json")) {
      return json(415, { error: "unsupported_media_type" });
    }
    if (body === undefined) {
      return json(400, { error: "bad_request", detail: "empty body" });
    }
    switch (path) {
      case "/api/v1/drops":
        return this.createDrop(headers, body);
      case "/api/v1/drops/upload":
        return this.upload(body);
      case "/api/v1/drops/status":
        return this.status("drop", body);
      case "/api/v1/drops/fetch":
        return this.fetchDrop(headers, body);
      case "/api/v1/drops/revoke":
        return this.revoke("drop", body);
      case "/api/v1/reveals":
        return this.createReveal(headers, body);
      case "/api/v1/reveals/open":
        return this.open(body);
      case "/api/v1/reveals/status":
        return this.status("reveal", body);
      case "/api/v1/reveals/revoke":
        return this.revoke("reveal", body);
      default:
        return json(404, { error: "not_found" });
    }
  };

  /** Forces a slot to expire now. */
  expire(id: string): void {
    const s = this.slots.get(id);
    if (s !== undefined) {
      s.expiresAt = this.now() - 1;
    }
  }

  /** Removes a slot entirely, as the sweeper does after expiry. */
  delete(id: string): void {
    this.slots.delete(id);
  }

  state(id: string): string {
    return this.slots.get(id)?.state ?? "";
  }

  private authorized(headers: Record<string, string | undefined>): boolean {
    if (this.apiKeys.size === 0) {
      return true;
    }
    const h = headers.authorization ?? "";
    return h.startsWith("Bearer ") && this.apiKeys.has(h.slice(7));
  }

  private live(id: unknown): Slot | undefined {
    if (typeof id !== "string") {
      return undefined;
    }
    const s = this.slots.get(id);
    if (s === undefined) {
      return undefined;
    }
    if (!terminal(s.state) && s.expiresAt <= this.now()) {
      s.state = "expired";
      s.ciphertext = "";
    }
    return s;
  }

  private stateError(s: Slot, op: string): Response {
    const at = s.state === "uploaded" ? s.uploadedAt : s.state === "fetched" || s.state === "opened" ? s.fetchedAt : s.state === "revoked" ? s.revokedAt : s.state === "expired" ? s.expiresAt : s.createdAt;
    const extra = { state: s.state, at: rfc3339(at) };
    if (op === "upload" && s.state === "uploaded") {
      return json(409, { error: "already_uploaded", ...extra });
    }
    if (op === "fetch" && s.state === "created") {
      return json(404, { error: "not_uploaded", ...extra });
    }
    return json(410, { error: "gone", ...extra });
  }

  private clampTtl(ttl: unknown): number {
    const n = typeof ttl === "number" ? ttl : 0;
    if (n <= 0) {
      return 3600;
    }
    return Math.min(86400, Math.max(60, n));
  }

  private createDrop(headers: Record<string, string>, body: Record<string, unknown>): Response {
    if (!this.authorized(headers)) {
      return json(401, { error: "unauthorized" });
    }
    const commitment = body.commitment;
    if (typeof commitment !== "string" || commitment.length !== 43) {
      return json(400, { error: "bad_request", detail: "commitment must be the base64url SHA-256 of the recipient public key" });
    }
    const now = this.now();
    const slot: Slot = {
      id: randomToken(),
      kind: "drop",
      state: "created",
      ciphertext: "",
      commitment,
      tokenA: randomToken(),
      tokenB: randomToken(),
      createdAt: now,
      expiresAt: now + this.clampTtl(body.ttl_seconds) * 1000,
      uploadedAt: 0,
      fetchedAt: 0,
      revokedAt: 0,
    };
    this.slots.set(slot.id, slot);
    return json(201, { drop_id: slot.id, upload_token: slot.tokenA, fetch_token: slot.tokenB, expires_at: rfc3339(slot.expiresAt) });
  }

  private upload(body: Record<string, unknown>): Response {
    const s = this.live(body.drop_id);
    if (s?.kind !== "drop") {
      return json(404, { error: "not_found" });
    }
    if (s.state !== "created") {
      return this.stateError(s, "upload");
    }
    if (body.upload_token !== s.tokenA) {
      return json(403, { error: "bad_token" });
    }
    if (body.commitment !== s.commitment) {
      return json(422, { error: "commitment_mismatch", detail: "the public key in this link does not match the key the agent registered" });
    }
    const ct = body.ciphertext;
    if (typeof ct !== "string" || ct === "") {
      return json(400, { error: "bad_request", detail: "ciphertext is required" });
    }
    let raw: Uint8Array;
    try {
      raw = decodeBase64Url(ct);
    } catch {
      return json(400, { error: "bad_request", detail: "ciphertext must be base64url without padding" });
    }
    if (raw.length > this.maxCiphertextBytes) {
      return json(413, { error: "too_large", max_bytes: this.maxCiphertextBytes });
    }
    if (raw.length < 48 + 256) {
      return json(400, { error: "bad_request", detail: "ciphertext is too short to be valid" });
    }
    s.ciphertext = ct;
    s.state = "uploaded";
    s.uploadedAt = this.now();
    s.tokenA = "";
    return json(200, { state: "uploaded" });
  }

  private async status(kind: Kind, body: Record<string, unknown>): Promise<Response> {
    const s = this.live(body.drop_id);
    if (s?.kind !== kind) {
      return json(404, { error: "not_found" });
    }
    const wait = typeof body.wait_seconds === "number" ? body.wait_seconds : 0;
    if (wait < 0 || wait > 30) {
      return json(400, { error: "bad_request", detail: "wait_seconds must be between 0 and 30" });
    }
    const waitWhile = typeof body.wait_while === "string" ? body.wait_while : "";
    if (wait > 0 && !terminal(s.state) && (waitWhile === "" || waitWhile === s.state)) {
      const initial = s.state;
      const deadline = this.now() + wait * 1000;
      while (this.now() < deadline) {
        await new Promise((r) => setTimeout(r, this.pollIntervalMs));
        this.live(s.id);
        if (s.state !== initial) {
          break;
        }
      }
    }
    const out: Record<string, unknown> = { state: s.state, kind: s.kind, created_at: rfc3339(s.createdAt), expires_at: rfc3339(s.expiresAt) };
    if (s.uploadedAt !== 0) {
      out.uploaded_at = rfc3339(s.uploadedAt);
    }
    if (s.fetchedAt !== 0) {
      out[s.kind === "reveal" ? "opened_at" : "fetched_at"] = rfc3339(s.fetchedAt);
    }
    if (s.revokedAt !== 0) {
      out.revoked_at = rfc3339(s.revokedAt);
    }
    return json(200, out);
  }

  private fetchDrop(headers: Record<string, string>, body: Record<string, unknown>): Response {
    if (!this.authorized(headers)) {
      return json(401, { error: "unauthorized" });
    }
    const s = this.live(body.drop_id);
    if (s?.kind !== "drop") {
      return json(404, { error: "not_found" });
    }
    if (s.state !== "uploaded") {
      return this.stateError(s, "fetch");
    }
    if (body.fetch_token !== s.tokenB) {
      return json(403, { error: "bad_token" });
    }
    const ct = s.ciphertext;
    s.ciphertext = "";
    s.tokenB = "";
    s.state = "fetched";
    s.fetchedAt = this.now();
    return json(200, { ciphertext: ct, uploaded_at: rfc3339(s.uploadedAt) });
  }

  private createReveal(headers: Record<string, string>, body: Record<string, unknown>): Response {
    if (!this.authorized(headers)) {
      return json(401, { error: "unauthorized" });
    }
    const ct = body.ciphertext;
    if (typeof ct !== "string" || ct === "") {
      return json(400, { error: "bad_request", detail: "ciphertext is required" });
    }
    let raw: Uint8Array;
    try {
      raw = decodeBase64Url(ct);
    } catch {
      return json(400, { error: "bad_request", detail: "ciphertext must be base64url without padding" });
    }
    if (raw.length > this.maxCiphertextBytes) {
      return json(413, { error: "too_large", max_bytes: this.maxCiphertextBytes });
    }
    if (raw.length < 40 + 256) {
      return json(400, { error: "bad_request", detail: "ciphertext is too short to be valid" });
    }
    const now = this.now();
    const slot: Slot = {
      id: randomToken(),
      kind: "reveal",
      state: "created",
      ciphertext: ct,
      commitment: "",
      tokenA: randomToken(),
      tokenB: randomToken(),
      createdAt: now,
      expiresAt: now + this.clampTtl(body.ttl_seconds) * 1000,
      uploadedAt: 0,
      fetchedAt: 0,
      revokedAt: 0,
    };
    this.slots.set(slot.id, slot);
    return json(201, { drop_id: slot.id, reveal_token: slot.tokenA, revoke_token: slot.tokenB, expires_at: rfc3339(slot.expiresAt) });
  }

  private open(body: Record<string, unknown>): Response {
    const s = this.live(body.drop_id);
    if (s?.kind !== "reveal") {
      return json(404, { error: "not_found" });
    }
    if (s.state !== "created") {
      return this.stateError(s, "open");
    }
    if (body.reveal_token !== s.tokenA) {
      return json(403, { error: "bad_token" });
    }
    const ct = s.ciphertext;
    s.ciphertext = "";
    s.tokenA = "";
    s.tokenB = "";
    s.state = "opened";
    s.fetchedAt = this.now();
    return json(200, { ciphertext: ct, created_at: rfc3339(s.createdAt) });
  }

  private revoke(kind: Kind, body: Record<string, unknown>): Response {
    const s = this.live(body.drop_id);
    if (s?.kind !== kind) {
      return json(404, { error: "not_found" });
    }
    if (terminal(s.state)) {
      return this.stateError(s, "revoke");
    }
    const token = body.token;
    if (token !== s.tokenA && token !== s.tokenB) {
      return json(403, { error: "bad_token" });
    }
    s.ciphertext = "";
    s.tokenA = "";
    s.tokenB = "";
    s.state = "revoked";
    s.revokedAt = this.now();
    return json(200, { state: "revoked" });
  }
}
