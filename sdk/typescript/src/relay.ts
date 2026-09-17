/**
 * Talks to a burndrop relay over its JSON API (design section 6.1). Every
 * call is a POST with the identifiers in the body, so nothing sensitive
 * reaches a URL or an access log. The X-Client header is sent on every
 * request; the relay rejects requests without it so that plain form posts
 * and scanners cannot reach the API.
 *
 * Uses the global fetch; no Node-only imports.
 */
import { decodeBase64Url, encodeBase64Url } from "./base64url.js";
import { parseRfc3339 } from "./envelope.js";
import { BurndropError, RelayError, RelayUnavailableError } from "./errors.js";
import { normalizeOrigin } from "./link.js";
import { DEFAULT_CLIENT_NAME } from "./version.js";

/** Header that must be present on every API request. */
export const CLIENT_HEADER = "X-Client";

/** Longest single long poll the relay allows, in seconds. */
export const MAX_WAIT_SECONDS = 30;

/** Per-request timeout: the longest long poll plus a margin. */
export const REQUEST_TIMEOUT_MS = (MAX_WAIT_SECONDS + 15) * 1000;

const MAX_RESPONSE_BYTES = 1 << 20;

/** Error codes returned by the relay. */
export const RelayCode = {
  NotFound: "not_found",
  NotUploaded: "not_uploaded",
  Gone: "gone",
  BadToken: "bad_token",
  Unauthorized: "unauthorized",
  RateLimited: "rate_limited",
  CommitmentMismatch: "commitment_mismatch",
  AlreadyUploaded: "already_uploaded",
} as const;

/** Slot states as reported by the relay. */
export const SlotState = {
  Created: "created",
  Uploaded: "uploaded",
  Fetched: "fetched",
  Opened: "opened",
  Revoked: "revoked",
  Expired: "expired",
} as const;

/** Reports whether a state can no longer change. */
export function isTerminalState(state: string): boolean {
  return state === SlotState.Fetched || state === SlotState.Opened || state === SlotState.Revoked || state === SlotState.Expired;
}

/** Result of createDrop. */
export interface DropCreated {
  id: string;
  uploadToken: string;
  fetchToken: string;
  expiresAt: Date;
}

/** Result of createReveal. */
export interface RevealCreated {
  id: string;
  revealToken: string;
  revokeToken: string;
  expiresAt: Date;
}

/** A drop or reveal status. Timestamps are absent when the relay omits them. */
export interface Status {
  state: string;
  kind: string;
  createdAt?: Date;
  expiresAt?: Date;
  uploadedAt?: Date;
  fetchedAt?: Date;
  openedAt?: Date;
  revokedAt?: Date;
}

/** The relay's self description. */
export interface RelayInfo {
  version: string;
  api: string;
  defaultTtlSeconds: number;
  maxTtlSeconds: number;
  maxCiphertextBytes: number;
  longPollMaxSeconds: number;
  agentAuth: string;
  pageServed: boolean;
  pageVersion: string;
  pageSha256: string;
}

/** A long poll gave up because the caller's deadline passed. */
export class DeadlineExceededError extends BurndropError {
  /** The last status seen before the deadline, if any poll succeeded. */
  readonly lastStatus: Status | undefined;

  constructor(lastStatus?: Status) {
    super("deadline exceeded");
    this.name = "DeadlineExceededError";
    this.lastStatus = lastStatus;
  }
}

export interface RelayClientOptions {
  /** Value of the X-Client header. Default "burndrop-ts/<version>". */
  clientName?: string;
  /** fetch implementation; default globalThis.fetch. */
  fetch?: typeof globalThis.fetch;
  /** Per-request timeout in milliseconds; default REQUEST_TIMEOUT_MS. */
  timeoutMs?: number;
}

type Json = Record<string, unknown>;

function str(obj: Json, key: string): string {
  const v = obj[key];
  return typeof v === "string" ? v : "";
}

function num(obj: Json, key: string): number {
  const v = obj[key];
  return typeof v === "number" ? v : 0;
}

function time(obj: Json, key: string): Date | undefined {
  const s = str(obj, key);
  return s === "" ? undefined : parseRfc3339(s);
}

function requiredTime(obj: Json, key: string, status: number): Date {
  const t = time(obj, key);
  if (t === undefined) {
    throw new RelayUnavailableError("malformed response (HTTP " + String(status) + "): missing " + key);
  }
  return t;
}

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(abortReason(signal));
      return;
    }
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    function onAbort(): void {
      clearTimeout(timer);
      reject(abortReason(signal));
    }
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

function abortReason(signal: AbortSignal | undefined): Error {
  const reason: unknown = signal?.reason;
  if (reason instanceof Error) {
    return reason;
  }
  return new BurndropError("aborted");
}

function toDeadlineMs(deadline: Date | number): number {
  return deadline instanceof Date ? deadline.getTime() : deadline;
}

/** A relay client. Safe to share between concurrent calls. */
export class RelayClient {
  /** The normalized relay origin, for example https://relay.example. */
  readonly origin: string;
  /** Sent as a bearer token on agent endpoints when set. */
  readonly apiKey: string;
  /** Identifies the software in the X-Client header. */
  readonly clientName: string;
  private readonly fetchImpl: typeof globalThis.fetch;
  private readonly timeoutMs: number;

  constructor(origin: string, apiKey = "", options: RelayClientOptions = {}) {
    this.origin = normalizeOrigin(origin);
    this.apiKey = apiKey;
    this.clientName = options.clientName ?? DEFAULT_CLIENT_NAME;
    this.fetchImpl = options.fetch ?? globalThis.fetch;
    this.timeoutMs = options.timeoutMs ?? REQUEST_TIMEOUT_MS;
  }

  /**
   * Reserves a slot for a human to upload into. commitment is the base64url
   * SHA-256 of the recipient public key; a ttl of zero uses the relay
   * default.
   */
  async createDrop(commitment: string, ttlSeconds = 0, signal?: AbortSignal): Promise<DropCreated> {
    const { status, body } = await this.post("/api/v1/drops", { ttl_seconds: Math.floor(ttlSeconds), commitment }, true, signal);
    return {
      id: str(body, "drop_id"),
      uploadToken: str(body, "upload_token"),
      fetchToken: str(body, "fetch_token"),
      expiresAt: requiredTime(body, "expires_at", status),
    };
  }

  /**
   * Stores a sealed envelope in a drop slot. It is what the page does; the
   * human helpers use it for the human side of a request.
   */
  async upload(dropId: string, uploadToken: string, commitment: string, ciphertext: Uint8Array, signal?: AbortSignal): Promise<void> {
    await this.post(
      "/api/v1/drops/upload",
      { drop_id: dropId, upload_token: uploadToken, commitment, ciphertext: encodeBase64Url(ciphertext) },
      false,
      signal,
    );
  }

  /**
   * Reports a drop's state. With waitSeconds above zero the relay holds the
   * request for up to that long (at most MAX_WAIT_SECONDS) while the state
   * equals waitWhile, or while it is not terminal when waitWhile is empty.
   */
  dropStatus(dropId: string, waitSeconds = 0, waitWhile = "", signal?: AbortSignal): Promise<Status> {
    return this.status("/api/v1/drops/status", dropId, waitSeconds, waitWhile, signal);
  }

  /** dropStatus for reveals. */
  revealStatus(dropId: string, waitSeconds = 0, waitWhile = "", signal?: AbortSignal): Promise<Status> {
    return this.status("/api/v1/reveals/status", dropId, waitSeconds, waitWhile, signal);
  }

  private async status(path: string, dropId: string, waitSeconds: number, waitWhile: string, signal?: AbortSignal): Promise<Status> {
    const wait = Math.max(0, Math.min(MAX_WAIT_SECONDS, Math.floor(waitSeconds)));
    const { body } = await this.post(path, { drop_id: dropId, wait_seconds: wait, wait_while: waitWhile }, false, signal);
    return {
      state: str(body, "state"),
      kind: str(body, "kind"),
      createdAt: time(body, "created_at"),
      expiresAt: time(body, "expires_at"),
      uploadedAt: time(body, "uploaded_at"),
      fetchedAt: time(body, "fetched_at"),
      openedAt: time(body, "opened_at"),
      revokedAt: time(body, "revoked_at"),
    };
  }

  /**
   * Long polls until the drop leaves the created state, then resolves with
   * that status. Throws DeadlineExceededError when the deadline passes
   * first, carrying the last status seen.
   */
  waitForUpload(dropId: string, deadline: Date | number, signal?: AbortSignal): Promise<Status> {
    return this.waitWhile((wait) => this.dropStatus(dropId, wait, SlotState.Created, signal), SlotState.Created, toDeadlineMs(deadline), signal);
  }

  /**
   * Long polls until the reveal leaves the created state, which for a reveal
   * means it was opened, revoked, or expired.
   */
  waitForOpen(dropId: string, deadline: Date | number, signal?: AbortSignal): Promise<Status> {
    return this.waitWhile((wait) => this.revealStatus(dropId, wait, SlotState.Created, signal), SlotState.Created, toDeadlineMs(deadline), signal);
  }

  private async waitWhile(poll: (waitSeconds: number) => Promise<Status>, state: string, deadlineMs: number, signal?: AbortSignal): Promise<Status> {
    let last: Status | undefined;
    let failures = 0;
    for (;;) {
      const remaining = deadlineMs - Date.now();
      if (remaining <= 0) {
        throw new DeadlineExceededError(last);
      }
      const wait = Math.min(MAX_WAIT_SECONDS, Math.ceil(remaining / 1000));
      let st: Status;
      try {
        st = await poll(wait);
      } catch (err) {
        if (signal?.aborted) {
          throw err;
        }
        if (err instanceof RelayError && err.status < 500 && err.code !== RelayCode.RateLimited) {
          throw err;
        }
        failures++;
        if (failures > 5) {
          throw err;
        }
        await sleep(failures * 1000, signal);
        continue;
      }
      failures = 0;
      last = st;
      if (st.state !== state) {
        return st;
      }
    }
  }

  /**
   * Downloads and deletes the sealed envelope. Only the first call with a
   * valid fetch token succeeds; later calls fail with code "gone".
   */
  async fetch(dropId: string, fetchToken: string, signal?: AbortSignal): Promise<{ ciphertext: Uint8Array; uploadedAt: Date | undefined }> {
    const { status, body } = await this.post("/api/v1/drops/fetch", { drop_id: dropId, fetch_token: fetchToken }, true, signal);
    return { ciphertext: decodeCiphertext(body, status), uploadedAt: time(body, "uploaded_at") };
  }

  /** Stores an encrypted reveal for a human to open once. */
  async createReveal(ciphertext: Uint8Array, ttlSeconds = 0, signal?: AbortSignal): Promise<RevealCreated> {
    const { status, body } = await this.post(
      "/api/v1/reveals",
      { ttl_seconds: Math.floor(ttlSeconds), ciphertext: encodeBase64Url(ciphertext) },
      true,
      signal,
    );
    return {
      id: str(body, "drop_id"),
      revealToken: str(body, "reveal_token"),
      revokeToken: str(body, "revoke_token"),
      expiresAt: requiredTime(body, "expires_at", status),
    };
  }

  /**
   * Downloads and deletes a reveal's ciphertext. It is what the page does;
   * the human helpers use it for the human side of a send.
   */
  async open(dropId: string, revealToken: string, signal?: AbortSignal): Promise<{ ciphertext: Uint8Array; createdAt: Date | undefined }> {
    const { status, body } = await this.post("/api/v1/reveals/open", { drop_id: dropId, reveal_token: revealToken }, false, signal);
    return { ciphertext: decodeCiphertext(body, status), createdAt: time(body, "created_at") };
  }

  /** Cancels a request; either of its tokens is accepted. */
  async revokeDrop(dropId: string, token: string, signal?: AbortSignal): Promise<void> {
    await this.post("/api/v1/drops/revoke", { drop_id: dropId, token }, false, signal);
  }

  /** Deletes an unopened reveal. */
  async revokeReveal(dropId: string, token: string, signal?: AbortSignal): Promise<void> {
    await this.post("/api/v1/reveals/revoke", { drop_id: dropId, token }, false, signal);
  }

  /** Fetches the relay description. */
  async info(signal?: AbortSignal): Promise<RelayInfo> {
    const { body } = await this.request("GET", "/api/v1/info", undefined, false, signal);
    return {
      version: str(body, "version"),
      api: str(body, "api"),
      defaultTtlSeconds: num(body, "default_ttl_seconds"),
      maxTtlSeconds: num(body, "max_ttl_seconds"),
      maxCiphertextBytes: num(body, "max_ciphertext_bytes"),
      longPollMaxSeconds: num(body, "long_poll_max_seconds"),
      agentAuth: str(body, "agent_auth"),
      pageServed: body.page_served === true,
      pageVersion: str(body, "page_version"),
      pageSha256: str(body, "page_sha256"),
    };
  }

  private post(path: string, body: Json, auth: boolean, signal?: AbortSignal): Promise<{ status: number; body: Json }> {
    return this.request("POST", path, body, auth, signal);
  }

  private async request(method: "GET" | "POST", path: string, body: Json | undefined, auth: boolean, signal?: AbortSignal): Promise<{ status: number; body: Json }> {
    const headers: Record<string, string> = { [CLIENT_HEADER]: this.clientName };
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
    }
    if (auth && this.apiKey !== "") {
      headers.Authorization = "Bearer " + this.apiKey;
    }
    const timeout = AbortSignal.timeout(this.timeoutMs);
    const combined = signal === undefined ? timeout : AbortSignal.any([signal, timeout]);
    let response: Response;
    try {
      response = await this.fetchImpl(this.origin + path, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: combined,
        redirect: "error",
      });
    } catch (err) {
      if (signal?.aborted) {
        throw abortReason(signal);
      }
      if (timeout.aborted) {
        throw new RelayUnavailableError("request timed out", { cause: err });
      }
      throw new RelayUnavailableError(err instanceof Error ? err.message : String(err), { cause: err });
    }
    const length = Number(response.headers.get("content-length") ?? "0");
    if (length > MAX_RESPONSE_BYTES) {
      throw new RelayUnavailableError("response too large");
    }
    let text: string;
    try {
      text = await response.text();
    } catch (err) {
      throw new RelayUnavailableError("reading response: " + (err instanceof Error ? err.message : String(err)), { cause: err });
    }
    if (text.length > MAX_RESPONSE_BYTES) {
      throw new RelayUnavailableError("response too large");
    }
    if (response.status < 200 || response.status > 299) {
      throw decodeError(response.status, text);
    }
    if (text === "") {
      return { status: response.status, body: {} };
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      throw new RelayUnavailableError("malformed response (HTTP " + String(response.status) + ")");
    }
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      throw new RelayUnavailableError("malformed response (HTTP " + String(response.status) + ")");
    }
    return { status: response.status, body: parsed as Json };
  }
}

function decodeCiphertext(body: Json, status: number): Uint8Array {
  try {
    return decodeBase64Url(str(body, "ciphertext"));
  } catch {
    throw new RelayUnavailableError("malformed ciphertext in response (HTTP " + String(status) + ")");
  }
}

function decodeError(status: number, text: string): RelayError {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return new RelayError(status, "http_" + String(status));
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return new RelayError(status, "http_" + String(status));
  }
  const body = parsed as Json;
  const code = str(body, "error");
  if (code === "") {
    return new RelayError(status, "http_" + String(status));
  }
  return new RelayError(status, code, str(body, "detail"), str(body, "state"), time(body, "at"));
}
