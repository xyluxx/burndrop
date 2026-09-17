import { afterEach, describe, expect, it, vi } from "vitest";

import {
  CLIENT_HEADER,
  DEFAULT_CLIENT_NAME,
  DeadlineExceededError,
  LinkError,
  MAX_WAIT_SECONDS,
  RelayClient,
  RelayError,
  RelayUnavailableError,
  encodeBase64Url,
  isTerminalState,
} from "../src/index.js";
import { bytesEqual, utf8 } from "./helpers.js";

interface Call {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: unknown;
}

function json(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(typeof body === "string" ? body : JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });
}

function stub(handler: (call: Call, index: number) => Response | Promise<Response>): { fetch: typeof globalThis.fetch; calls: Call[] } {
  const calls: Call[] = [];
  const fetch: typeof globalThis.fetch = (input, init) => {
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries((init?.headers ?? {}) as Record<string, string>)) {
      headers[k] = v;
    }
    const call: Call = {
      url: typeof input === "string" ? input : input instanceof URL ? input.href : input.url,
      method: init?.method ?? "GET",
      headers,
      body: typeof init?.body === "string" ? JSON.parse(init.body) : undefined,
    };
    calls.push(call);
    return Promise.resolve(handler(call, calls.length - 1));
  };
  return { fetch, calls };
}

const origin = "https://relay.example";
const id = "MTIzNDU2Nzg5MGFiY2RlZg";

describe("RelayClient requests", () => {
  it("normalizes the origin and rejects bad ones", () => {
    expect(new RelayClient("https://Relay.Example.com:443/").origin).toBe("https://relay.example.com");
    expect(() => new RelayClient("http://relay.example.com")).toThrow(LinkError);
    expect(new RelayClient(origin).clientName).toBe(DEFAULT_CLIENT_NAME);
    expect(new RelayClient(origin, "", { clientName: "custom/1" }).clientName).toBe("custom/1");
  });

  it("posts JSON with the client header and identifiers only in the body", async () => {
    const s = stub(() => json(201, { drop_id: id, upload_token: "u", fetch_token: "f", expires_at: "2026-01-01T00:00:00Z" }));
    const client = new RelayClient(origin, "agent-key", { fetch: s.fetch });
    const created = await client.createDrop("c".repeat(43), 600.9);
    expect(created).toEqual({ id, uploadToken: "u", fetchToken: "f", expiresAt: new Date("2026-01-01T00:00:00Z") });
    const call = s.calls[0];
    expect(call.method).toBe("POST");
    expect(call.url).toBe(origin + "/api/v1/drops");
    expect(call.url).not.toContain("?");
    expect(call.headers[CLIENT_HEADER]).toBe(DEFAULT_CLIENT_NAME);
    expect(call.headers["Content-Type"]).toBe("application/json");
    expect(call.headers.Authorization).toBe("Bearer agent-key");
    expect(call.body).toEqual({ ttl_seconds: 600, commitment: "c".repeat(43) });
  });

  it("sends the bearer token only on agent endpoints", async () => {
    const s = stub((call) => {
      if (call.url.endsWith("/upload") || call.url.endsWith("/status") || call.url.endsWith("/open") || call.url.endsWith("/revoke")) {
        return json(200, { state: "x" });
      }
      return json(200, { ciphertext: "AAEC", uploaded_at: "2026-01-01T00:00:00Z", drop_id: id, reveal_token: "r", revoke_token: "k", expires_at: "2026-01-01T00:00:00Z" });
    });
    const client = new RelayClient(origin, "agent-key", { fetch: s.fetch });
    await client.upload(id, "tok", "c".repeat(43), new Uint8Array([1, 2, 3]));
    await client.dropStatus(id);
    await client.revealStatus(id, 5, "created");
    await client.open(id, "reveal-token");
    await client.revokeDrop(id, "t");
    await client.revokeReveal(id, "t");
    for (const call of s.calls) {
      expect(call.headers.Authorization, call.url).toBeUndefined();
      expect(call.headers[CLIENT_HEADER]).toBe(DEFAULT_CLIENT_NAME);
    }
    expect(s.calls[0].body).toEqual({ drop_id: id, upload_token: "tok", commitment: "c".repeat(43), ciphertext: "AQID" });
    expect(s.calls[1].body).toEqual({ drop_id: id, wait_seconds: 0, wait_while: "" });
    expect(s.calls[1].url).toBe(origin + "/api/v1/drops/status");
    expect(s.calls[2].body).toEqual({ drop_id: id, wait_seconds: 5, wait_while: "created" });
    expect(s.calls[2].url).toBe(origin + "/api/v1/reveals/status");
    expect(s.calls[3].body).toEqual({ drop_id: id, reveal_token: "reveal-token" });
    expect(s.calls[4].body).toEqual({ drop_id: id, token: "t" });
    expect(s.calls[4].url).toBe(origin + "/api/v1/drops/revoke");
    expect(s.calls[5].url).toBe(origin + "/api/v1/reveals/revoke");
    await client.fetch(id, "fetch-token");
    await client.createReveal(new Uint8Array([9]), 60);
    expect(s.calls[6].headers.Authorization).toBe("Bearer agent-key");
    expect(s.calls[6].body).toEqual({ drop_id: id, fetch_token: "fetch-token" });
    expect(s.calls[7].headers.Authorization).toBe("Bearer agent-key");
    expect(s.calls[7].body).toEqual({ ttl_seconds: 60, ciphertext: "CQ" });
  });

  it("omits the bearer header without an api key", async () => {
    const s = stub(() => json(201, { drop_id: id, upload_token: "u", fetch_token: "f", expires_at: "2026-01-01T00:00:00Z" }));
    await new RelayClient(origin, "", { fetch: s.fetch }).createDrop("c".repeat(43));
    expect(s.calls[0].headers.Authorization).toBeUndefined();
    expect(s.calls[0].body).toEqual({ ttl_seconds: 0, commitment: "c".repeat(43) });
  });

  it("clamps wait_seconds to the relay maximum", async () => {
    const s = stub(() => json(200, { state: "created", kind: "drop", created_at: "2026-01-01T00:00:00Z", expires_at: "2026-01-01T01:00:00Z" }));
    const client = new RelayClient(origin, "", { fetch: s.fetch });
    const st = await client.dropStatus(id, 45.7, "created");
    expect(s.calls[0].body).toEqual({ drop_id: id, wait_seconds: MAX_WAIT_SECONDS, wait_while: "created" });
    expect(st.state).toBe("created");
    expect(st.kind).toBe("drop");
    expect(st.createdAt).toEqual(new Date("2026-01-01T00:00:00Z"));
    expect(st.expiresAt).toEqual(new Date("2026-01-01T01:00:00Z"));
    expect(st.uploadedAt).toBeUndefined();
    await client.dropStatus(id, -3);
    expect(s.calls[1].body).toEqual({ drop_id: id, wait_seconds: 0, wait_while: "" });
  });

  it("decodes ciphertext and timestamps", async () => {
    const ct = utf8("sealed bytes");
    const s = stub(() => json(200, { ciphertext: encodeBase64Url(ct), uploaded_at: "2026-01-01T00:00:00Z", created_at: "bad" }));
    const client = new RelayClient(origin, "", { fetch: s.fetch });
    const fetched = await client.fetch(id, "f");
    expect(bytesEqual(fetched.ciphertext, ct)).toBe(true);
    expect(fetched.uploadedAt).toEqual(new Date("2026-01-01T00:00:00Z"));
    const opened = await client.open(id, "r");
    expect(opened.createdAt).toBeUndefined();
    const bad = stub(() => json(200, { ciphertext: "AA==" }));
    await expect(new RelayClient(origin, "", { fetch: bad.fetch }).fetch(id, "f")).rejects.toBeInstanceOf(RelayUnavailableError);
  });

  it("fetches info with a GET and no body", async () => {
    const s = stub(() =>
      json(200, {
        version: "1.2.3",
        api: "v1",
        default_ttl_seconds: 3600,
        max_ttl_seconds: 86400,
        max_ciphertext_bytes: 65840,
        long_poll_max_seconds: 30,
        agent_auth: "required",
        page_served: true,
        page_version: "p",
        page_sha256: "h",
      }),
    );
    const info = await new RelayClient(origin, "", { fetch: s.fetch }).info();
    expect(info).toEqual({
      version: "1.2.3",
      api: "v1",
      defaultTtlSeconds: 3600,
      maxTtlSeconds: 86400,
      maxCiphertextBytes: 65840,
      longPollMaxSeconds: 30,
      agentAuth: "required",
      pageServed: true,
      pageVersion: "p",
      pageSha256: "h",
    });
    expect(s.calls[0].method).toBe("GET");
    expect(s.calls[0].url).toBe(origin + "/api/v1/info");
    expect(s.calls[0].body).toBeUndefined();
    expect(s.calls[0].headers["Content-Type"]).toBeUndefined();
    expect(s.calls[0].headers[CLIENT_HEADER]).toBe(DEFAULT_CLIENT_NAME);
  });
});

describe("RelayClient errors", () => {
  it("turns error bodies into RelayError", async () => {
    const s = stub(() => json(410, { error: "gone", state: "fetched", at: "2026-01-01T00:00:00Z" }));
    const err = await new RelayClient(origin, "", { fetch: s.fetch }).fetch(id, "f").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(RelayError);
    const relayErr = err as RelayError;
    expect(relayErr.status).toBe(410);
    expect(relayErr.code).toBe("gone");
    expect(relayErr.state).toBe("fetched");
    expect(relayErr.at).toEqual(new Date("2026-01-01T00:00:00Z"));
    expect(relayErr.message).toBe("relay: gone (fetched) [HTTP 410]");
    const detail = stub(() => json(422, { error: "commitment_mismatch", detail: "the public key in this link does not match the key the agent registered" }));
    const e2 = (await new RelayClient(origin, "", { fetch: detail.fetch }).upload(id, "u", "c", new Uint8Array(1)).catch((e: unknown) => e)) as RelayError;
    expect(e2.code).toBe("commitment_mismatch");
    expect(e2.detail).toContain("does not match");
    expect(e2.message).toBe("relay: commitment_mismatch: the public key in this link does not match the key the agent registered [HTTP 422]");
    expect(e2.state).toBe("");
    expect(e2.at).toBeUndefined();
  });

  it("uses http_<status> when the body is not an error object", async () => {
    for (const body of ["Internal Server Error", "[]", "{}", '{"error":""}', '{"error":5}']) {
      const s = stub(() => json(500, body));
      const err = (await new RelayClient(origin, "", { fetch: s.fetch }).dropStatus(id).catch((e: unknown) => e)) as RelayError;
      expect(err, body).toBeInstanceOf(RelayError);
      expect(err.code).toBe("http_500");
      expect(err.status).toBe(500);
    }
  });

  it("treats unreadable success responses as unavailable", async () => {
    for (const body of ["not json", "[]", "null", '"x"']) {
      const s = stub(() => json(200, body));
      await expect(new RelayClient(origin, "", { fetch: s.fetch }).dropStatus(id), body).rejects.toBeInstanceOf(RelayUnavailableError);
    }
    const missing = stub(() => json(201, { drop_id: id, upload_token: "u", fetch_token: "f" }));
    await expect(new RelayClient(origin, "", { fetch: missing.fetch }).createDrop("c".repeat(43))).rejects.toThrow(/missing expires_at/);
    const empty = stub(() => new Response("", { status: 200 }));
    await expect(new RelayClient(origin, "", { fetch: empty.fetch }).upload(id, "u", "c", new Uint8Array(1))).resolves.toBeUndefined();
    const big = stub(() => json(200, "{}", { "content-length": String(2 << 20) }));
    await expect(new RelayClient(origin, "", { fetch: big.fetch }).dropStatus(id)).rejects.toThrow(/too large/);
  });

  it("wraps network failures, timeouts, and honors the caller's abort signal", async () => {
    const down: typeof globalThis.fetch = () => Promise.reject(new TypeError("fetch failed"));
    const err = await new RelayClient(origin, "", { fetch: down }).dropStatus(id).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(RelayUnavailableError);
    expect((err as RelayUnavailableError).message).toBe("relay: fetch failed");
    expect((err as RelayUnavailableError).cause).toBeInstanceOf(TypeError);

    const hang: typeof globalThis.fetch = (_input, init) =>
      new Promise((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => {
          reject(init.signal?.reason as Error);
        });
      });
    await expect(new RelayClient(origin, "", { fetch: hang, timeoutMs: 50 }).dropStatus(id)).rejects.toThrow(/request timed out/);

    const controller = new AbortController();
    const pending = new RelayClient(origin, "", { fetch: hang }).dropStatus(id, 0, "", controller.signal);
    controller.abort(new Error("caller cancelled"));
    await expect(pending).rejects.toThrow(/caller cancelled/);
  });
});

describe("RelayClient long polling", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("returns as soon as the state changes", async () => {
    const states = ["created", "created", "uploaded"];
    const s = stub((_call, i) => json(200, { state: states[Math.min(i, states.length - 1)], kind: "drop", uploaded_at: i >= 2 ? "2026-01-01T00:00:00Z" : "" }));
    const client = new RelayClient(origin, "", { fetch: s.fetch });
    const st = await client.waitForUpload(id, Date.now() + 60_000);
    expect(st.state).toBe("uploaded");
    expect(st.uploadedAt).toEqual(new Date("2026-01-01T00:00:00Z"));
    expect(s.calls.length).toBe(3);
    for (const call of s.calls) {
      const body = call.body as { wait_seconds: number; wait_while: string };
      expect(body.wait_while).toBe("created");
      expect(body.wait_seconds).toBeGreaterThan(0);
      expect(body.wait_seconds).toBeLessThanOrEqual(MAX_WAIT_SECONDS);
    }
    const r = stub(() => json(200, { state: "opened", kind: "reveal", opened_at: "2026-01-01T00:00:00Z" }));
    const opened = await new RelayClient(origin, "", { fetch: r.fetch }).waitForOpen(id, new Date(Date.now() + 1000));
    expect(opened.state).toBe("opened");
    expect(opened.openedAt).toBeDefined();
    expect(r.calls[0].url).toBe(origin + "/api/v1/reveals/status");
  });

  it("gives up at the deadline with the last status", async () => {
    const s = stub(() => json(200, { state: "created", kind: "drop" }));
    const client = new RelayClient(origin, "", { fetch: s.fetch });
    const err = await client.waitForUpload(id, Date.now() + 200).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(DeadlineExceededError);
    expect((err as DeadlineExceededError).lastStatus?.state).toBe("created");
    const past = await client.waitForUpload(id, Date.now() - 1).catch((e: unknown) => e);
    expect(past).toBeInstanceOf(DeadlineExceededError);
    expect((past as DeadlineExceededError).lastStatus).toBeUndefined();
  });

  it("stops on client errors but retries server errors and rate limits", async () => {
    const notFound = stub(() => json(404, { error: "not_found" }));
    await expect(new RelayClient(origin, "", { fetch: notFound.fetch }).waitForUpload(id, Date.now() + 60_000)).rejects.toMatchObject({ code: "not_found" });
    expect(notFound.calls.length).toBe(1);

    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "Date"] });
    const flaky = stub((_call, i) => {
      if (i === 0) {
        return json(503, { error: "store_full" });
      }
      if (i === 1) {
        return json(429, { error: "rate_limited" });
      }
      if (i === 2) {
        return Promise.reject(new TypeError("connection reset"));
      }
      return json(200, { state: "uploaded", kind: "drop" });
    });
    const client = new RelayClient(origin, "", { fetch: flaky.fetch });
    const waiting = client.waitForUpload(id, Date.now() + 600_000);
    await vi.advanceTimersByTimeAsync(1000);
    await vi.advanceTimersByTimeAsync(2000);
    await vi.advanceTimersByTimeAsync(3000);
    const st = await waiting;
    expect(st.state).toBe("uploaded");
    expect(flaky.calls.length).toBe(4);

    const broken = stub(() => json(500, { error: "internal_error" }));
    const failing = new RelayClient(origin, "", { fetch: broken.fetch }).waitForUpload(id, Date.now() + 600_000);
    const rejection = expect(failing).rejects.toMatchObject({ status: 500 });
    for (let i = 1; i <= 6; i++) {
      await vi.advanceTimersByTimeAsync(i * 1000);
    }
    await rejection;
    expect(broken.calls.length).toBe(6);
  });

  it("reports terminal states", () => {
    expect(isTerminalState("created")).toBe(false);
    expect(isTerminalState("uploaded")).toBe(false);
    for (const s of ["fetched", "opened", "revoked", "expired"]) {
      expect(isTerminalState(s)).toBe(true);
    }
  });
});
