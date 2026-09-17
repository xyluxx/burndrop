import { describe, expect, it } from "vitest";
import { CLIENT_HEADER, RelayClient, RelayError } from "../src/api.js";

interface Call {
  url: string;
  init: RequestInit;
}

function fakeFetch(status: number, body: string, calls: Call[]): (url: string, init: RequestInit) => Promise<Response> {
  return async (url, init) => {
    calls.push({ url, init });
    return new Response(body, { status, headers: { "Content-Type": "application/json" } });
  };
}

describe("RelayClient", () => {
  it("posts JSON with the client header and no credentials", async () => {
    const calls: Call[] = [];
    const c = new RelayClient("https://relay.example", "test/1", fakeFetch(200, '{"state":"created","kind":"drop","created_at":"a","expires_at":"b"}', calls));
    const st = await c.dropStatus("id", 5, "created");
    expect(st.state).toBe("created");
    expect(calls).toHaveLength(1);
    const call = calls[0]!;
    expect(call.url).toBe("https://relay.example/api/v1/drops/status");
    expect(call.init.method).toBe("POST");
    expect(call.init.credentials).toBe("omit");
    expect(call.init.referrerPolicy).toBe("no-referrer");
    expect((call.init.headers as Record<string, string>)[CLIENT_HEADER]).toBe("test/1");
    expect(JSON.parse(call.init.body as string)).toEqual({ drop_id: "id", wait_seconds: 5, wait_while: "created" });
  });

  it("covers every endpoint the page uses", async () => {
    const calls: Call[] = [];
    const c = new RelayClient("https://relay.example", "t", fakeFetch(200, "{}", calls));
    await c.revealStatus("r");
    await c.upload("d", "u", "c", "ct");
    await c.open("r", "o");
    expect(calls.map((x) => x.url.replace("https://relay.example", ""))).toEqual(["/api/v1/reveals/status", "/api/v1/drops/upload", "/api/v1/reveals/open"]);
    expect(JSON.parse(calls[1]!.init.body as string)).toEqual({ drop_id: "d", upload_token: "u", commitment: "c", ciphertext: "ct" });
    expect(JSON.parse(calls[2]!.init.body as string)).toEqual({ drop_id: "r", reveal_token: "o" });
  });

  it("turns relay errors into RelayError with code, state, and time", async () => {
    const c = new RelayClient("https://relay.example", "t", fakeFetch(410, '{"error":"gone","state":"fetched","at":"2026-01-01T00:00:00Z","detail":"d"}', []));
    const err = await c.dropStatus("x").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(RelayError);
    const re = err as RelayError;
    expect(re.status).toBe(410);
    expect(re.code).toBe("gone");
    expect(re.state).toBe("fetched");
    expect(re.at).toBe("2026-01-01T00:00:00Z");
    expect(re.detail).toBe("d");
    expect(re.message).toBe("gone (HTTP 410)");
  });

  it("copes with non-JSON error bodies, empty bodies, and network failures", async () => {
    const html = new RelayClient("https://relay.example", "t", fakeFetch(502, "<html>bad gateway</html>", []));
    await expect(html.dropStatus("x")).rejects.toMatchObject({ code: "http_502", status: 502 });
    const empty = new RelayClient("https://relay.example", "t", fakeFetch(200, "", []));
    await expect(empty.dropStatus("x")).rejects.toMatchObject({ code: "malformed_response" });
    const scalar = new RelayClient("https://relay.example", "t", fakeFetch(200, "42", []));
    await expect(scalar.dropStatus("x")).rejects.toMatchObject({ code: "malformed_response" });
    const down = new RelayClient("https://relay.example", "t", async () => {
      throw new TypeError("failed to fetch");
    });
    await expect(down.dropStatus("x")).rejects.toMatchObject({ code: "network", status: 0 });
  });
});
