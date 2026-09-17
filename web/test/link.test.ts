import { describe, expect, it } from "vitest";
import * as b64 from "../src/base64.js";
import { LinkError, buildDropLink, buildRevealLink, normalizeOrigin, parseDropFragment, parseLink, parseRevealFragment } from "../src/link.js";

const TOKEN = "AAAAAAAAAAAAAAAAAAAAAA";
const TOKEN2 = "MTIzNDU2Nzg5MGFiY2RlZg";
const KEY = new Uint8Array(32).fill(7);
const KEY_B64 = b64.encode(KEY);

function dropFrag(overrides: Record<string, string | null> = {}): string {
  const fields: Record<string, string | null> = { v: "1", i: TOKEN, u: TOKEN2, k: KEY_B64, n: "openai-api-key", p: "Call the API", s: "macOS Keychain", t: "until-revoked", ...overrides };
  return Object.entries(fields)
    .filter(([, v]) => v !== null)
    .map(([k, v]) => `${k}=${encodeURIComponent(v as string)}`)
    .join("&");
}

function revealFrag(overrides: Record<string, string | null> = {}): string {
  const fields: Record<string, string | null> = { v: "1", i: TOKEN, o: TOKEN2, k: KEY_B64, n: "staging-db-url", c: "1", ...overrides };
  return Object.entries(fields)
    .filter(([, v]) => v !== null)
    .map(([k, v]) => `${k}=${encodeURIComponent(v as string)}`)
    .join("&");
}

describe("normalizeOrigin", () => {
  it("lowercases, strips default ports, and keeps others", () => {
    expect(normalizeOrigin("HTTPS://Relay.Example:443")).toBe("https://relay.example");
    expect(normalizeOrigin("https://relay.example:8443/")).toBe("https://relay.example:8443");
    expect(normalizeOrigin("http://localhost:8080")).toBe("http://localhost:8080");
    expect(normalizeOrigin("http://127.0.0.1")).toBe("http://127.0.0.1");
    expect(normalizeOrigin("http://[::1]:80")).toBe("http://[::1]");
    expect(normalizeOrigin("https://[2001:db8::1]:443")).toBe("https://[2001:db8::1]");
  });

  it("rejects paths, queries, userinfo, plain http, and other schemes", () => {
    for (const bad of ["https://relay.example/path", "https://relay.example/?x=1", "https://u:p@relay.example", "http://relay.example", "ftp://relay.example", "relay.example", "https://", "", "https://relay.example#frag"]) {
      expect(() => normalizeOrigin(bad), bad).toThrow(LinkError);
    }
    expect(() => normalizeOrigin("https://" + "a".repeat(600))).toThrow(/too long/);
  });
});

describe("parseDropFragment", () => {
  it("parses a full drop fragment", () => {
    const d = parseDropFragment(dropFrag({ r: "https://relay.example" }));
    expect(d.kind).toBe("drop");
    expect(d.id).toBe(TOKEN);
    expect(d.uploadToken).toBe(TOKEN2);
    expect(d.recipientKey).toEqual(KEY);
    expect(d.name).toBe("openai-api-key");
    expect(d.purpose).toBe("Call the API");
    expect(d.storage).toBe("macOS Keychain");
    expect(d.retention).toBe("until-revoked");
    expect(d.relay).toBe("https://relay.example");
  });

  it("accepts the minimal fragment and plus-encoded spaces", () => {
    const d = parseDropFragment(dropFrag({ p: null, s: null }));
    expect(d.purpose).toBe("");
    expect(d.storage).toBe("");
    expect(d.relay).toBeNull();
    const plus = parseDropFragment(dropFrag().replace("Call%20the%20API", "Call+the+API"));
    expect(plus.purpose).toBe("Call the API");
  });

  it("rejects malformed fragments the way the Go parser does", () => {
    const cases: Array<[string, string]> = [
      ["empty", ""],
      ["no equals", "v"],
      ["empty key", "=1&" + dropFrag()],
      ["unknown field", dropFrag() + "&x=1"],
      ["duplicate field", dropFrag() + "&n=again"],
      ["bad percent", dropFrag({ p: "" }) .replace("p=", "p=%zz")],
      ["version", dropFrag({ v: "2" })],
      ["missing version", dropFrag({ v: null })],
      ["missing id", dropFrag({ i: null })],
      ["missing upload token", dropFrag({ u: null })],
      ["missing key", dropFrag({ k: null })],
      ["missing name", dropFrag({ n: null })],
      ["missing retention", dropFrag({ t: null })],
      ["short id", dropFrag({ i: "abc" })],
      ["bad token chars", dropFrag({ u: "AAAAAAAAAAAAAAAAAAAAA=" })],
      ["short key", dropFrag({ k: b64.encode(new Uint8Array(31)) })],
      ["long key", dropFrag({ k: b64.encode(new Uint8Array(33)) })],
      ["key not base64", dropFrag({ k: "!".repeat(43) })],
      ["bad retention", dropFrag({ t: "forever" })],
      ["bad retention date", dropFrag({ t: "until:2026-13-45T99:00:00Z" })],
      ["name too long", dropFrag({ n: "a".repeat(101) })],
      ["name whitespace", dropFrag({ n: " padded" })],
      ["name control", dropFrag({ n: "ab" })],
      ["purpose too long", dropFrag({ p: "a".repeat(201) })],
      ["purpose control", dropFrag({ p: "ab" })],
      ["storage too long", dropFrag({ s: "a".repeat(201) })],
      ["bad relay", dropFrag({ r: "http://relay.example" })],
      ["relay with path", dropFrag({ r: "https://relay.example/x" })],
    ];
    for (const [label, frag] of cases) {
      expect(() => parseDropFragment(frag), label).toThrow(LinkError);
    }
  });

  it("allows newlines in purpose and 100 rune names", () => {
    const d = parseDropFragment(dropFrag({ p: "line one\nline two", n: "é".repeat(100) }));
    expect(d.purpose).toBe("line one\nline two");
    expect(d.name.length).toBe(100);
  });
});

describe("parseRevealFragment", () => {
  it("parses a reveal fragment", () => {
    const r = parseRevealFragment(revealFrag({ r: "https://relay.example:8443" }));
    expect(r.kind).toBe("reveal");
    expect(r.id).toBe(TOKEN);
    expect(r.revealToken).toBe(TOKEN2);
    expect(r.key).toEqual(KEY);
    expect(r.name).toBe("staging-db-url");
    expect(r.keepsCopy).toBe(true);
    expect(r.relay).toBe("https://relay.example:8443");
    expect(parseRevealFragment(revealFrag({ c: "0" })).keepsCopy).toBe(false);
    expect(parseRevealFragment(revealFrag()).relay).toBeNull();
  });

  it("rejects malformed reveal fragments", () => {
    const cases: Array<[string, string]> = [
      ["drop fields", dropFrag()],
      ["missing c", revealFrag({ c: null })],
      ["bad c", revealFrag({ c: "yes" })],
      ["missing o", revealFrag({ o: null })],
      ["bad id", revealFrag({ i: "x" })],
      ["bad token", revealFrag({ o: "x" })],
      ["bad key", revealFrag({ k: "abc" })],
      ["bad name", revealFrag({ n: "" })],
      ["long name", revealFrag({ n: "a".repeat(101) })],
      ["unknown", revealFrag() + "&p=x"],
    ];
    for (const [label, frag] of cases) {
      expect(() => parseRevealFragment(frag), label).toThrow(LinkError);
    }
  });
});

describe("parseLink and builders", () => {
  it("parses whole links and reports the page origin", () => {
    const drop = parseLink(`https://Relay.Example/drop#${dropFrag()}`);
    expect(drop.link.kind).toBe("drop");
    expect(drop.pageOrigin).toBe("https://relay.example");
    const reveal = parseLink(`https://relay.example:8443/reveal/#${revealFrag()}`);
    expect(reveal.link.kind).toBe("reveal");
    expect(reveal.pageOrigin).toBe("https://relay.example:8443");
  });

  it("rejects links without a fragment, with a query, userinfo, or another path", () => {
    for (const bad of [
      `https://relay.example/drop`,
      `https://relay.example/drop?x=1#${dropFrag()}`,
      `https://u:p@relay.example/drop#${dropFrag()}`,
      `https://relay.example/other#${dropFrag()}`,
      `https://relay.example/drop/extra#${dropFrag()}`,
      `not a url#${dropFrag()}`,
      `https://relay.example/drop#${"a".repeat(9000)}`,
    ]) {
      expect(() => parseLink(bad), bad.slice(0, 60)).toThrow(LinkError);
    }
  });

  it("builds links that parse back to the same values", () => {
    const link = buildDropLink("https://Relay.Example:443", {
      relay: "https://other.example",
      id: TOKEN,
      uploadToken: TOKEN2,
      recipientKey: KEY,
      name: "né name",
      purpose: "why & how",
      storage: "os keychain",
      retention: "session",
    });
    expect(link.startsWith("https://relay.example/drop#v=1&i=")).toBe(true);
    expect(link).not.toContain("%20");
    const parsed = parseLink(link);
    expect(parsed.link).toMatchObject({ kind: "drop", name: "né name", purpose: "why & how", storage: "os keychain", retention: "session", relay: "https://other.example" });
    const short = buildDropLink("https://relay.example", { relay: null, id: TOKEN, uploadToken: TOKEN2, recipientKey: KEY, name: "n", purpose: "", storage: "", retention: "session" });
    expect(short).not.toContain("&r=");
    expect(parseLink(short).link).toMatchObject({ purpose: "", storage: "", relay: null });

    const reveal = buildRevealLink("https://relay.example", { relay: "https://relay.example", id: TOKEN, revealToken: TOKEN2, key: KEY, name: "db", keepsCopy: false });
    expect(parseLink(reveal).link).toMatchObject({ kind: "reveal", name: "db", keepsCopy: false, relay: "https://relay.example" });
    const noRelay = buildRevealLink("https://relay.example", { relay: null, id: TOKEN, revealToken: TOKEN2, key: KEY, name: "db", keepsCopy: true });
    expect(noRelay).not.toContain("&r=");
    expect(parseLink(noRelay).link).toMatchObject({ keepsCopy: true, relay: null });
  });
});
