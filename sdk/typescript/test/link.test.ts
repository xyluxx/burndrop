/** Mirrors internal/link/link_test.go. */
import { describe, expect, it } from "vitest";

import {
  LinkError,
  buildDropLink,
  buildRevealLink,
  fingerprint,
  isValidToken,
  normalizeOrigin,
  parseDropLink,
  parseLink,
  parseRevealLink,
  parsedRelayOrigin,
  queryEscape,
  relayOrigin,
  revealAad,
  type DropLink,
  type RevealLink,
} from "../src/index.js";
import { bytesEqual, text } from "./helpers.js";

const id = "MTIzNDU2Nzg5MGFiY2RlZg";
const token = "YWJjZGVmZ2hpamtsbW5vcA";
const page = "https://drop.example.com";

function key(b: number): Uint8Array {
  return new Uint8Array(32).fill(b);
}

function sampleDrop(): DropLink {
  return {
    id,
    uploadToken: token,
    recipientKey: key(7),
    name: "openai-api-key",
    purpose: "Call the OpenAI API from the billing script & report",
    storage: "macOS Keychain",
    retention: "until-revoked",
  };
}

function sampleReveal(): RevealLink {
  return { id, revealToken: token, key: key(9), name: "staging-db-url", keepsCopy: true };
}

describe("drop links", () => {
  it("round trip", async () => {
    const d = sampleDrop();
    const raw = buildDropLink(d, page);
    expect(raw.startsWith(page + "/drop#v=1&i=" + id + "&u=" + token + "&k=")).toBe(true);
    expect(raw).not.toContain("?");
    // Byte for byte what the Go implementation builds.
    expect(raw).toBe(
      page +
        "/drop#v=1&i=" +
        id +
        "&u=" +
        token +
        "&k=BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc&n=openai-api-key&p=Call+the+OpenAI+API+from+the+billing+script+%26+report&s=macOS+Keychain&t=until-revoked",
    );
    const { drop: got, pageOrigin } = parseDropLink(raw);
    expect(pageOrigin).toBe(page);
    expect(got.id).toBe(d.id);
    expect(got.uploadToken).toBe(d.uploadToken);
    expect(bytesEqual(got.recipientKey, d.recipientKey)).toBe(true);
    expect(got.name).toBe(d.name);
    expect(got.purpose).toBe(d.purpose);
    expect(got.storage).toBe(d.storage);
    expect(got.retention).toBe(d.retention);
    expect(got.relay).toBeUndefined();
    expect(await fingerprint(got.recipientKey)).toBe(await fingerprint(key(7)));
    const p = parseLink(raw);
    expect(p.kind).toBe("drop");
    expect(parsedRelayOrigin(p)).toBe(page);
  });

  it("with relay and unicode", () => {
    const d = sampleDrop();
    d.relay = "HTTPS://Relay.Example.com:8443/";
    d.name = "clé API";
    d.purpose = "Ligne 1\nligne 2 with + plus and % percent and #hash and =equals";
    const raw = buildDropLink(d, page);
    const { drop: got } = parseDropLink(raw);
    expect(got.relay).toBe("https://relay.example.com:8443");
    expect(got.name).toBe(d.name);
    expect(got.purpose).toBe(d.purpose);
    expect(parsedRelayOrigin(parseLink(raw))).toBe("https://relay.example.com:8443");
  });

  it("accepts optional fields and a trailing slash on the path", () => {
    const raw = page + "/drop/#v=1&i=" + id + "&u=" + token + "&k=BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc&n=n&t=session";
    const { drop } = parseDropLink(raw);
    expect(drop.purpose).toBe("");
    expect(drop.storage).toBe("");
    expect(drop.retention).toBe("session");
    // Fields may come in any order, and an escaped path still matches.
    const reordered = page + "/dr%6fp#t=session&n=n&k=BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc&u=" + token + "&i=" + id + "&v=1";
    expect(parseDropLink(reordered).drop.name).toBe("n");
  });
});

describe("reveal links", () => {
  it("round trip", () => {
    const r = sampleReveal();
    const raw = buildRevealLink(r, page);
    expect(raw.startsWith(page + "/reveal#v=1&i=" + id + "&o=" + token + "&k=")).toBe(true);
    expect(raw.endsWith("&c=1")).toBe(true);
    const { reveal: got, pageOrigin } = parseRevealLink(raw);
    expect(pageOrigin).toBe(page);
    expect(got.id).toBe(r.id);
    expect(got.revealToken).toBe(r.revealToken);
    expect(bytesEqual(got.key, r.key)).toBe(true);
    expect(got.name).toBe(r.name);
    expect(got.keepsCopy).toBe(true);
    expect(text(revealAad(got.name, got.keepsCopy))).toBe("burndrop/reveal/v1\nstaging-db-url\n1");
    r.keepsCopy = false;
    const raw2 = buildRevealLink(r, page);
    expect(parseRevealLink(raw2).reveal.keepsCopy).toBe(false);
    expect(() => parseDropLink(raw)).toThrow(LinkError);
    expect(() => parseRevealLink(buildDropLink(sampleDrop(), page))).toThrow(/not a reveal link/);
  });
});

describe("invalid links", () => {
  const good = buildDropLink(sampleDrop(), page);
  const frag = good.slice(good.indexOf("#") + 1);
  const goodReveal = buildRevealLink(sampleReveal(), page);
  const cases: Record<string, string> = {
    "no fragment": page + "/drop",
    "wrong path": page + "/other#" + frag,
    "root path": page + "/#" + frag,
    "double slash path": page + "/drop//#" + frag,
    "query string": page + "/drop?x=1#" + frag,
    "empty query string": page + "/drop?#" + frag,
    userinfo: "https://user@drop.example.com/drop#" + frag,
    "http origin": "http://drop.example.com/drop#" + frag,
    "no scheme": "drop.example.com/drop#" + frag,
    "bad path escape": page + "/dr%zzp#" + frag,
    "empty fragment": page + "/drop#",
    "wrong version": page + "/drop#" + frag.replace("v=1", "v=2"),
    "missing version": page + "/drop#" + frag.replace("v=1&", ""),
    "empty version": page + "/drop#" + frag.replace("v=1", "v="),
    "unknown field": page + "/drop#" + frag + "&x=1",
    "duplicate field": page + "/drop#" + frag + "&n=again",
    "empty part": page + "/drop#" + frag + "&",
    "missing id": page + "/drop#" + frag.replace("i=" + id, "i="),
    "short id": page + "/drop#" + frag.replace("i=" + id, "i=abc"),
    "non canonical id": page + "/drop#" + frag.replace("i=" + id, "i=MTIzNDU2Nzg5MGFiY2RlZh"),
    "bad token": page + "/drop#" + frag.replace("u=" + token, "u=" + token.slice(1)),
    "bad key": page + "/drop#" + frag.replace("&k=", "&k=x"),
    "short key": page + "/drop#" + frag.replace("&k=BwcH", "&k=Bwc"),
    "non canonical key": page + "/drop#" + frag.replace("BwcHBwc&n", "BwcHBwd&n"),
    "missing name": page + "/drop#" + frag.replace("n=openai-api-key", "n="),
    "bad retention": page + "/drop#" + frag.replace("t=until-revoked", "t=forever"),
    "missing retention": page + "/drop#" + frag.replace("&t=until-revoked", ""),
    "bad relay scheme": page + "/drop#" + frag + "&r=ftp%3A%2F%2Fx",
    "relay with path": page + "/drop#" + frag + "&r=https%3A%2F%2Fx%2Fpath",
    "relay http": page + "/drop#" + frag + "&r=http%3A%2F%2Fx",
    "malformed escape": page + "/drop#" + frag.replace("n=", "n=%zz"),
    "truncated escape": page + "/drop#" + frag.replace("n=", "n=%C3"),
    "field without eq": page + "/drop#" + frag + "&novalue",
    "field without key": page + "/drop#" + frag + "&=x",
    "long name": page + "/drop#" + frag.replace("n=openai-api-key", "n=" + "a".repeat(101)),
    "control in name": page + "/drop#" + frag.replace("n=openai-api-key", "n=a%00b"),
    "padded name": page + "/drop#" + frag.replace("n=openai-api-key", "n=+x"),
    "long purpose": page + "/drop#" + frag.replace("p=Call", "p=" + "b".repeat(201)),
    "control in storage": page + "/drop#" + frag.replace("s=macOS", "s=%09"),
    "reveal bad c": goodReveal.replace("&c=1", "&c=2"),
    "reveal missing c": goodReveal.replace("&c=1", ""),
    "reveal empty c": goodReveal.replace("&c=1", "&c="),
    "reveal drop fields": goodReveal + "&t=session",
    "reveal empty name": goodReveal.replace("n=staging-db-url", "n="),
    "too long": page + "/drop#" + frag + "&p=" + "a".repeat(9000),
  };
  for (const [name, raw] of Object.entries(cases)) {
    it(name, () => {
      expect(() => parseLink(raw)).toThrow(LinkError);
    });
  }
});

describe("build validation", () => {
  it("rejects bad fields and origins", () => {
    const d = sampleDrop();
    d.recipientKey = key(1).subarray(0, 31);
    expect(() => buildDropLink(d, page)).toThrow(LinkError);
    expect(() => buildDropLink(sampleDrop(), "http://drop.example.com")).toThrow(LinkError);
    expect(() => buildDropLink(sampleDrop(), "http://localhost:8080")).not.toThrow();
    const withRelay = sampleDrop();
    withRelay.relay = "https://relay.example.com/api";
    expect(() => buildDropLink(withRelay, page)).toThrow(LinkError);
    const badId = sampleDrop();
    badId.id = "short";
    expect(() => buildDropLink(badId, page)).toThrow(/malformed drop id/);
    const badToken = sampleDrop();
    badToken.uploadToken = "AAAAAAAAAAAAAAAAAAAAAB";
    expect(() => buildDropLink(badToken, page)).toThrow(/malformed upload token/);
    const badName = sampleDrop();
    badName.name = "";
    expect(() => buildDropLink(badName, page)).toThrow(LinkError);
    const badRetention = sampleDrop();
    badRetention.retention = "forever";
    expect(() => buildDropLink(badRetention, page)).toThrow(LinkError);
    const r = sampleReveal();
    r.name = "";
    expect(() => buildRevealLink(r, page)).toThrow(LinkError);
    const rk = sampleReveal();
    rk.key = new Uint8Array(16);
    expect(() => buildRevealLink(rk, page)).toThrow(/key must be 32 bytes/);
    const rt = sampleReveal();
    rt.revealToken = "x";
    expect(() => buildRevealLink(rt, page)).toThrow(/malformed reveal token/);
    const rr = sampleReveal();
    rr.relay = "ftp://relay.example";
    expect(() => buildRevealLink(rr, page)).toThrow(LinkError);
    const ri = sampleReveal();
    ri.id = "";
    expect(() => buildRevealLink(ri, page)).toThrow(/malformed drop id/);
  });
});

describe("normalizeOrigin", () => {
  it("accepts and normalizes valid origins", () => {
    const ok: Record<string, string> = {
      "https://Example.com": "https://example.com",
      "https://example.com/": "https://example.com",
      "https://example.com:8443": "https://example.com:8443",
      "http://localhost:3000": "http://localhost:3000",
      "http://127.0.0.1": "http://127.0.0.1",
      "http://[::1]:8081": "http://[::1]:8081",
      "https://[2001:db8::1]:443": "https://[2001:db8::1]",
      "https://[2001:DB8::1]": "https://[2001:db8::1]",
      "https://example.com:443/": "https://example.com",
      "http://localhost:80": "http://localhost",
      "http://LOCALHOST": "http://localhost",
      "http://localhost:8080": "http://localhost:8080",
      "https://sub.example.co.uk/": "https://sub.example.co.uk",
      "HTTPS://Relay.Example.com:8443/": "https://relay.example.com:8443",
    };
    for (const [input, want] of Object.entries(ok)) {
      expect(normalizeOrigin(input), input).toBe(want);
    }
  });

  it("rejects everything else", () => {
    for (const bad of [
      "",
      "example.com",
      "http://example.com",
      "http://localhost.example",
      "https://",
      "https:///",
      "https://example.com/path",
      "https://example.com?x=1",
      "https://example.com?",
      "https://example.com#f",
      "https://example.com#",
      "https://u:p@example.com",
      "https://@example.com",
      "ftp://example.com",
      "https:/example.com",
      "https:example.com",
      "://example.com",
      "1https://example.com",
      "https://exa mple.com",
      "https://example.com:",
      "https://example.com:abc",
      "https://example.com:8080:1",
      "https://[::1",
      "https://[::1]x",
      "https://[::1]:x",
      "https://example.com\n",
      "https://exa" + String.fromCharCode(1) + "mple.com",
      "https://[::1" + String.fromCharCode(1) + "]",
      "https://" + "a".repeat(600),
    ]) {
      expect(() => normalizeOrigin(bad), JSON.stringify(bad)).toThrow(LinkError);
    }
  });
});

describe("helpers", () => {
  it("keeps links short", () => {
    expect(buildDropLink(sampleDrop(), page).length).toBeLessThanOrEqual(400);
    expect(buildRevealLink(sampleReveal(), page).length).toBeLessThanOrEqual(250);
  });

  it("falls back to the page origin for the relay", () => {
    expect(relayOrigin(sampleDrop(), "https://page.example")).toBe("https://page.example");
    const d = sampleDrop();
    d.relay = "https://r.example";
    expect(relayOrigin(d, "https://page.example")).toBe("https://r.example");
    const r = sampleReveal();
    expect(relayOrigin(r, "https://page.example")).toBe("https://page.example");
    r.relay = "https://r.example";
    expect(relayOrigin(r, "https://page.example")).toBe("https://r.example");
    const parsed = parseLink(buildRevealLink(r, page));
    expect(parsedRelayOrigin(parsed)).toBe("https://r.example");
  });

  it("escapes like Go's url.QueryEscape", () => {
    expect(queryEscape("a b&c=d/é~_.-!*'()")).toBe("a+b%26c%3Dd%2F%C3%A9~_.-%21%2A%27%28%29");
    expect(queryEscape("")).toBe("");
  });

  it("validates tokens", () => {
    expect(isValidToken(id)).toBe(true);
    expect(isValidToken("AAAAAAAAAAAAAAAAAAAAAA")).toBe(true);
    expect(isValidToken("AAAAAAAAAAAAAAAAAAAAAB")).toBe(false);
    expect(isValidToken("AAAAAAAAAAAAAAAAAAAAA")).toBe(false);
    expect(isValidToken("AAAAAAAAAAAAAAAAAAAAAAA")).toBe(false);
    expect(isValidToken("AAAAAAAAAAAAAAAAAAAA+/")).toBe(false);
    expect(isValidToken("")).toBe(false);
  });
});
