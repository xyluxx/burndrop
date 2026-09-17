import { describe, expect, it } from "vitest";
import { contentScriptPatterns, hostPattern, normalizeOrigin, OriginError, originMatches, scriptId } from "../src/origins.js";

describe("normalizeOrigin", () => {
  it("accepts https origins, lowercases the host, and drops the default port", () => {
    expect(normalizeOrigin("https://Relay.Example")).toBe("https://relay.example");
    expect(normalizeOrigin(" https://relay.example:443/ ")).toBe("https://relay.example");
    expect(normalizeOrigin("https://relay.example:8443")).toBe("https://relay.example:8443");
  });

  it("accepts http only on loopback", () => {
    expect(normalizeOrigin("http://localhost:8941")).toBe("http://localhost:8941");
    expect(normalizeOrigin("http://127.0.0.1")).toBe("http://127.0.0.1");
    expect(normalizeOrigin("http://[::1]:8080")).toBe("http://[::1]:8080");
    expect(() => normalizeOrigin("http://relay.example")).toThrow(OriginError);
    expect(() => normalizeOrigin("http://localhost.example")).toThrow(OriginError);
  });

  it("rejects anything that is not scheme://host[:port]", () => {
    const rejected = ["", "   ", "relay.example", "ftp://relay.example", "https://relay.example/drop", "https://relay.example?x=1", "https://relay.example#v=1", "https://user:pw@relay.example", `https://${"a".repeat(600)}`];
    for (const input of rejected) {
      expect(() => normalizeOrigin(input), input).toThrow(OriginError);
    }
  });
});

describe("patterns", () => {
  it("keep the port on Chrome and drop it on Firefox, which cannot express one", () => {
    expect(hostPattern("https://relay.example:8443", "chrome")).toBe("https://relay.example:8443/*");
    expect(hostPattern("https://relay.example:8443", "firefox")).toBe("https://relay.example/*");
    expect(contentScriptPatterns("http://localhost:8941", "chrome")).toEqual(["http://localhost:8941/drop*", "http://localhost:8941/reveal*"]);
    expect(contentScriptPatterns("http://localhost:8941", "firefox")).toEqual(["http://localhost/drop*", "http://localhost/reveal*"]);
    expect(scriptId("https://relay.example")).toBe("relay:https://relay.example");
  });

  it("match exactly on Chrome and per host on Firefox, never across schemes", () => {
    expect(originMatches("https://relay.example", "https://relay.example", "chrome")).toBe(true);
    expect(originMatches("https://relay.example", "https://relay.example:8443", "chrome")).toBe(false);
    expect(originMatches("https://relay.example", "https://relay.example:8443", "firefox")).toBe(true);
    expect(originMatches("https://relay.example", "http://relay.example", "firefox")).toBe(false);
    expect(originMatches("https://relay.example", "https://other.example", "firefox")).toBe(false);
  });
});
