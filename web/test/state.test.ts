import { describe, expect, it } from "vitest";
import {
  DROP_COPY,
  REVEAL_COPY,
  MAX_SECRET_BYTES,
  describeRetention,
  dropStateFor,
  formatCountdown,
  formatTime,
  relayErrorMessage,
  revealStateFor,
} from "../src/state.js";

describe("state copy", () => {
  it("has a title for every state and never an em dash", () => {
    for (const copy of [...Object.values(DROP_COPY), ...Object.values(REVEAL_COPY)]) {
      expect(copy.title.length).toBeGreaterThan(0);
      for (const s of [copy.title, copy.text]) {
        expect(s.includes(String.fromCharCode(0x2014))).toBe(false);
      }
    }
  });

  it("maps relay states to page states on load", () => {
    expect(dropStateFor("created")).toBe("waiting");
    expect(dropStateFor("uploaded")).toBe("sent");
    expect(dropStateFor("fetched")).toBe("delivered");
    expect(dropStateFor("revoked")).toBe("revoked");
    expect(dropStateFor("expired")).toBe("expired");
    expect(dropStateFor("anything else")).toBe("expired");
    expect(revealStateFor("created")).toBe("ready");
    expect(revealStateFor("opened")).toBe("opened");
    expect(revealStateFor("revoked")).toBe("revoked");
    expect(revealStateFor("expired")).toBe("expired");
  });
});

describe("formatting", () => {
  const now = new Date("2026-01-01T00:00:00Z");

  it("formats countdowns by magnitude", () => {
    expect(formatCountdown(new Date("2026-01-03T05:00:00Z"), now)).toBe("2 d 5 h");
    expect(formatCountdown(new Date("2026-01-01T02:05:00Z"), now)).toBe("2 h 5 min");
    expect(formatCountdown(new Date("2026-01-01T00:04:10Z"), now)).toBe("4 min");
    expect(formatCountdown(new Date("2026-01-01T00:00:42Z"), now)).toBe("42 s");
    expect(formatCountdown(now, now)).toBe("expired");
    expect(formatCountdown(new Date("2025-12-31T00:00:00Z"), now)).toBe("expired");
    expect(formatCountdown(new Date("not a date"), now)).toBe("expired");
  });

  it("formats times in a locale and passes junk through", () => {
    const s = formatTime("2026-03-04T05:06:00Z", "en-US");
    expect(s).toMatch(/2026/);
    expect(formatTime("junk")).toBe("junk");
  });

  it("describes retention policies", () => {
    expect(describeRetention("session")).toBe("only while the agent runs");
    expect(describeRetention("until-revoked")).toBe("until the agent deletes it");
    expect(describeRetention("until:2027-01-02T03:04:05Z")).toMatch(/^until .*2027/);
    expect(describeRetention("custom")).toBe("custom");
  });

  it("keeps the secret limit under the envelope limit", () => {
    expect(MAX_SECRET_BYTES).toBeLessThan(64 * 1024);
  });
});

describe("relay error messages", () => {
  it("has a sentence for each known code and a fallback", () => {
    expect(relayErrorMessage("network", "")).toMatch(/could not be reached/);
    expect(relayErrorMessage("rate_limited", "")).toMatch(/Too many requests/);
    expect(relayErrorMessage("commitment_mismatch", "")).toMatch(/altered/);
    expect(relayErrorMessage("too_large", "")).toMatch(/too large/);
    expect(relayErrorMessage("bad_request", "field x")).toBe("The relay rejected the request: field x");
    expect(relayErrorMessage("missing_client_header", "")).toBe("The relay rejected the request.");
    expect(relayErrorMessage("store_full", "")).toBe("The relay answered store_full.");
    expect(relayErrorMessage("store_full", "no room")).toBe("The relay answered store_full: no room");
  });
});
