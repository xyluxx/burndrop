import { describe, expect, it } from "vitest";

import { MIN_REDACT_LEN, Redactor, pathEscape, trimGoSpace } from "../src/index.js";
import { utf8 } from "./helpers.js";

describe("Redactor", () => {
  it("replaces the raw value and its encodings", () => {
    const r = new Redactor();
    r.add("api-key", utf8("super-secret-value"));
    // 18 bytes: base64 needs no padding and the value has no characters that
    // url, path, or JSON escaping would change, so three distinct forms remain
    // (raw, base64, hex), exactly as in the Go redactor.
    expect(r.count).toBe(3);
    expect(r.redact("key=super-secret-value;")).toBe("key=[redacted:api-key];");
    // Standard base64 with and without padding, url-safe, hex.
    expect(r.redact("c3VwZXItc2VjcmV0LXZhbHVl")).toBe("[redacted:api-key]");
    expect(r.redact(Buffer.from("super-secret-value").toString("base64"))).toBe("[redacted:api-key]");
    expect(r.redact(Buffer.from("super-secret-value").toString("base64url"))).toBe("[redacted:api-key]");
    expect(r.redact(Buffer.from("super-secret-value").toString("hex"))).toBe("[redacted:api-key]");
    // Unrelated text is untouched.
    expect(r.redact("nothing to see")).toBe("nothing to see");
    expect(r.redact("")).toBe("");
  });

  it("covers url, path, json, and trimmed forms", () => {
    const r = new Redactor();
    r.add("token", " a value/with <odd> chars \n");
    expect(r.redact("q=" + encodeURIComponent(" a value/with <odd> chars \n"))).toContain("[redacted:token]");
    expect(r.redact("q=+a+value%2Fwith+%3Codd%3E+chars+%0A")).toBe("q=[redacted:token]");
    expect(r.redact("/p/" + pathEscape(" a value/with <odd> chars \n"))).toBe("/p/[redacted:token]");
    // Go's json.Marshal form: quotes stripped, HTML escaped.
    const BS = String.fromCharCode(92);
    expect(r.redact('{"v":" a value/with ' + BS + "u003codd" + BS + "u003e chars " + BS + 'n"}')).toBe('{"v":"[redacted:token]"}');
    // The trimmed form is registered when it differs.
    expect(r.redact("a value/with <odd> chars")).toBe("[redacted:token]");
  });

  it("ignores short values so ordinary text is not masked", () => {
    const r = new Redactor();
    r.add("pin", "12345");
    expect(r.count).toBe(0);
    expect(r.redact("12345")).toBe("12345");
    r.add("six", "123456");
    expect(r.count).toBeGreaterThan(0);
    expect(MIN_REDACT_LEN).toBe(6);
  });

  it("forgets values by name and replaces longer forms first", () => {
    const r = new Redactor();
    r.add("a", "secret-one");
    r.add("b", "secret-one-longer");
    expect(r.redact("secret-one-longer and secret-one")).toBe("[redacted:b] and [redacted:a]");
    r.remove("b");
    expect(r.redact("secret-one-longer")).toBe("[redacted:a]-longer");
    r.remove("a");
    expect(r.count).toBe(0);
  });

  it("accepts strings and bytes and does not register a form twice", () => {
    const r = new Redactor();
    r.add("x", "same-value-here");
    const n = r.count;
    r.add("y", utf8("same-value-here"));
    expect(r.count).toBe(n);
    expect(r.redact("same-value-here")).toBe("[redacted:x]");
  });

  it("helpers escape and trim like Go", () => {
    expect(pathEscape("a b/c;d,e?f$g&h+i:j=k@l~m")).toBe("a%20b%2Fc%3Bd%2Ce%3Ff$g&h+i:j=k@l~m");
    expect(trimGoSpace("  x y\t\n")).toBe("x y");
    expect(trimGoSpace(String.fromCharCode(0xa0) + "x" + String.fromCharCode(0x3000))).toBe("x");
    expect(trimGoSpace("   ")).toBe("");
  });
});
