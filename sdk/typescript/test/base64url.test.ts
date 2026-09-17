import { describe, expect, it } from "vitest";

import { EncodingError, decodeBase64Url, encodeBase64Url, isBase64Url } from "../src/index.js";
import { bytesEqual } from "./helpers.js";

describe("base64url", () => {
  it("encodes without padding using the url alphabet", () => {
    expect(encodeBase64Url(new Uint8Array([]))).toBe("");
    expect(encodeBase64Url(new Uint8Array([0]))).toBe("AA");
    expect(encodeBase64Url(new Uint8Array([0, 0]))).toBe("AAA");
    expect(encodeBase64Url(new Uint8Array([0, 0, 0]))).toBe("AAAA");
    expect(encodeBase64Url(new Uint8Array([0xfb, 0xff]))).toBe("-_8");
    expect(encodeBase64Url(new Uint8Array([0xff, 0xff, 0xff, 0xff]))).toBe("_____w");
  });

  it("round trips every length up to a few blocks", () => {
    for (let n = 0; n <= 70; n++) {
      const bytes = new Uint8Array(n);
      globalThis.crypto.getRandomValues(bytes);
      const s = encodeBase64Url(bytes);
      expect(s).not.toContain("=");
      expect(s).not.toContain("+");
      expect(s).not.toContain("/");
      expect(bytesEqual(decodeBase64Url(s), bytes)).toBe(true);
      expect(isBase64Url(s)).toBe(true);
    }
  });

  it("rejects padding, the standard alphabet, whitespace, and other characters", () => {
    for (const bad of ["AA==", "AAA=", "AAAA+", "AAAA/", "AA A", "AAAA\n", "AAAA\r", "A*AA", "AAAA.", "é", "AAAA%3D"]) {
      expect(() => decodeBase64Url(bad), bad).toThrow(EncodingError);
      expect(isBase64Url(bad)).toBe(false);
    }
  });

  it("rejects a length of 1 modulo 4", () => {
    expect(() => decodeBase64Url("A")).toThrow(EncodingError);
    expect(() => decodeBase64Url("AAAAA")).toThrow(EncodingError);
  });

  it("rejects non-canonical trailing bits", () => {
    // "AB" leaves the low four bits of B set.
    expect(() => decodeBase64Url("AB")).toThrow(EncodingError);
    // "AAB" leaves the low two bits of B set.
    expect(() => decodeBase64Url("AAB")).toThrow(EncodingError);
    // The canonical forms decode.
    expect(bytesEqual(decodeBase64Url("AQ"), new Uint8Array([1]))).toBe(true);
    expect(bytesEqual(decodeBase64Url("AAE"), new Uint8Array([0, 1]))).toBe(true);
    // A 22 character token whose last character carries stray bits.
    expect(() => decodeBase64Url("AAAAAAAAAAAAAAAAAAAAAB")).toThrow(EncodingError);
    expect(decodeBase64Url("AAAAAAAAAAAAAAAAAAAAAA").length).toBe(16);
  });

  it("rejects characters outside ASCII", () => {
    expect(() => decodeBase64Url("AAAÄ")).toThrow(EncodingError);
  });
});
