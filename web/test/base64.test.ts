import { describe, expect, it } from "vitest";
import { Base64Error, decode, encode, isValid } from "../src/base64.js";

function bytes(...b: number[]): Uint8Array {
  return new Uint8Array(b);
}

describe("base64url", () => {
  it("round-trips every length up to 70 bytes against Node", () => {
    for (let n = 0; n <= 70; n++) {
      const data = new Uint8Array(n);
      for (let i = 0; i < n; i++) data[i] = (i * 37 + n) & 0xff;
      const s = encode(data);
      expect(s).toBe(Buffer.from(data).toString("base64url"));
      expect(decode(s)).toEqual(data);
    }
  });

  it("encodes the RFC 4648 examples without padding", () => {
    expect(encode(new TextEncoder().encode(""))).toBe("");
    expect(encode(new TextEncoder().encode("f"))).toBe("Zg");
    expect(encode(new TextEncoder().encode("fo"))).toBe("Zm8");
    expect(encode(new TextEncoder().encode("foo"))).toBe("Zm9v");
    expect(encode(new TextEncoder().encode("foob"))).toBe("Zm9vYg");
    expect(encode(bytes(0xfb, 0xff))).toBe("-_8");
  });

  it("rejects padding, the standard alphabet, and bad lengths", () => {
    expect(() => decode("Zg==")).toThrow(Base64Error);
    expect(() => decode("-/8")).toThrow(Base64Error);
    expect(() => decode("+_8")).toThrow(Base64Error);
    expect(() => decode("Z")).toThrow(Base64Error);
    expect(() => decode("Zm9vY")).toThrow(Base64Error);
    expect(() => decode("Zgé")).toThrow(Base64Error);
    expect(() => decode("Zg ")).toThrow(Base64Error);
  });

  it("rejects non-canonical trailing bits", () => {
    // "Zh" decodes to 0x66 with leftover bits 0b0001 set; Go's strict mode rejects it.
    expect(() => decode("Zh")).toThrow(/non-canonical/);
    expect(() => decode("Zm8")).not.toThrow();
    expect(() => decode("Zm9")).toThrow(/non-canonical/);
    expect(() => decode("Zm-")).toThrow(/non-canonical/);
  });

  it("isValid mirrors decode", () => {
    expect(isValid("Zm9v")).toBe(true);
    expect(isValid("Zm9v=")).toBe(false);
    expect(isValid("")).toBe(true);
  });
});
