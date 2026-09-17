// Password-protected reveals: the shared derivation vectors and the salt
// field of reveal links.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import * as b64 from "../src/base64.js";
import * as c from "../src/crypto.js";
import { buildRevealLink, parseRevealFragment } from "../src/link.js";

interface PasswordVector {
  name: string;
  password: string;
  salt: string;
  link_key: string;
  password_key: string;
  key: string;
}

const here = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(readFileSync(join(here, "..", "..", "spec", "vectors.json"), "utf8")) as { reveal_password: PasswordVector[] };

const ID = "AAAAAAAAAAAAAAAAAAAAAA";
const TOKEN = "MTIzNDU2Nzg5MGFiY2RlZg";
const ORIGIN = "https://drop.example.com";

describe("password-protected reveals", () => {
  beforeAll(() => c.ready());

  it("has vectors", () => {
    expect(vectors.reveal_password.length).toBeGreaterThan(0);
  });

  it.each(vectors.reveal_password.map((v) => [v.name, v] as const))(
    "vector: %s",
    (_name, v) => {
      const salt = b64.decode(v.salt);
      const linkKey = b64.decode(v.link_key);
      expect(b64.encode(c.passwordKey(v.password, salt))).toBe(v.password_key);
      expect(b64.encode(c.revealKeyWithPassword(linkKey, v.password, salt))).toBe(v.key);
      expect(b64.encode(c.revealKeyWithPassword(linkKey, v.password + "x", salt))).not.toBe(v.key);
    },
    60_000,
  );

  it("rejects an empty password and a salt of the wrong size", () => {
    expect(() => c.passwordKey("", new Uint8Array(c.SALT_SIZE))).toThrow(c.CryptoError);
    expect(() => c.passwordKey("pw", new Uint8Array(c.SALT_SIZE - 1))).toThrow(c.CryptoError);
  });

  it("carries the salt in the link and reads it back", () => {
    const key = c.newSymmetricKey();
    const salt = c.randomBytes(c.SALT_SIZE);
    const link = buildRevealLink(ORIGIN, { relay: null, id: ID, revealToken: TOKEN, key, name: "db", keepsCopy: true, salt });
    expect(link).toContain("&s=");
    const parsed = parseRevealFragment(link.slice(link.indexOf("#") + 1));
    expect(parsed.salt).toEqual(salt);
    expect(parsed.key).toEqual(key);

    const plain = buildRevealLink(ORIGIN, { relay: null, id: ID, revealToken: TOKEN, key, name: "db", keepsCopy: true });
    expect(plain).not.toContain("&s=");
    const frag = plain.slice(plain.indexOf("#") + 1);
    expect(parseRevealFragment(frag).salt).toBeNull();
    expect(() => parseRevealFragment(`${frag}&s=short`)).toThrow(/salt/);
    expect(() => parseRevealFragment(`${frag}&s=${"!".repeat(22)}`)).toThrow(/salt/);
  });
});
