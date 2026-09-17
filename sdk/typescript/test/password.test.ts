/**
 * Password-protected reveals: the shared derivation vectors and the salt
 * field of reveal links.
 */
import { describe, expect, it } from "vitest";

import {
  CryptoError,
  LinkError,
  SALT_SIZE,
  buildRevealLink,
  decodeBase64Url,
  encodeBase64Url,
  newSalt,
  newSymmetricKey,
  parseRevealLink,
  passwordKey,
  revealKeyWithPassword,
} from "../src/index.js";
import { loadVectors } from "./helpers.js";

interface PasswordVector {
  name: string;
  password: string;
  salt: string;
  link_key: string;
  password_key: string;
  key: string;
}

const v = loadVectors() as unknown as { reveal_password: PasswordVector[] };
const ID = "AAAAAAAAAAAAAAAAAAAAAA";
const TOKEN = "MTIzNDU2Nzg5MGFiY2RlZg";
const ORIGIN = "https://drop.example.com";

describe("password-protected reveals", () => {
  it("has vectors", () => {
    expect(v.reveal_password.length).toBeGreaterThan(0);
  });

  it.each(v.reveal_password.map((c) => [c.name, c] as const))(
    "vector: %s",
    async (_name, c) => {
      const salt = decodeBase64Url(c.salt);
      const linkKey = decodeBase64Url(c.link_key);
      expect(encodeBase64Url(await passwordKey(c.password, salt))).toBe(c.password_key);
      expect(encodeBase64Url(await revealKeyWithPassword(linkKey, c.password, salt))).toBe(c.key);
      expect(encodeBase64Url(await revealKeyWithPassword(linkKey, c.password + "x", salt))).not.toBe(c.key);
    },
    60_000,
  );

  it("rejects an empty password and a salt of the wrong size", async () => {
    await expect(passwordKey("", new Uint8Array(SALT_SIZE))).rejects.toBeInstanceOf(CryptoError);
    await expect(passwordKey("pw", new Uint8Array(SALT_SIZE - 1))).rejects.toBeInstanceOf(CryptoError);
    await expect(revealKeyWithPassword(new Uint8Array(31), "pw", new Uint8Array(SALT_SIZE))).rejects.toBeInstanceOf(CryptoError);
  });

  it("carries the salt in the link and reads it back", async () => {
    const key = await newSymmetricKey();
    const salt = await newSalt();
    const link = buildRevealLink({ id: ID, revealToken: TOKEN, key, name: "db", keepsCopy: true, salt }, ORIGIN);
    expect(link).toContain("&s=");
    const { reveal } = parseRevealLink(link);
    expect(reveal.salt).toEqual(salt);
    expect(reveal.key).toEqual(key);

    const plain = buildRevealLink({ id: ID, revealToken: TOKEN, key, name: "db", keepsCopy: true }, ORIGIN);
    expect(plain).not.toContain("&s=");
    expect(parseRevealLink(plain).reveal.salt).toBeUndefined();
    expect(() => parseRevealLink(plain + "&s=short")).toThrow(LinkError);
    expect(() => parseRevealLink(plain + "&s=" + "!".repeat(22))).toThrow(LinkError);
    expect(() => buildRevealLink({ id: ID, revealToken: TOKEN, key, name: "db", keepsCopy: true, salt: new Uint8Array(3) }, ORIGIN)).toThrow(LinkError);
  });
});
