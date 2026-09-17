import sodium from "libsodium-wrappers";
import { describe, expect, it } from "vitest";

import {
  AEAD_OVERHEAD,
  CryptoError,
  EnvelopeError,
  KEY_SIZE,
  MAX_PLAINTEXT,
  NONCE_SIZE,
  PAD_BLOCK,
  SEALED_OVERHEAD,
  commitment,
  constantTimeEqual,
  decryptAead,
  decryptEnvelope,
  encodeBase64Url,
  encryptAead,
  encryptEnvelope,
  fingerprint,
  generateKeyPair,
  newSymmetricKey,
  openEnvelope,
  openSealed,
  pad,
  publicKeyFromPrivate,
  randomBytes,
  ready,
  revealAad,
  seal,
  sealEnvelope,
  sha256,
  sodiumVersion,
  unpad,
  zero,
  type Envelope,
} from "../src/index.js";
import { bytesEqual, utf8 } from "./helpers.js";

const dropEnvelope: Envelope = {
  v: 1,
  type: "drop",
  name: "openai-api-key",
  purpose: "Call the OpenAI API",
  storage: "the agent's process memory only",
  retention: "until-revoked",
  fingerprint: "0000-0000-0000-0000",
  format: "text",
  secret: "sk-test-value",
};

describe("keys and randomness", () => {
  it("generates 32 byte keypairs whose public key derives from the private key", async () => {
    await ready();
    const kp = await generateKeyPair();
    expect(kp.publicKey.length).toBe(KEY_SIZE);
    expect(kp.privateKey.length).toBe(KEY_SIZE);
    expect(bytesEqual(await publicKeyFromPrivate(kp.privateKey), kp.publicKey)).toBe(true);
    const other = await generateKeyPair();
    expect(bytesEqual(kp.privateKey, other.privateKey)).toBe(false);
  });

  it("rejects private keys of the wrong length", async () => {
    await expect(publicKeyFromPrivate(new Uint8Array(31))).rejects.toMatchObject({ code: "length" });
  });

  it("reports the libsodium version", async () => {
    expect(await sodiumVersion()).toMatch(/^\d+\.\d+\.\d+$/);
  });

  it("returns fresh symmetric keys and random bytes", async () => {
    const a = await newSymmetricKey();
    const b = await newSymmetricKey();
    expect(a.length).toBe(KEY_SIZE);
    expect(bytesEqual(a, b)).toBe(false);
    expect((await randomBytes(7)).length).toBe(7);
  });
});

describe("sealed boxes", () => {
  it("round trips and fails with the wrong key or altered ciphertext", async () => {
    const kp = await generateKeyPair();
    const msg = utf8("hello sealed box");
    const ct = await seal(kp.publicKey, msg);
    expect(ct.length).toBe(msg.length + SEALED_OVERHEAD);
    expect(bytesEqual(await openSealed(kp.publicKey, kp.privateKey, ct), msg)).toBe(true);
    const other = await generateKeyPair();
    await expect(openSealed(other.publicKey, other.privateKey, ct)).rejects.toMatchObject({ code: "decrypt" });
    const tampered = new Uint8Array(ct);
    tampered[tampered.length - 1] ^= 0x01;
    await expect(openSealed(kp.publicKey, kp.privateKey, tampered)).rejects.toBeInstanceOf(CryptoError);
    await expect(openSealed(kp.publicKey, kp.privateKey, ct.subarray(0, SEALED_OVERHEAD - 1))).rejects.toMatchObject({ code: "decrypt" });
  });

  it("checks key lengths", async () => {
    const kp = await generateKeyPair();
    await expect(seal(new Uint8Array(16), utf8("x"))).rejects.toMatchObject({ code: "length" });
    await expect(openSealed(new Uint8Array(16), kp.privateKey, new Uint8Array(64))).rejects.toMatchObject({ code: "length" });
    await expect(openSealed(kp.publicKey, new Uint8Array(33), new Uint8Array(64))).rejects.toMatchObject({ code: "length" });
  });
});

describe("xchacha20poly1305", () => {
  it("round trips with additional data and rejects any change", async () => {
    const key = await newSymmetricKey();
    const aad = revealAad("staging-db-url", true);
    const msg = utf8("postgres://example");
    const blob = await encryptAead(key, msg, aad);
    expect(blob.length).toBe(msg.length + AEAD_OVERHEAD);
    expect(bytesEqual(await decryptAead(key, blob, aad), msg)).toBe(true);
    const other = await encryptAead(key, msg, aad);
    expect(bytesEqual(other, blob)).toBe(false);
    const tampered = new Uint8Array(blob);
    tampered[NONCE_SIZE + 1] ^= 0x80;
    await expect(decryptAead(key, tampered, aad)).rejects.toMatchObject({ code: "decrypt" });
    await expect(decryptAead(key, blob, revealAad("staging-db-url", false))).rejects.toMatchObject({ code: "decrypt" });
    const wrongKey = new Uint8Array(key);
    wrongKey[3] ^= 1;
    await expect(decryptAead(wrongKey, blob, aad)).rejects.toMatchObject({ code: "decrypt" });
    await expect(decryptAead(key, blob.subarray(0, AEAD_OVERHEAD - 1), aad)).rejects.toMatchObject({ code: "decrypt" });
  });

  it("checks key and nonce lengths", async () => {
    await expect(encryptAead(new Uint8Array(31), utf8("x"), utf8("a"))).rejects.toMatchObject({ code: "length" });
    await expect(encryptAead(new Uint8Array(32), utf8("x"), utf8("a"), { nonce: new Uint8Array(12) })).rejects.toMatchObject({ code: "length" });
    await expect(decryptAead(new Uint8Array(1), new Uint8Array(64), utf8("a"))).rejects.toMatchObject({ code: "length" });
  });
});

describe("padding", () => {
  it("always adds at least one byte and fills to the block", () => {
    const empty = pad(new Uint8Array(0));
    expect(empty.length).toBe(PAD_BLOCK);
    expect(empty[0]).toBe(0x80);
    expect(empty.subarray(1).every((b) => b === 0)).toBe(true);
    const aligned = pad(new Uint8Array(PAD_BLOCK).fill(7));
    expect(aligned.length).toBe(2 * PAD_BLOCK);
    expect(aligned[PAD_BLOCK]).toBe(0x80);
    const one = pad(new Uint8Array([1]), 4);
    expect(Array.from(one)).toEqual([1, 0x80, 0, 0]);
    const three = pad(new Uint8Array([1, 2, 3]), 4);
    expect(Array.from(three)).toEqual([1, 2, 3, 0x80]);
  });

  it("unpads exactly what pad produced", () => {
    for (const n of [0, 1, 17, 255, 256, 257, 511, 512, 1000]) {
      const data = new Uint8Array(n).map((_, i) => (i * 7 + 3) & 0xff);
      expect(bytesEqual(unpad(pad(data)), data)).toBe(true);
    }
  });

  it("matches libsodium's sodium_pad on random inputs", async () => {
    await ready();
    for (let n = 0; n <= 600; n += 37) {
      const data = new Uint8Array(n);
      globalThis.crypto.getRandomValues(data);
      expect(bytesEqual(pad(data), sodium.pad(data, PAD_BLOCK))).toBe(true);
    }
  });

  it("rejects malformed padding like the Go implementation", () => {
    // Empty input.
    expect(() => unpad(new Uint8Array(0))).toThrow(CryptoError);
    // Length not a multiple of the block, even when a marker is present
    // (libsodium's sodium_unpad would accept this one).
    const odd = new Uint8Array(300);
    odd[299] = 0x80;
    expect(() => unpad(odd)).toThrow(CryptoError);
    // No marker in the last block.
    expect(() => unpad(new Uint8Array(PAD_BLOCK))).toThrow(CryptoError);
    // A non-zero byte after the marker.
    const trailing = pad(utf8("abc"));
    trailing[trailing.length - 1] = 0x01;
    expect(() => unpad(trailing)).toThrow(CryptoError);
    // A marker further back than one block.
    const far = new Uint8Array(2 * PAD_BLOCK);
    far[100] = 0x80;
    expect(() => unpad(far)).toThrow(CryptoError);
    // A 0x80 byte that is data, followed by a real marker, unpads to the data.
    const data = new Uint8Array([0x80, 0x80]);
    expect(bytesEqual(unpad(pad(data)), data)).toBe(true);
    // A lone marker at the very start of a single block is the empty message.
    expect(unpad(pad(new Uint8Array(0))).length).toBe(0);
    // Bad block sizes.
    expect(() => pad(new Uint8Array(1), 0)).toThrow(CryptoError);
    expect(() => unpad(new Uint8Array(4), -4)).toThrow(CryptoError);
    expect(() => unpad(new Uint8Array(4), 2.5)).toThrow(CryptoError);
  });
});

describe("hashing", () => {
  it("computes SHA-256, fingerprints, and commitments", async () => {
    const empty = await sha256(new Uint8Array(0));
    expect(encodeBase64Url(empty)).toBe("47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU");
    const fp = await fingerprint(new Uint8Array(32));
    expect(fp).toMatch(/^[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}$/);
    expect(fp).toBe("6668-7aad-f862-bd77");
    expect(await commitment(new Uint8Array(32))).toBe("Zmh6rfhivXdsj8GLjp-OIAiXFIVu4jOzkCpZHQ1fKSU");
    // A view into a larger buffer hashes only its own bytes.
    const big = new Uint8Array(64);
    expect(await fingerprint(big.subarray(16, 48))).toBe(fp);
  });
});

describe("helpers", () => {
  it("compares in constant time and zeroes buffers", () => {
    expect(constantTimeEqual(utf8("abc"), utf8("abc"))).toBe(true);
    expect(constantTimeEqual(utf8("abc"), utf8("abd"))).toBe(false);
    expect(constantTimeEqual(utf8("abc"), utf8("ab"))).toBe(false);
    expect(constantTimeEqual(new Uint8Array(0), new Uint8Array(0))).toBe(true);
    const a = utf8("secret");
    const b = utf8("other");
    zero(a, b);
    expect(a.every((x) => x === 0)).toBe(true);
    expect(b.every((x) => x === 0)).toBe(true);
  });
});

describe("envelope encryption", () => {
  it("seals and opens drop envelopes", async () => {
    const kp = await generateKeyPair();
    const sealed = await sealEnvelope(kp.publicKey, dropEnvelope);
    expect((sealed.length - SEALED_OVERHEAD) % PAD_BLOCK).toBe(0);
    expect(await openEnvelope(kp.publicKey, kp.privateKey, sealed)).toEqual(dropEnvelope);
    const other = await generateKeyPair();
    await expect(openEnvelope(other.publicKey, other.privateKey, sealed)).rejects.toMatchObject({ code: "decrypt" });
    await expect(sealEnvelope(kp.publicKey, { ...dropEnvelope, fingerprint: "nope" })).rejects.toBeInstanceOf(EnvelopeError);
  });

  it("encrypts and decrypts reveal envelopes bound to the display fields", async () => {
    const key = await newSymmetricKey();
    const env: Envelope = { v: 1, type: "reveal", name: "staging-db-url", format: "text", secret: "postgres://example" };
    const blob = await encryptEnvelope(key, env, revealAad(env.name, true));
    expect((blob.length - AEAD_OVERHEAD) % PAD_BLOCK).toBe(0);
    expect(await decryptEnvelope(key, blob, revealAad(env.name, true))).toEqual(env);
    await expect(decryptEnvelope(key, blob, revealAad(env.name, false))).rejects.toMatchObject({ code: "decrypt" });
    await expect(decryptEnvelope(key, blob, revealAad("other-name", true))).rejects.toMatchObject({ code: "decrypt" });
  });

  it("enforces the size limits before and after encryption", async () => {
    const kp = await generateKeyPair();
    const huge: Envelope = { v: 1, type: "reveal", name: "n", format: "text", secret: "x".repeat(MAX_PLAINTEXT) };
    await expect(sealEnvelope(kp.publicKey, huge)).rejects.toMatchObject({ code: "size" });
    await expect(encryptEnvelope(new Uint8Array(32), huge, utf8("a"))).rejects.toMatchObject({ code: "size" });
    await expect(openEnvelope(kp.publicKey, kp.privateKey, new Uint8Array(MAX_PLAINTEXT + PAD_BLOCK + SEALED_OVERHEAD + 1))).rejects.toMatchObject({ code: "size" });
    await expect(decryptEnvelope(new Uint8Array(32), new Uint8Array(MAX_PLAINTEXT + PAD_BLOCK + AEAD_OVERHEAD + 1), utf8("a"))).rejects.toMatchObject({ code: "size" });
    // A plaintext that is exactly at the limit is accepted.
    const atLimit: Envelope = { v: 1, type: "reveal", name: "n", format: "text", secret: "" };
    const overhead = new TextEncoder().encode(JSON.stringify(atLimit)).length;
    atLimit.secret = "x".repeat(MAX_PLAINTEXT - overhead);
    const key = await newSymmetricKey();
    const blob = await encryptEnvelope(key, atLimit, utf8("a"));
    expect((await decryptEnvelope(key, blob, utf8("a"))).secret.length).toBe(atLimit.secret.length);
  });

  it("rejects ciphertext whose plaintext has bad padding or a bad envelope", async () => {
    const kp = await generateKeyPair();
    const unpadded = await seal(kp.publicKey, utf8("{}"));
    await expect(openEnvelope(kp.publicKey, kp.privateKey, unpadded)).rejects.toMatchObject({ code: "padding" });
    const badJson = await seal(kp.publicKey, pad(utf8('{"v":1}')));
    await expect(openEnvelope(kp.publicKey, kp.privateKey, badJson)).rejects.toBeInstanceOf(EnvelopeError);
    const key = await newSymmetricKey();
    const blob = await encryptAead(key, pad(utf8("not json")), utf8("a"));
    await expect(decryptEnvelope(key, blob, utf8("a"))).rejects.toBeInstanceOf(EnvelopeError);
  });
});
