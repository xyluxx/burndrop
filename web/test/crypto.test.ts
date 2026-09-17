// Runs the shared vectors in spec/vectors.json against the page's crypto
// module and exercises every error branch, so the file stays at 100 percent.
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import * as b64 from "../src/base64.js";
import * as c from "../src/crypto.js";

interface Vectors {
  pad_block: number;
  sealed_box: Array<{ name: string; recipient_public_key: string; recipient_secret_key: string; sealed: string; padded_plaintext: string; plaintext: string }>;
  xchacha20poly1305: Array<{ name: string; key: string; nonce: string; aad: string; plaintext: string; blob: string }>;
  padding: Array<{ block: number; unpadded: string; padded: string }>;
  fingerprint: Array<{ public_key: string; fingerprint: string; commitment: string }>;
  envelope: Array<{ name: string; envelope: Record<string, unknown>; valid: boolean }>;
  reveal_aad: Array<{ name: string; keeps_copy: boolean; aad: string }>;
  tokens: Array<{ token: string; sha256: string; valid: boolean }>;
}

const here = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(readFileSync(join(here, "..", "..", "spec", "vectors.json"), "utf8")) as Vectors;
const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);
const dec = b64.decode;

function envelopeOf(v: Vectors["envelope"][number]): c.Envelope {
  return v.envelope as unknown as c.Envelope;
}

beforeAll(async () => {
  await c.ready();
  await c.ready(); // the second call reuses the promise
});

describe("spec vectors", () => {
  it("uses the same padding block", () => {
    expect(c.PAD_BLOCK).toBe(vectors.pad_block);
  });

  it.each(vectors.sealed_box.map((v) => [v.name, v] as const))("sealed box: %s", (_name, v) => {
    const pk = dec(v.recipient_public_key);
    const sk = dec(v.recipient_secret_key);
    const padded = c.openSealed(pk, sk, dec(v.sealed));
    expect(padded).toEqual(dec(v.padded_plaintext));
    const plain = c.unpad(padded);
    expect(plain).toEqual(dec(v.plaintext));
    const env = c.decodeEnvelope(plain);
    // Encoding is byte for byte identical to Go, field order and escaping included.
    expect(c.encodeEnvelope(env)).toEqual(dec(v.plaintext));
    // Our own sealed boxes open on the agent side.
    expect(c.openEnvelope(pk, sk, c.sealEnvelope(pk, env))).toEqual(env);
    expect(c.openEnvelope(pk, sk, dec(v.sealed))).toEqual(env);
  });

  it.each(vectors.xchacha20poly1305.map((v) => [v.name, v] as const))("xchacha20poly1305: %s", (_name, v) => {
    const key = dec(v.key);
    const aad = dec(v.aad);
    expect(c.encryptAead(key, dec(v.plaintext), aad, dec(v.nonce))).toEqual(dec(v.blob));
    expect(c.decryptAead(key, dec(v.blob), aad)).toEqual(dec(v.plaintext));
    expect(() => c.decryptAead(key, dec(v.blob), utf8("other"))).toThrow(c.CryptoError);
    const env = c.decryptEnvelope(key, dec(v.blob), aad);
    expect(c.decodeEnvelope(c.unpad(dec(v.plaintext)))).toEqual(env);
    expect(c.encryptEnvelope(key, env, aad, dec(v.nonce))).toEqual(dec(v.blob));
  });

  it.each(vectors.padding.map((v, i) => [i, v] as const))("padding %i", (_i, v) => {
    expect(c.pad(dec(v.unpadded), v.block)).toEqual(dec(v.padded));
    expect(c.unpad(dec(v.padded), v.block)).toEqual(dec(v.unpadded));
  });

  it.each(vectors.fingerprint.map((v) => [v.fingerprint, v] as const))("fingerprint %s", async (_fp, v) => {
    const pk = dec(v.public_key);
    expect(await c.fingerprint(pk)).toBe(v.fingerprint);
    expect(await c.commitment(pk)).toBe(v.commitment);
    expect(c.validCommitment(v.commitment)).toBe(true);
  });

  it.each(vectors.envelope.map((v) => [v.name, v] as const))("envelope: %s", (_name, v) => {
    if (v.valid) {
      const env = envelopeOf(v);
      expect(() => c.validateEnvelope(env)).not.toThrow();
      expect(c.decodeEnvelope(c.encodeEnvelope(env))).toEqual(normalize(env));
    } else {
      expect(() => c.validateEnvelope(envelopeOf(v))).toThrow(c.EnvelopeError);
      expect(() => c.encodeEnvelope(envelopeOf(v))).toThrow(c.EnvelopeError);
    }
  });

  it.each(vectors.reveal_aad.map((v) => [v.name, v] as const))("reveal aad: %s", (_name, v) => {
    expect(c.revealAad(v.name, v.keeps_copy)).toEqual(dec(v.aad));
  });

  it.each(vectors.tokens.map((v) => [v.token, v] as const))("token %s", async (_t, v) => {
    expect(c.validToken(v.token)).toBe(v.valid);
    expect(b64.encode(await c.sha256(utf8(v.token)))).toBe(v.sha256);
  });
});

function normalize(e: c.Envelope): c.Envelope {
  const out: c.Envelope = { v: 1, type: e.type, name: e.name, format: e.format, secret: e.secret };
  if (e.purpose) out.purpose = e.purpose;
  if (e.storage) out.storage = e.storage;
  if (e.retention) out.retention = e.retention;
  if (e.fingerprint) out.fingerprint = e.fingerprint;
  return out;
}

const dropEnvelope = (): c.Envelope => ({
  v: 1,
  type: "drop",
  name: "api-key",
  purpose: "why",
  storage: "where",
  retention: "until-revoked",
  fingerprint: "0123-4567-89ab-cdef",
  format: "text",
  secret: "s3cret",
});

describe("primitives", () => {
  it("generates keys and round-trips a sealed box", () => {
    const kp = c.generateKeyPair();
    expect(kp.publicKey.length).toBe(c.KEY_SIZE);
    expect(kp.privateKey.length).toBe(c.KEY_SIZE);
    const sealed = c.seal(kp.publicKey, utf8("hello"));
    expect(sealed.length).toBe(5 + c.SEALED_OVERHEAD);
    expect(c.openSealed(kp.publicKey, kp.privateKey, sealed)).toEqual(utf8("hello"));
    const other = c.generateKeyPair();
    expect(() => c.openSealed(other.publicKey, other.privateKey, sealed)).toThrow(/decryption failed/);
    expect(() => c.openSealed(kp.publicKey, kp.privateKey, sealed.subarray(0, 10))).toThrow(/too short/);
    expect(() => c.seal(new Uint8Array(31), utf8("x"))).toThrow(/public key must be 32/);
    expect(() => c.openSealed(new Uint8Array(3), kp.privateKey, sealed)).toThrow(c.CryptoError);
    expect(() => c.openSealed(kp.publicKey, new Uint8Array(3), sealed)).toThrow(c.CryptoError);
  });

  it("encrypts with fresh nonces and rejects tampering", () => {
    const key = c.newSymmetricKey();
    expect(key.length).toBe(c.KEY_SIZE);
    expect(c.randomBytes(7).length).toBe(7);
    const aad = utf8("aad");
    const a = c.encryptAead(key, utf8("m"), aad);
    const b = c.encryptAead(key, utf8("m"), aad);
    expect(a).not.toEqual(b);
    expect(a.length).toBe(1 + c.AEAD_OVERHEAD);
    expect(c.decryptAead(key, a, aad)).toEqual(utf8("m"));
    a[a.length - 1] = (a[a.length - 1] as number) ^ 1;
    expect(() => c.decryptAead(key, a, aad)).toThrow(/decryption failed/);
    expect(() => c.decryptAead(key, new Uint8Array(10), aad)).toThrow(/too short/);
    expect(() => c.encryptAead(new Uint8Array(1), utf8("m"), aad)).toThrow(/key must be 32/);
    expect(() => c.encryptAead(key, utf8("m"), aad, new Uint8Array(5))).toThrow(/nonce must be 24/);
    expect(() => c.decryptAead(new Uint8Array(1), a, aad)).toThrow(c.CryptoError);
  });

  it("pads and detects bad padding", () => {
    expect(c.pad(new Uint8Array(0)).length).toBe(c.PAD_BLOCK);
    expect(c.pad(new Uint8Array(c.PAD_BLOCK - 1)).length).toBe(c.PAD_BLOCK);
    expect(c.pad(new Uint8Array(c.PAD_BLOCK)).length).toBe(2 * c.PAD_BLOCK);
    expect(() => c.unpad(new Uint8Array(0))).toThrow(/bad padding/);
    expect(() => c.unpad(new Uint8Array(100))).toThrow(/bad padding/);
    expect(() => c.unpad(new Uint8Array(c.PAD_BLOCK))).toThrow(/bad padding/); // no marker
    const trailing = c.pad(utf8("x"));
    trailing[trailing.length - 1] = 1;
    expect(() => c.unpad(trailing)).toThrow(/bad padding/);
    expect(c.unpad(c.pad(utf8("abc"), 4), 4)).toEqual(utf8("abc"));
  });

  it("zeroes buffers", () => {
    const buf = new Uint8Array([1, 2, 3]);
    c.zero(buf);
    expect(buf).toEqual(new Uint8Array(3));
  });

  it("validates tokens and commitments", () => {
    expect(c.validToken("AAAAAAAAAAAAAAAAAAAAAA")).toBe(true);
    expect(c.validToken("AAAAAAAAAAAAAAAAAAAAA")).toBe(false);
    expect(c.validToken("AAAAAAAAAAAAAAAAAAAA+/")).toBe(false);
    expect(c.validCommitment("A".repeat(43))).toBe(true);
    expect(c.validCommitment("A".repeat(42))).toBe(false);
    expect(c.validCommitment("+".repeat(43))).toBe(false);
  });
});

describe("envelope validation", () => {
  it("accepts the reference envelope and rejects each broken field", () => {
    expect(() => c.validateEnvelope(dropEnvelope())).not.toThrow();
    const broken: Array<[string, Partial<Record<keyof c.Envelope, unknown>>, RegExp]> = [
      ["version", { v: 2 }, /version/],
      ["type", { type: "other" }, /type/],
      ["format", { format: "hex" }, /format/],
      ["empty name", { name: "" }, /name must be/],
      ["long name", { name: "a".repeat(101) }, /name must be/],
      ["padded name", { name: " a" }, /whitespace/],
      ["control name", { name: "a" + String.fromCharCode(1) }, /control/],
      ["del name", { name: "a" + String.fromCharCode(0x7f) }, /control/],
      ["long purpose", { purpose: "p".repeat(201) }, /purpose longer/],
      ["control purpose", { purpose: "p" + String.fromCharCode(7) }, /purpose contains/],
      ["long storage", { storage: "s".repeat(201) }, /storage longer/],
      ["retention", { retention: "forever" }, /retention policy/],
      ["retention date", { retention: "until:2026-02-30T00:00:00Z" }, /retention date/],
      ["retention hour", { retention: "until:2026-02-01T24:00:00Z" }, /retention date/],
      ["retention offset", { retention: "until:2026-02-01T00:00:00+24:00" }, /retention date/],
      ["retention month", { retention: "until:2026-13-01T00:00:00Z" }, /retention date/],
      ["fingerprint", { fingerprint: "zzzz-0000-0000-0000" }, /fingerprint/],
      ["missing fingerprint", { fingerprint: undefined }, /fingerprint/],
      ["missing retention", { retention: undefined }, /retention policy/],
      ["base64 secret", { format: "base64", secret: "not*base64" }, /base64url/],
      ["lone surrogate", { secret: "a" + String.fromCharCode(0xd800) }, /UTF-8/],
      ["lone low surrogate", { secret: String.fromCharCode(0xdc00) + "a" }, /UTF-8/],
      ["high then non-low", { secret: String.fromCharCode(0xd800, 0x41) }, /UTF-8/],
    ];
    for (const [label, patch, re] of broken) {
      const env = { ...dropEnvelope(), ...patch } as c.Envelope;
      expect(() => c.validateEnvelope(env), label).toThrow(re);
    }
    const okPairs: Array<Partial<c.Envelope>> = [
      { purpose: "line\nline" },
      { retention: "until:2026-02-28T23:59:59.5+05:30" },
      { retention: "until:2026-02-28T23:59:59-08:00" },
      { retention: "session" },
      { secret: String.fromCharCode(0xd83d, 0xde00) },
      { name: "a".repeat(100) },
      { format: "base64", secret: b64.encode(new Uint8Array([0, 255])) },
    ];
    for (const patch of okPairs) {
      expect(() => c.validateEnvelope({ ...dropEnvelope(), ...patch }), JSON.stringify(patch)).not.toThrow();
    }
  });

  it("rejects reveal envelopes that carry drop metadata", () => {
    const reveal: c.Envelope = { v: 1, type: "reveal", name: "db", format: "text", secret: "x" };
    expect(() => c.validateEnvelope(reveal)).not.toThrow();
    for (const patch of [{ purpose: "p" }, { storage: "s" }, { retention: "session" }, { fingerprint: "0123-4567-89ab-cdef" }]) {
      expect(() => c.validateEnvelope({ ...reveal, ...patch })).toThrow(/no drop metadata/);
    }
  });

  it("encodes in Go field order, omitting empty fields and escaping line separators", () => {
    const text = new TextDecoder().decode(c.encodeEnvelope({ v: 1, type: "reveal", name: "n", format: "text", secret: "a" + String.fromCharCode(0x2028) + "b" + String.fromCharCode(0x2029) }));
    const bs = String.fromCharCode(92);
    expect(text).toBe(`{"v":1,"type":"reveal","name":"n","format":"text","secret":"a${bs}u2028b${bs}u2029"}`);
    const full = new TextDecoder().decode(c.encodeEnvelope(dropEnvelope()));
    expect(full).toBe('{"v":1,"type":"drop","name":"api-key","purpose":"why","storage":"where","retention":"until-revoked","fingerprint":"0123-4567-89ab-cdef","format":"text","secret":"s3cret"}');
  });

  it("decodes strictly", () => {
    const bad: Array<[string, string, RegExp]> = [
      ["not json", "{", /valid JSON/],
      ["invalid utf8", "", /valid JSON/],
      ["array", "[]", /not an object/],
      ["null", "null", /not an object/],
      ["unknown field", '{"v":1,"type":"reveal","name":"n","format":"text","secret":"s","extra":1}', /unknown envelope field extra/],
      ["non-string", '{"v":1,"type":"reveal","name":5,"format":"text","secret":"s"}', /field name must be a string/],
      ["version", '{"v":"1","type":"reveal","name":"n","format":"text","secret":"s"}', /version/],
      ["invalid", '{"v":1,"type":"reveal","name":"","format":"text","secret":"s"}', /name must be/],
    ];
    for (const [label, json, re] of bad) {
      const bytes = label === "invalid utf8" ? new Uint8Array([0xff, 0xfe]) : utf8(json);
      expect(() => c.decodeEnvelope(bytes), label).toThrow(re);
    }
    const env = c.decodeEnvelope(utf8('{"v":1,"type":"reveal","name":"n","format":"text","secret":"s","purpose":""}'));
    expect(env).toEqual({ v: 1, type: "reveal", name: "n", format: "text", secret: "s" });
  });

  it("extracts secret bytes in both formats", () => {
    expect(c.secretBytes({ v: 1, type: "reveal", name: "n", format: "text", secret: "hi" })).toEqual(utf8("hi"));
    expect(c.secretBytes({ v: 1, type: "reveal", name: "n", format: "base64", secret: "AAE" })).toEqual(new Uint8Array([0, 1]));
  });

  it("picks text for printable UTF-8 and base64 otherwise", () => {
    expect(c.secretFromBytes(utf8("plain\ttext\r\nline"))).toEqual({ format: "text", secret: "plain\ttext\r\nline" });
    expect(c.secretFromBytes(new Uint8Array([0x61, 0x00]))).toEqual({ format: "base64", secret: "YQA" });
    expect(c.secretFromBytes(new Uint8Array([0xff, 0xfe]))).toEqual({ format: "base64", secret: "__4" });
    expect(c.secretFromBytes(new Uint8Array([0x61, 0x7f]))).toEqual({ format: "text", secret: "a" + String.fromCharCode(0x7f) });
  });

  it("refuses envelopes above the plaintext limit in every direction", () => {
    const kp = c.generateKeyPair();
    const huge: c.Envelope = { v: 1, type: "reveal", name: "n", format: "text", secret: "x".repeat(c.MAX_PLAINTEXT) };
    expect(() => c.sealEnvelope(kp.publicKey, huge)).toThrow(/too large/);
    expect(() => c.encryptEnvelope(c.newSymmetricKey(), huge, utf8("a"))).toThrow(/too large/);
    const big = new Uint8Array(c.MAX_PLAINTEXT + c.PAD_BLOCK + c.SEALED_OVERHEAD + 1);
    expect(() => c.openEnvelope(kp.publicKey, kp.privateKey, big)).toThrow(/too large/);
    expect(() => c.decryptEnvelope(c.newSymmetricKey(), new Uint8Array(c.MAX_PLAINTEXT + c.PAD_BLOCK + c.AEAD_OVERHEAD + 1), utf8("a"))).toThrow(/too large/);
  });

  it("seals and opens a full envelope round trip", () => {
    const kp = c.generateKeyPair();
    const env = dropEnvelope();
    const sealed = c.sealEnvelope(kp.publicKey, env);
    expect(sealed.length).toBe(c.PAD_BLOCK + c.SEALED_OVERHEAD);
    expect(c.openEnvelope(kp.publicKey, kp.privateKey, sealed)).toEqual(env);
    const key = c.newSymmetricKey();
    const reveal: c.Envelope = { v: 1, type: "reveal", name: "db", format: "text", secret: "x" };
    const aad = c.revealAad("db", false);
    const blob = c.encryptEnvelope(key, reveal, aad);
    expect(c.decryptEnvelope(key, blob, aad)).toEqual(reveal);
    expect(() => c.decryptEnvelope(key, blob, c.revealAad("db", true))).toThrow(c.CryptoError);
  });
});
