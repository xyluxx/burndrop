/**
 * Every section of spec/vectors.json is exercised here: sealed_box,
 * xchacha20poly1305, padding, fingerprint, envelope, reveal_aad, tokens, and
 * the header fields.
 */
import { describe, expect, it } from "vitest";

import {
  CryptoError,
  EnvelopeError,
  PAD_BLOCK,
  commitment,
  decodeEnvelope,
  decryptAead,
  decryptEnvelope,
  encodeBase64Url,
  encodeEnvelope,
  encryptAead,
  fingerprint,
  isValidToken,
  openEnvelope,
  openSealed,
  pad,
  publicKeyFromPrivate,
  revealAad,
  seal,
  sha256,
  unpad,
  validateEnvelope,
  type Envelope,
} from "../src/index.js";
import { b64, bytesEqual, loadVectors, utf8 } from "./helpers.js";

const v = loadVectors();

describe("vectors header", () => {
  it("has the expected version and block size", () => {
    expect(v.version).toBe(1);
    expect(v.pad_block).toBe(PAD_BLOCK);
    expect(v.sealed_box.length).toBeGreaterThan(0);
    expect(v.xchacha20poly1305.length).toBeGreaterThan(0);
    expect(v.padding.length).toBeGreaterThan(0);
    expect(v.fingerprint.length).toBeGreaterThan(0);
    expect(v.envelope.length).toBeGreaterThan(0);
    expect(v.reveal_aad.length).toBeGreaterThan(0);
    expect(v.tokens.length).toBeGreaterThan(0);
  });
});

describe("sealed_box vectors", () => {
  for (const s of v.sealed_box) {
    it(s.name, async () => {
      const pub = b64(s.recipient_public_key);
      const priv = b64(s.recipient_secret_key);
      // The public key must be the one libsodium derives from the secret key.
      expect(bytesEqual(await publicKeyFromPrivate(priv), pub)).toBe(true);
      const padded = await openSealed(pub, priv, b64(s.sealed));
      expect(bytesEqual(padded, b64(s.padded_plaintext))).toBe(true);
      const plain = unpad(padded, PAD_BLOCK);
      expect(bytesEqual(plain, b64(s.plaintext))).toBe(true);
      const env = decodeEnvelope(plain);
      expect(env.type).toBe("drop");
      const full = await openEnvelope(pub, priv, b64(s.sealed));
      expect(full).toEqual(env);
      // Encoding the decoded envelope reproduces the Go bytes exactly.
      expect(bytesEqual(encodeEnvelope(env), b64(s.plaintext))).toBe(true);
      // The envelope vector with the same name is this envelope.
      const ev = v.envelope.find((e) => e.name === s.name);
      expect(ev).toBeDefined();
      expect(env).toEqual(ev?.envelope);
      // A fresh seal to the same key opens with the same secret key.
      const resealed = await seal(pub, b64(s.padded_plaintext));
      expect(bytesEqual(await openSealed(pub, priv, resealed), padded)).toBe(true);
      // The wrong secret key fails. (Bit 0 of byte 0 is cleared by X25519
      // clamping, so a different bit is flipped.)
      const wrong = new Uint8Array(priv);
      wrong[1] ^= 0x10;
      await expect(openSealed(pub, wrong, b64(s.sealed))).rejects.toBeInstanceOf(CryptoError);
    });
  }
});

describe("xchacha20poly1305 vectors", () => {
  for (const a of v.xchacha20poly1305) {
    it(a.name, async () => {
      const key = b64(a.key);
      const blob = b64(a.blob);
      const nonce = b64(a.nonce);
      expect(bytesEqual(blob.subarray(0, 24), nonce)).toBe(true);
      const padded = await decryptAead(key, blob, b64(a.aad));
      expect(bytesEqual(padded, b64(a.plaintext))).toBe(true);
      // Deterministic encryption with the vector nonce reproduces the blob.
      const again = await encryptAead(key, b64(a.plaintext), b64(a.aad), { nonce });
      expect(bytesEqual(again, blob)).toBe(true);
      // Altered additional data is rejected.
      const alteredAad = new Uint8Array(b64(a.aad).length + 1);
      alteredAad.set(b64(a.aad));
      alteredAad[alteredAad.length - 1] = 0x78;
      await expect(decryptAead(key, blob, alteredAad)).rejects.toMatchObject({ code: "decrypt" });
      const env = await decryptEnvelope(key, blob, b64(a.aad));
      expect(env.type).toBe("reveal");
      // The envelope vector with the same name pads to this plaintext.
      const ev = v.envelope.find((e) => e.name === a.name);
      expect(ev).toBeDefined();
      expect(env).toEqual(ev?.envelope);
      expect(bytesEqual(pad(encodeEnvelope(env), PAD_BLOCK), b64(a.plaintext))).toBe(true);
      // The aad is the reveal aad of the display fields.
      const aadText = new TextDecoder().decode(b64(a.aad));
      const keeps = aadText.endsWith("\n1");
      expect(bytesEqual(revealAad(env.name, keeps), b64(a.aad))).toBe(true);
    });
  }
});

describe("padding vectors", () => {
  for (const p of v.padding) {
    it("pads and unpads " + String(b64(p.unpadded).length) + " bytes", () => {
      expect(bytesEqual(pad(b64(p.unpadded), p.block), b64(p.padded))).toBe(true);
      expect(bytesEqual(unpad(b64(p.padded), p.block), b64(p.unpadded))).toBe(true);
    });
  }
});

describe("fingerprint vectors", () => {
  for (const f of v.fingerprint) {
    it(f.fingerprint, async () => {
      const pub = b64(f.public_key);
      expect(await fingerprint(pub)).toBe(f.fingerprint);
      expect(await commitment(pub)).toBe(f.commitment);
    });
  }
});

describe("envelope vectors", () => {
  for (const e of v.envelope) {
    it(e.name + (e.valid ? " (valid)" : " (invalid)"), () => {
      const env = e.envelope as unknown as Envelope;
      const jsonBytes = utf8(JSON.stringify(e.envelope));
      if (e.valid) {
        expect(() => validateEnvelope(env)).not.toThrow();
        const encoded = encodeEnvelope(env);
        expect(decodeEnvelope(encoded)).toEqual(env);
        expect(decodeEnvelope(jsonBytes)).toEqual(env);
      } else {
        expect(() => validateEnvelope(env)).toThrow(EnvelopeError);
        expect(() => encodeEnvelope(env)).toThrow(EnvelopeError);
        expect(() => decodeEnvelope(jsonBytes)).toThrow(EnvelopeError);
      }
    });
  }
});

describe("reveal_aad vectors", () => {
  for (const a of v.reveal_aad) {
    it(a.name + " keeps_copy=" + String(a.keeps_copy), () => {
      expect(encodeBase64Url(revealAad(a.name, a.keeps_copy))).toBe(a.aad);
    });
  }
});

describe("token vectors", () => {
  for (const t of v.tokens) {
    it(JSON.stringify(t.token) + " valid=" + String(t.valid), async () => {
      expect(isValidToken(t.token)).toBe(t.valid);
      // The relay hashes the token string bytes, never the decoded bytes.
      expect(encodeBase64Url(await sha256(utf8(t.token)))).toBe(t.sha256);
    });
  }
});
