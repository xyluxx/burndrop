// The audited cryptographic module of the drop page. It has no dependency
// other than libsodium-wrappers-sumo and WebCrypto SHA-256, no DOM access, and
// matches internal/crypto in Go byte for byte (spec/vectors.json).
//
// Primitives (docs/design.md section 5): libsodium sealed boxes for human to
// agent, XChaCha20-Poly1305-IETF with additional data for agent to human,
// ISO/IEC 7816-4 padding to 256 byte blocks, SHA-256 fingerprints and
// commitments, and a fixed JSON envelope.

import sodium from "libsodium-wrappers-sumo";
import * as b64 from "./base64.js";

export const KEY_SIZE = 32;
export const NONCE_SIZE = 24;
export const TAG_SIZE = 16;
export const SEALED_OVERHEAD = 48;
export const AEAD_OVERHEAD = NONCE_SIZE + TAG_SIZE;
export const PAD_BLOCK = 256;
export const MAX_PLAINTEXT = 64 * 1024;
export const MAX_NAME_LEN = 100;
export const MAX_TEXT_LEN = 200;
export const TOKEN_LEN = 22;

export class CryptoError extends Error {}
export class EnvelopeError extends Error {}

let readyPromise: Promise<void> | undefined;

/** ready resolves once libsodium is initialized. Call it before anything else. */
export function ready(): Promise<void> {
  if (!readyPromise) {
    readyPromise = sodium.ready.then(() => undefined);
  }
  return readyPromise;
}

export interface KeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

export function generateKeyPair(): KeyPair {
  const kp = sodium.crypto_box_keypair();
  return { publicKey: kp.publicKey, privateKey: kp.privateKey };
}

/** seal encrypts plaintext to a recipient public key (crypto_box_seal). */
export function seal(recipientPublicKey: Uint8Array, plaintext: Uint8Array): Uint8Array {
  requireLength(recipientPublicKey, KEY_SIZE, "public key");
  return sodium.crypto_box_seal(plaintext, recipientPublicKey);
}

export function openSealed(publicKey: Uint8Array, privateKey: Uint8Array, sealed: Uint8Array): Uint8Array {
  requireLength(publicKey, KEY_SIZE, "public key");
  requireLength(privateKey, KEY_SIZE, "private key");
  if (sealed.length < SEALED_OVERHEAD) {
    throw new CryptoError("sealed box too short");
  }
  try {
    return sodium.crypto_box_seal_open(sealed, publicKey, privateKey);
  } catch {
    throw new CryptoError("decryption failed");
  }
}

export function newSymmetricKey(): Uint8Array {
  return sodium.randombytes_buf(KEY_SIZE);
}

export function randomBytes(n: number): Uint8Array {
  return sodium.randombytes_buf(n);
}

/** encryptAead returns nonce || ciphertext || tag with a fresh random nonce. */
export function encryptAead(key: Uint8Array, plaintext: Uint8Array, aad: Uint8Array, nonce?: Uint8Array): Uint8Array {
  requireLength(key, KEY_SIZE, "key");
  const n = nonce ?? sodium.randombytes_buf(NONCE_SIZE);
  requireLength(n, NONCE_SIZE, "nonce");
  const ct = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, null, n, key);
  const out = new Uint8Array(n.length + ct.length);
  out.set(n, 0);
  out.set(ct, n.length);
  return out;
}

export function decryptAead(key: Uint8Array, blob: Uint8Array, aad: Uint8Array): Uint8Array {
  requireLength(key, KEY_SIZE, "key");
  if (blob.length < AEAD_OVERHEAD) {
    throw new CryptoError("ciphertext too short");
  }
  const nonce = blob.subarray(0, NONCE_SIZE);
  const ct = blob.subarray(NONCE_SIZE);
  try {
    return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ct, aad, nonce, key);
  } catch {
    throw new CryptoError("decryption failed");
  }
}

/** pad applies ISO/IEC 7816-4 padding: a 0x80 byte then zeros to a multiple of block. */
export function pad(data: Uint8Array, block: number = PAD_BLOCK): Uint8Array {
  const total = (Math.floor(data.length / block) + 1) * block;
  const out = new Uint8Array(total);
  out.set(data, 0);
  out[data.length] = 0x80;
  return out;
}

export function unpad(data: Uint8Array, block: number = PAD_BLOCK): Uint8Array {
  if (data.length === 0 || data.length % block !== 0) {
    throw new CryptoError("bad padding");
  }
  // The marker must be within the last block.
  for (let i = data.length - 1; i >= data.length - block; i--) {
    const c = data[i];
    if (c === 0x80) {
      return data.subarray(0, i);
    }
    if (c !== 0x00) {
      throw new CryptoError("bad padding");
    }
  }
  throw new CryptoError("bad padding");
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest("SHA-256", data as BufferSource);
  return new Uint8Array(digest);
}

const HEX = "0123456789abcdef";

/** fingerprint is the first 64 bits of SHA-256(publicKey) as xxxx-xxxx-xxxx-xxxx. */
export async function fingerprint(publicKey: Uint8Array): Promise<string> {
  const h = await sha256(publicKey);
  let hex = "";
  for (let i = 0; i < 8; i++) {
    const c = h[i] as number;
    hex += HEX[c >> 4]! + HEX[c & 15]!;
  }
  return `${hex.slice(0, 4)}-${hex.slice(4, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}`;
}

/** commitment is base64url(SHA-256(publicKey)), registered with the relay at slot creation. */
export async function commitment(publicKey: Uint8Array): Promise<string> {
  return b64.encode(await sha256(publicKey));
}

export const FINGERPRINT_RE = /^[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}$/;

export type EnvelopeType = "drop" | "reveal";
export type EnvelopeFormat = "text" | "base64";

export interface Envelope {
  v: 1;
  type: EnvelopeType;
  name: string;
  purpose?: string;
  storage?: string;
  retention?: string;
  fingerprint?: string;
  format: EnvelopeFormat;
  secret: string;
}

const RETENTION_RE = /^(session|until-revoked|until:\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2}))$/;

function runeCount(s: string): number {
  let n = 0;
  for (const _ of s) {
    n++;
  }
  return n;
}

function hasControl(s: string, allowNewline: boolean): boolean {
  for (const ch of s) {
    const c = ch.codePointAt(0) as number;
    if ((c < 0x20 && !(allowNewline && c === 0x0a)) || c === 0x7f) {
      return true;
    }
  }
  return false;
}

export function validateName(name: string): void {
  if (name === "" || runeCount(name) > MAX_NAME_LEN) {
    throw new EnvelopeError(`name must be 1 to ${MAX_NAME_LEN} characters`);
  }
  if (name.trim() !== name) {
    throw new EnvelopeError("name has leading or trailing whitespace");
  }
  if (hasControl(name, false)) {
    throw new EnvelopeError("name contains a control character");
  }
}

export function validateText(field: string, s: string): void {
  if (runeCount(s) > MAX_TEXT_LEN) {
    throw new EnvelopeError(`${field} longer than ${MAX_TEXT_LEN} characters`);
  }
  if (hasControl(s, true)) {
    throw new EnvelopeError(`${field} contains a control character`);
  }
}

export function validateRetention(policy: string): void {
  if (!RETENTION_RE.test(policy)) {
    throw new EnvelopeError("invalid retention policy");
  }
  if (policy.startsWith("until:") && !validRfc3339(policy.slice(6))) {
    throw new EnvelopeError("invalid retention date");
  }
}

/** validRfc3339 checks the calendar fields the way Go's time.Parse does. */
function validRfc3339(s: string): boolean {
  const y = Number(s.slice(0, 4));
  const mo = Number(s.slice(5, 7));
  const d = Number(s.slice(8, 10));
  const h = Number(s.slice(11, 13));
  const mi = Number(s.slice(14, 16));
  const sec = Number(s.slice(17, 19));
  if (mo < 1 || mo > 12 || d < 1 || h > 23 || mi > 59 || sec > 59) {
    return false;
  }
  if (new Date(Date.UTC(y, mo - 1, d)).getUTCDate() !== d) {
    return false;
  }
  if (s.length > 19 && s[19] !== "Z") {
    const off = s.slice(-6);
    const oh = Number(off.slice(1, 3));
    const om = Number(off.slice(4, 6));
    if (off[0] === "Z" || oh > 23 || om > 59) {
      return false;
    }
  }
  return !Number.isNaN(Date.parse(s));
}

export function validateEnvelope(e: Envelope): void {
  if (e.v !== 1) {
    throw new EnvelopeError("unsupported envelope version");
  }
  if (e.type !== "drop" && e.type !== "reveal") {
    throw new EnvelopeError("unknown envelope type");
  }
  if (e.format !== "text" && e.format !== "base64") {
    throw new EnvelopeError("unknown format");
  }
  validateName(e.name);
  validateText("purpose", e.purpose ?? "");
  validateText("storage", e.storage ?? "");
  if (e.type === "drop") {
    validateRetention(e.retention ?? "");
    if (!FINGERPRINT_RE.test(e.fingerprint ?? "")) {
      throw new EnvelopeError("malformed fingerprint");
    }
  } else if (e.retention || e.fingerprint || e.purpose || e.storage) {
    throw new EnvelopeError("reveal envelopes carry no drop metadata");
  }
  if (e.format === "base64") {
    if (!b64.isValid(e.secret)) {
      throw new EnvelopeError("secret is not base64url");
    }
  } else if (!isValidUtf8(e.secret)) {
    throw new EnvelopeError("secret is not valid UTF-8");
  }
}

function isValidUtf8(s: string): boolean {
  // A JavaScript string fails to encode as UTF-8 only when it contains a
  // lone surrogate, which JSON.parse lets through as an escape.
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const d = i + 1 < s.length ? s.charCodeAt(i + 1) : 0;
      if (d < 0xdc00 || d > 0xdfff) {
        return false;
      }
      i++;
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      return false;
    }
  }
  return true;
}

/**
 * encodeEnvelope validates and serializes with the same field order and
 * omissions as the Go encoder, so the bytes match across languages.
 */
export function encodeEnvelope(e: Envelope): Uint8Array {
  validateEnvelope(e);
  const ordered: Record<string, unknown> = { v: 1, type: e.type, name: e.name };
  if (e.purpose) ordered["purpose"] = e.purpose;
  if (e.storage) ordered["storage"] = e.storage;
  if (e.retention) ordered["retention"] = e.retention;
  if (e.fingerprint) ordered["fingerprint"] = e.fingerprint;
  ordered["format"] = e.format;
  ordered["secret"] = e.secret;
  // Go escapes U+2028 and U+2029 even with HTML escaping off.
  const bs = String.fromCharCode(92);
  const json = JSON.stringify(ordered)
    .replace(new RegExp(String.fromCharCode(0x2028), "g"), bs + "u2028")
    .replace(new RegExp(String.fromCharCode(0x2029), "g"), bs + "u2029");
  return new TextEncoder().encode(json);
}

const KNOWN_FIELDS = new Set(["v", "type", "name", "purpose", "storage", "retention", "fingerprint", "format", "secret"]);

export function decodeEnvelope(bytes: Uint8Array): Envelope {
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new EnvelopeError("envelope is not valid JSON");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new EnvelopeError("envelope is not an object");
  }
  const obj = parsed as Record<string, unknown>;
  for (const key of Object.keys(obj)) {
    if (!KNOWN_FIELDS.has(key)) {
      throw new EnvelopeError(`unknown envelope field ${key}`);
    }
  }
  const str = (k: string): string => {
    const v = obj[k];
    if (v === undefined) return "";
    if (typeof v !== "string") throw new EnvelopeError(`field ${k} must be a string`);
    return v;
  };
  if (obj["v"] !== 1) {
    throw new EnvelopeError("unsupported envelope version");
  }
  const e: Envelope = {
    v: 1,
    type: str("type") as EnvelopeType,
    name: str("name"),
    format: str("format") as EnvelopeFormat,
    secret: str("secret"),
  };
  const purpose = str("purpose");
  const storage = str("storage");
  const retention = str("retention");
  const fp = str("fingerprint");
  if (purpose) e.purpose = purpose;
  if (storage) e.storage = storage;
  if (retention) e.retention = retention;
  if (fp) e.fingerprint = fp;
  validateEnvelope(e);
  return e;
}

/** secretBytes returns the secret as raw bytes. */
export function secretBytes(e: Envelope): Uint8Array {
  return e.format === "base64" ? b64.decode(e.secret) : new TextEncoder().encode(e.secret);
}

/** setSecret stores text as text and anything else as base64. */
export function secretFromBytes(value: Uint8Array): { format: EnvelopeFormat; secret: string } {
  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(value);
    for (const ch of text) {
      const c = ch.codePointAt(0) as number;
      if (c < 0x20 && c !== 0x09 && c !== 0x0a && c !== 0x0d) {
        return { format: "base64", secret: b64.encode(value) };
      }
    }
    return { format: "text", secret: text };
  } catch {
    return { format: "base64", secret: b64.encode(value) };
  }
}

/** revealAad is the additional data for a reveal: the display fields joined behind a domain string. */
export function revealAad(name: string, keepsCopy: boolean): Uint8Array {
  return new TextEncoder().encode(`burndrop/reveal/v1\n${name}\n${keepsCopy ? "1" : "0"}`);
}

export function sealEnvelope(recipientPublicKey: Uint8Array, e: Envelope): Uint8Array {
  const plain = encodeEnvelope(e);
  if (plain.length > MAX_PLAINTEXT) {
    throw new CryptoError("envelope too large");
  }
  const padded = pad(plain);
  const out = seal(recipientPublicKey, padded);
  sodium.memzero(padded);
  sodium.memzero(plain);
  return out;
}

export function openEnvelope(publicKey: Uint8Array, privateKey: Uint8Array, sealed: Uint8Array): Envelope {
  if (sealed.length > MAX_PLAINTEXT + PAD_BLOCK + SEALED_OVERHEAD) {
    throw new CryptoError("sealed box too large");
  }
  const padded = openSealed(publicKey, privateKey, sealed);
  const plain = unpad(padded);
  const e = decodeEnvelope(plain);
  sodium.memzero(padded);
  return e;
}

export function encryptEnvelope(key: Uint8Array, e: Envelope, aad: Uint8Array, nonce?: Uint8Array): Uint8Array {
  const plain = encodeEnvelope(e);
  if (plain.length > MAX_PLAINTEXT) {
    throw new CryptoError("envelope too large");
  }
  const padded = pad(plain);
  const out = encryptAead(key, padded, aad, nonce);
  sodium.memzero(padded);
  sodium.memzero(plain);
  return out;
}

export function decryptEnvelope(key: Uint8Array, blob: Uint8Array, aad: Uint8Array): Envelope {
  if (blob.length > MAX_PLAINTEXT + PAD_BLOCK + AEAD_OVERHEAD) {
    throw new CryptoError("ciphertext too large");
  }
  const padded = decryptAead(key, blob, aad);
  const plain = unpad(padded);
  const e = decodeEnvelope(plain);
  sodium.memzero(padded);
  return e;
}

export function zero(buf: Uint8Array): void {
  sodium.memzero(buf);
}

// Password-protected reveals (docs/crypto-spec.md section 4.1): the link
// carries a key and a salt, and the real key mixes in Argon2id of the
// password the human set. Parameters are libsodium's interactive limits.
export const SALT_SIZE = 16;
export const PASSWORD_OPSLIMIT = 2;
export const PASSWORD_MEMLIMIT = 64 * 1024 * 1024;
const PASSWORD_DOMAIN = "burndrop/reveal-password/v1";

/** passwordKey derives 32 bytes from a password with Argon2id 1.3 (time 2, memory 64 MiB, one lane). */
export function passwordKey(password: string, salt: Uint8Array): Uint8Array {
  if (password === "") {
    throw new CryptoError("password must not be empty");
  }
  requireLength(salt, SALT_SIZE, "salt");
  return sodium.crypto_pwhash(KEY_SIZE, new TextEncoder().encode(password), salt, PASSWORD_OPSLIMIT, PASSWORD_MEMLIMIT, sodium.crypto_pwhash_ALG_ARGON2ID13);
}

/** revealKeyWithPassword is BLAKE2b-256(domain || linkKey || passwordKey), the key of a password-protected reveal. */
export function revealKeyWithPassword(linkKey: Uint8Array, password: string, salt: Uint8Array): Uint8Array {
  requireLength(linkKey, KEY_SIZE, "key");
  const pk = passwordKey(password, salt);
  const domain = new TextEncoder().encode(PASSWORD_DOMAIN);
  const msg = new Uint8Array(domain.length + KEY_SIZE * 2);
  msg.set(domain, 0);
  msg.set(linkKey, domain.length);
  msg.set(pk, domain.length + KEY_SIZE);
  const out = sodium.crypto_generichash(KEY_SIZE, msg, null);
  sodium.memzero(msg);
  sodium.memzero(pk);
  return out;
}

/** validToken reports whether s is a 22 character base64url token (16 bytes). */
export function validToken(s: string): boolean {
  if (s.length !== TOKEN_LEN) {
    return false;
  }
  try {
    return b64.decode(s).length === 16;
  } catch {
    return false;
  }
}

export function validCommitment(s: string): boolean {
  if (s.length !== 43) {
    return false;
  }
  try {
    return b64.decode(s).length === 32;
  } catch {
    return false;
  }
}

function requireLength(buf: Uint8Array, n: number, what: string): void {
  if (buf.length !== n) {
    throw new CryptoError(`${what} must be ${n} bytes`);
  }
}
