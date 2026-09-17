/**
 * The cryptographic core of the burndrop TypeScript SDK.
 *
 * Every operation maps to one libsodium primitive, so the bytes produced here
 * are consumed unchanged by the Go implementation (golang.org/x/crypto) and
 * the Python SDK (PyNaCl), and vice versa. The shared vectors live in
 * spec/vectors.json.
 *
 * Two encryption paths exist and nothing else:
 *
 * - Drop (human to agent): a libsodium sealed box to the agent's per-request
 *   X25519 public key. Crypto spec section 5.3.
 * - Reveal (agent to human): XChaCha20-Poly1305 (IETF) under a random
 *   256-bit key with the display metadata as additional data. Section 5.4.
 *
 * Plaintext is always an Envelope, padded to a multiple of PAD_BLOCK bytes
 * with ISO/IEC 7816-4 padding before encryption, so the relay only learns a
 * coarse size class.
 *
 * The standard libsodium-wrappers build has no crypto_hash_sha256, so
 * fingerprints and commitments use WebCrypto's SHA-256, which every browser
 * and Node 22 provide as globalThis.crypto.subtle. Padding is implemented
 * here rather than with sodium_pad and sodium_unpad so that unpad enforces
 * exactly the Go rules (input length a positive multiple of the block).
 *
 * No Node-only imports: the browser page can reuse this module.
 */
import sodium from "libsodium-wrappers";

import { encodeBase64Url } from "./base64url.js";
import { CryptoError } from "./errors.js";
import { decodeEnvelope, encodeEnvelope, type Envelope } from "./envelope.js";

export * from "./base64url.js";
export * from "./envelope.js";

/** Size of X25519 keys and of XChaCha20-Poly1305 keys. */
export const KEY_SIZE = 32;
/** XChaCha20-Poly1305 nonce size (192 bits). */
export const NONCE_SIZE = 24;
/** Poly1305 authentication tag size. */
export const TAG_SIZE = 16;
/** Sealed box overhead: ephemeral public key (32) plus tag (16). */
export const SEALED_OVERHEAD = 48;
/** Reveal blob overhead: nonce (24) plus tag (16). */
export const AEAD_OVERHEAD = NONCE_SIZE + TAG_SIZE;
/** Padding block size (crypto spec section 5.1). */
export const PAD_BLOCK = 256;
/** Largest envelope accepted before padding. */
export const MAX_PLAINTEXT = 64 * 1024;

/** An X25519 keypair for one drop request. */
export interface KeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

/**
 * Resolves once libsodium's WebAssembly module is loaded. Every function in
 * this module awaits it internally; calling it once up front only moves the
 * one-time cost to a convenient moment.
 */
export async function ready(): Promise<void> {
  await sodium.ready;
}

/** The version of the libsodium build in use, for diagnostics. */
export async function sodiumVersion(): Promise<string> {
  await sodium.ready;
  return sodium.SODIUM_VERSION_STRING;
}

function requireLength(name: string, b: Uint8Array, n: number): void {
  if (b.length !== n) {
    throw new CryptoError("length", name + " must be " + String(n) + " bytes");
  }
}

/** Copies bytes into a fresh ArrayBuffer-backed Uint8Array for WebCrypto. */
function own(b: Uint8Array): Uint8Array<ArrayBuffer> {
  const copy = new Uint8Array(b.length);
  copy.set(b);
  return copy;
}

/** Returns n cryptographically random bytes. */
export async function randomBytes(n: number): Promise<Uint8Array> {
  await sodium.ready;
  return sodium.randombytes_buf(n);
}

/** Returns a fresh X25519 keypair for one drop request. */
export async function generateKeyPair(): Promise<KeyPair> {
  await sodium.ready;
  const kp = sodium.crypto_box_keypair();
  return { publicKey: kp.publicKey, privateKey: kp.privateKey };
}

/** Derives the X25519 public key of a private key (crypto_scalarmult_base). */
export async function publicKeyFromPrivate(privateKey: Uint8Array): Promise<Uint8Array> {
  await sodium.ready;
  requireLength("private key", privateKey, KEY_SIZE);
  return sodium.crypto_scalarmult_base(privateKey);
}

/**
 * Encrypts plaintext to recipientPublicKey as a libsodium sealed box
 * (crypto_box_seal): an ephemeral X25519 key is generated, the nonce is
 * BLAKE2b-24(ephemeral public key || recipient public key), and the output
 * is ephemeral public key || XSalsa20-Poly1305 ciphertext.
 */
export async function seal(recipientPublicKey: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array> {
  await sodium.ready;
  requireLength("recipient public key", recipientPublicKey, KEY_SIZE);
  return sodium.crypto_box_seal(plaintext, recipientPublicKey);
}

/** Decrypts a sealed box with the recipient keypair. */
export async function openSealed(publicKey: Uint8Array, privateKey: Uint8Array, sealed: Uint8Array): Promise<Uint8Array> {
  await sodium.ready;
  requireLength("public key", publicKey, KEY_SIZE);
  requireLength("private key", privateKey, KEY_SIZE);
  if (sealed.length < SEALED_OVERHEAD) {
    throw new CryptoError("decrypt", "decryption failed");
  }
  try {
    return sodium.crypto_box_seal_open(sealed, publicKey, privateKey);
  } catch {
    throw new CryptoError("decrypt", "decryption failed");
  }
}

/** Returns a random 256-bit key for one reveal. */
export async function newSymmetricKey(): Promise<Uint8Array> {
  await sodium.ready;
  return sodium.randombytes_buf(KEY_SIZE);
}

/**
 * Encrypts plaintext with XChaCha20-Poly1305 (IETF) and returns
 * nonce || ciphertext || tag, the wire format for reveal blobs. aad is
 * authenticated but not encrypted. A nonce may be supplied only to
 * reproduce test vectors; production callers must let it be random.
 */
export async function encryptAead(
  key: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
  options: { nonce?: Uint8Array } = {},
): Promise<Uint8Array> {
  await sodium.ready;
  requireLength("key", key, KEY_SIZE);
  const nonce = options.nonce ?? sodium.randombytes_buf(NONCE_SIZE);
  requireLength("nonce", nonce, NONCE_SIZE);
  const ct = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, null, nonce, key);
  const out = new Uint8Array(NONCE_SIZE + ct.length);
  out.set(nonce, 0);
  out.set(ct, NONCE_SIZE);
  return out;
}

/** Reverses encryptAead. Any modification of blob or aad fails. */
export async function decryptAead(key: Uint8Array, blob: Uint8Array, aad: Uint8Array): Promise<Uint8Array> {
  await sodium.ready;
  requireLength("key", key, KEY_SIZE);
  if (blob.length < AEAD_OVERHEAD) {
    throw new CryptoError("decrypt", "decryption failed");
  }
  try {
    return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, blob.subarray(NONCE_SIZE), aad, blob.subarray(0, NONCE_SIZE), key);
  } catch {
    throw new CryptoError("decrypt", "decryption failed");
  }
}

/**
 * Applies ISO/IEC 7816-4 padding: append 0x80, then 0x00 bytes up to the
 * next multiple of block. At least one byte is always added, so an input
 * that is already aligned grows by a full block. Identical to sodium_pad.
 */
export function pad(data: Uint8Array, block: number = PAD_BLOCK): Uint8Array {
  if (!Number.isInteger(block) || block <= 0) {
    throw new CryptoError("padding", "block size must be a positive integer");
  }
  const padLen = block - (data.length % block);
  const out = new Uint8Array(data.length + padLen);
  out.set(data);
  out[data.length] = 0x80;
  return out;
}

/**
 * Reverses pad. It scans back at most block bytes for the 0x80 marker and
 * rejects anything else. It runs on authenticated plaintext, so its timing
 * is not a concern.
 */
export function unpad(data: Uint8Array, block: number = PAD_BLOCK): Uint8Array {
  if (!Number.isInteger(block) || block <= 0) {
    throw new CryptoError("padding", "block size must be a positive integer");
  }
  if (data.length === 0 || data.length % block !== 0) {
    throw new CryptoError("padding", "invalid padding");
  }
  const stop = data.length - block;
  for (let i = data.length - 1; i >= stop; i--) {
    const b = data[i];
    if (b === 0x80) {
      return data.slice(0, i);
    }
    if (b !== 0x00) {
      break;
    }
  }
  throw new CryptoError("padding", "invalid padding");
}

/** SHA-256 via WebCrypto. */
export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const digest = await globalThis.crypto.subtle.digest("SHA-256", own(data));
  return new Uint8Array(digest);
}

const HEX = "0123456789abcdef";

/**
 * Returns the human-comparable fingerprint of a public key: the first 64
 * bits of SHA-256(key) as four groups of four lowercase hex characters, for
 * example "a1b2-c3d4-e5f6-a7b8". Crypto spec section 5.3 step 4.
 */
export async function fingerprint(publicKey: Uint8Array): Promise<string> {
  const sum = await sha256(publicKey);
  let hex = "";
  for (let i = 0; i < 8; i++) {
    hex += HEX[sum[i] >>> 4] + HEX[sum[i] & 0x0f];
  }
  return hex.slice(0, 4) + "-" + hex.slice(4, 8) + "-" + hex.slice(8, 12) + "-" + hex.slice(12, 16);
}

/**
 * Returns base64url(SHA-256(key)). The agent registers it with the relay
 * when it creates a slot and the page sends it again with the upload, so a
 * link whose key was altered in transit is rejected by an honest relay.
 */
export async function commitment(publicKey: Uint8Array): Promise<string> {
  return encodeBase64Url(await sha256(publicKey));
}

/**
 * Overwrites buffers with zeros. Best effort: JavaScript may hold other
 * copies (strings are immutable and cannot be zeroed at all).
 */
export function zero(...buffers: Uint8Array[]): void {
  for (const b of buffers) {
    b.fill(0);
  }
}

/**
 * Compares two byte strings without an early exit on the first difference.
 * Unequal lengths compare unequal immediately, as with libsodium's memcmp.
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

/** Encodes, pads, and seals an envelope to a recipient key. */
export async function sealEnvelope(recipientPublicKey: Uint8Array, env: Envelope): Promise<Uint8Array> {
  const plain = encodeEnvelope(env);
  if (plain.length > MAX_PLAINTEXT) {
    throw new CryptoError("size", "input too large");
  }
  const padded = pad(plain, PAD_BLOCK);
  try {
    return await seal(recipientPublicKey, padded);
  } finally {
    zero(padded, plain);
  }
}

/** Opens a sealed box, unpads, and decodes the envelope. */
export async function openEnvelope(publicKey: Uint8Array, privateKey: Uint8Array, sealed: Uint8Array): Promise<Envelope> {
  if (sealed.length > MAX_PLAINTEXT + PAD_BLOCK + SEALED_OVERHEAD) {
    throw new CryptoError("size", "input too large");
  }
  const padded = await openSealed(publicKey, privateKey, sealed);
  try {
    const plain = unpad(padded, PAD_BLOCK);
    try {
      return decodeEnvelope(plain);
    } finally {
      zero(plain);
    }
  } finally {
    zero(padded);
  }
}

/** Encodes, pads, and encrypts an envelope for a reveal. */
export async function encryptEnvelope(key: Uint8Array, env: Envelope, aad: Uint8Array): Promise<Uint8Array> {
  const plain = encodeEnvelope(env);
  if (plain.length > MAX_PLAINTEXT) {
    throw new CryptoError("size", "input too large");
  }
  const padded = pad(plain, PAD_BLOCK);
  try {
    return await encryptAead(key, padded, aad);
  } finally {
    zero(padded, plain);
  }
}

/** Reverses encryptEnvelope. */
export async function decryptEnvelope(key: Uint8Array, blob: Uint8Array, aad: Uint8Array): Promise<Envelope> {
  if (blob.length > MAX_PLAINTEXT + PAD_BLOCK + AEAD_OVERHEAD) {
    throw new CryptoError("size", "input too large");
  }
  const padded = await decryptAead(key, blob, aad);
  try {
    const plain = unpad(padded, PAD_BLOCK);
    try {
      return decodeEnvelope(plain);
    } finally {
      zero(plain);
    }
  } finally {
    zero(padded);
  }
}
