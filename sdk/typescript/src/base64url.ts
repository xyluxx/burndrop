/**
 * base64url without padding, the encoding of every binary field in links,
 * JSON bodies, and test vectors.
 *
 * Decoding is strict, like Go's base64.RawURLEncoding.Strict(): the standard
 * alphabet, "=" padding, whitespace, and non-zero trailing bits are all
 * rejected, so every byte string has exactly one accepted encoding. This
 * matters for tokens and keys, which are compared and hashed as strings.
 */
import { EncodingError } from "./errors.js";

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

const LOOKUP: Int16Array = (() => {
  const table = new Int16Array(128).fill(-1);
  for (let i = 0; i < ALPHABET.length; i++) {
    table[ALPHABET.charCodeAt(i)] = i;
  }
  return table;
})();

/** Encodes bytes as base64url without padding. */
export function encodeBase64Url(bytes: Uint8Array): string {
  let out = "";
  let i = 0;
  for (; i + 3 <= bytes.length; i += 3) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out += ALPHABET[n >>> 18] + ALPHABET[(n >>> 12) & 63] + ALPHABET[(n >>> 6) & 63] + ALPHABET[n & 63];
  }
  const rest = bytes.length - i;
  if (rest === 1) {
    const n = bytes[i] << 16;
    out += ALPHABET[n >>> 18] + ALPHABET[(n >>> 12) & 63];
  } else if (rest === 2) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8);
    out += ALPHABET[n >>> 18] + ALPHABET[(n >>> 12) & 63] + ALPHABET[(n >>> 6) & 63];
  }
  return out;
}

/**
 * Decodes base64url without padding. Throws EncodingError for any input that
 * is not the canonical encoding of some byte string.
 */
export function decodeBase64Url(s: string): Uint8Array {
  const len = s.length;
  const rem = len % 4;
  if (rem === 1) {
    throw new EncodingError("base64url: invalid length");
  }
  const out = new Uint8Array(Math.floor(len / 4) * 3 + (rem === 2 ? 1 : rem === 3 ? 2 : 0));
  let acc = 0;
  let bits = 0;
  let j = 0;
  for (let i = 0; i < len; i++) {
    const c = s.charCodeAt(i);
    const v = c < 128 ? LOOKUP[c] : -1;
    if (v < 0) {
      throw new EncodingError("base64url: invalid character");
    }
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[j++] = (acc >>> bits) & 0xff;
      acc &= (1 << bits) - 1;
    }
  }
  if (bits > 0 && acc !== 0) {
    throw new EncodingError("base64url: non-canonical encoding");
  }
  return out;
}

/** Reports whether s is canonical base64url without padding. */
export function isBase64Url(s: string): boolean {
  try {
    decodeBase64Url(s);
    return true;
  } catch {
    return false;
  }
}
