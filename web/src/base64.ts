// Strict base64url (RFC 4648 section 5) without padding. Decoding rejects
// padding, non-alphabet characters, and non-canonical trailing bits, matching
// Go's base64.RawURLEncoding.Strict().

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const LOOKUP = new Int16Array(128).fill(-1);
for (let i = 0; i < ALPHABET.length; i++) {
  LOOKUP[ALPHABET.charCodeAt(i)] = i;
}

export function encode(bytes: Uint8Array): string {
  let out = "";
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = ((bytes[i] as number) << 16) | ((bytes[i + 1] as number) << 8) | (bytes[i + 2] as number);
    out += ALPHABET[(n >> 18) & 63]! + ALPHABET[(n >> 12) & 63]! + ALPHABET[(n >> 6) & 63]! + ALPHABET[n & 63]!;
  }
  const rest = bytes.length - i;
  if (rest === 1) {
    const n = (bytes[i] as number) << 16;
    out += ALPHABET[(n >> 18) & 63]! + ALPHABET[(n >> 12) & 63]!;
  } else if (rest === 2) {
    const n = ((bytes[i] as number) << 16) | ((bytes[i + 1] as number) << 8);
    out += ALPHABET[(n >> 18) & 63]! + ALPHABET[(n >> 12) & 63]! + ALPHABET[(n >> 6) & 63]!;
  }
  return out;
}

export class Base64Error extends Error {}

export function decode(s: string): Uint8Array {
  const rem = s.length % 4;
  if (rem === 1) {
    throw new Base64Error("base64url: invalid length");
  }
  const outLen = Math.floor(s.length / 4) * 3 + (rem === 2 ? 1 : rem === 3 ? 2 : 0);
  const out = new Uint8Array(outLen);
  let bits = 0;
  let acc = 0;
  let o = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    const v = c < 128 ? (LOOKUP[c] as number) : -1;
    if (v < 0) {
      throw new Base64Error("base64url: invalid character");
    }
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >> bits) & 0xff;
    }
  }
  // Leftover bits must be zero for the encoding to be canonical.
  if (bits > 0 && (acc & ((1 << bits) - 1)) !== 0) {
    throw new Base64Error("base64url: non-canonical encoding");
  }
  return out;
}

export function isValid(s: string): boolean {
  try {
    decode(s);
    return true;
  } catch {
    return false;
  }
}
