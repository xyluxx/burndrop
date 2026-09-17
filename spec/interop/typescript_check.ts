/**
 * Verifies every spec/interop/*.json with the TypeScript SDK. Run from
 * sdk/typescript after npm install:
 *
 *   npm run interop:check      (or: npx tsx ../../spec/interop/typescript_check.ts [file ...])
 *
 * Without arguments every *.json next to this script is checked, including
 * typescript.json (a self check). The exit status is 1 when any case fails.
 * The checks are listed in README.md next to this file.
 *
 * The script avoids top-level await and import.meta so that it runs both as
 * an ES module and through tsx's CommonJS mode.
 */
import { readFileSync, readdirSync } from "node:fs";
import { basename, dirname, join } from "node:path";

import {
  CryptoError,
  KEY_SIZE,
  NONCE_SIZE,
  PAD_BLOCK,
  commitment,
  decodeBase64Url,
  decodeEnvelope,
  decryptAead,
  encodeEnvelope,
  fingerprint,
  openSealed,
  publicKeyFromPrivate,
  revealAad,
  secretBytes,
  unpad,
  type Envelope,
} from "../../sdk/typescript/src/index.js";

const here = dirname(process.argv[1] ?? ".");

class Failure extends Error {}

type Case = Record<string, unknown>;

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

function field(c: Case, name: string, length?: number): Uint8Array {
  const value = c[name];
  if (typeof value !== "string") {
    throw new Failure(name + " is missing or not a string");
  }
  let data: Uint8Array;
  try {
    data = decodeBase64Url(value);
  } catch {
    throw new Failure(name + " is not canonical base64url");
  }
  if (length !== undefined && data.length !== length) {
    throw new Failure(name + " must be " + String(length) + " bytes, got " + String(data.length));
  }
  return data;
}

const ENVELOPE_KEYS = ["v", "type", "name", "purpose", "storage", "retention", "fingerprint", "format", "secret"];

function expectedEnvelope(c: Case): Envelope {
  const obj = c.envelope;
  if (typeof obj !== "object" || obj === null || Array.isArray(obj)) {
    throw new Failure("envelope is missing or not an object");
  }
  for (const key of Object.keys(obj)) {
    if (!ENVELOPE_KEYS.includes(key)) {
      throw new Failure("envelope has unexpected fields: " + key);
    }
  }
  // Decoding the object's own JSON applies the same validation as the
  // strict parser and normalizes empty optional fields.
  try {
    return decodeEnvelope(new TextEncoder().encode(JSON.stringify(obj)));
  } catch (err) {
    throw new Failure("envelope is not valid: " + (err instanceof Error ? err.message : String(err)));
  }
}

function sameEnvelope(a: Envelope, b: Envelope): boolean {
  return bytesEqual(encodeEnvelope(a), encodeEnvelope(b));
}

function checkPlaintext(padded: Uint8Array, c: Case, expectedType: string): { decoded: Envelope; notes: string[] } {
  const notes: string[] = [];
  let plaintext: Uint8Array;
  try {
    plaintext = unpad(padded, PAD_BLOCK);
  } catch {
    throw new Failure("padding is malformed");
  }
  if (!bytesEqual(plaintext, field(c, "plaintext"))) {
    throw new Failure("unpadded plaintext differs from the plaintext field");
  }
  let decoded: Envelope;
  try {
    decoded = decodeEnvelope(plaintext);
  } catch (err) {
    throw new Failure("envelope does not decode: " + (err instanceof Error ? err.message : String(err)));
  }
  const expected = expectedEnvelope(c);
  if (!sameEnvelope(decoded, expected)) {
    throw new Failure("decoded envelope differs from the envelope field");
  }
  if (decoded.type !== expectedType) {
    throw new Failure("envelope type is " + decoded.type + ", want " + expectedType);
  }
  if (!bytesEqual(secretBytes(decoded), field(c, "secret"))) {
    throw new Failure("secret bytes differ from the secret field");
  }
  if (!bytesEqual(encodeEnvelope(decoded), plaintext)) {
    notes.push("re-encoding differs from the producer's bytes (informational)");
  }
  return { decoded, notes };
}

async function checkDrop(c: Case): Promise<string[]> {
  const publicKey = field(c, "recipient_public_key", KEY_SIZE);
  const privateKey = field(c, "recipient_secret_key", KEY_SIZE);
  if (!bytesEqual(await publicKeyFromPrivate(privateKey), publicKey)) {
    throw new Failure("public key is not derived from the secret key");
  }
  if (c.fingerprint !== (await fingerprint(publicKey))) {
    throw new Failure("fingerprint differs");
  }
  if (c.commitment !== (await commitment(publicKey))) {
    throw new Failure("commitment differs");
  }
  let padded: Uint8Array;
  try {
    padded = await openSealed(publicKey, privateKey, field(c, "sealed"));
  } catch (err) {
    if (err instanceof CryptoError) {
      throw new Failure("sealed box does not open");
    }
    throw err;
  }
  const { decoded, notes } = checkPlaintext(padded, c, "drop");
  if (decoded.fingerprint !== c.fingerprint) {
    throw new Failure("envelope fingerprint differs from the key fingerprint");
  }
  return notes;
}

async function checkReveal(c: Case): Promise<string[]> {
  const key = field(c, "key", KEY_SIZE);
  const nonce = field(c, "nonce", NONCE_SIZE);
  const displayName = c.display_name;
  const keepsCopy = c.keeps_copy;
  if (typeof displayName !== "string" || typeof keepsCopy !== "boolean") {
    throw new Failure("display_name must be a string and keeps_copy a boolean");
  }
  const aad = field(c, "aad");
  if (!bytesEqual(aad, revealAad(displayName, keepsCopy))) {
    throw new Failure("aad differs from reveal_aad(display_name, keeps_copy)");
  }
  const blob = field(c, "blob");
  if (!bytesEqual(blob.subarray(0, NONCE_SIZE), nonce)) {
    throw new Failure("blob does not start with the nonce");
  }
  let padded: Uint8Array;
  try {
    padded = await decryptAead(key, blob, aad);
  } catch (err) {
    if (err instanceof CryptoError) {
      throw new Failure("blob does not decrypt");
    }
    throw err;
  }
  const { notes } = checkPlaintext(padded, c, "reveal");
  let flippedOpened = false;
  try {
    await decryptAead(key, blob, revealAad(displayName, !keepsCopy));
    flippedOpened = true;
  } catch (err) {
    if (!(err instanceof CryptoError)) {
      throw err;
    }
  }
  if (flippedOpened) {
    throw new Failure("blob decrypts with keeps_copy flipped; the display fields are not bound");
  }
  return notes;
}

async function checkFile(path: string): Promise<{ passed: number; failed: number }> {
  const name = basename(path);
  let document: unknown;
  try {
    document = JSON.parse(readFileSync(path, "utf8"));
  } catch (err) {
    console.log("FAIL " + name + ": not JSON: " + (err instanceof Error ? err.message : String(err)));
    return { passed: 0, failed: 1 };
  }
  if (typeof document !== "object" || document === null || Array.isArray(document) || (document as Case).version !== 1) {
    console.log("FAIL " + name + ": version must be 1");
    return { passed: 0, failed: 1 };
  }
  const doc = document as Case;
  const producer = typeof doc.producer === "string" ? doc.producer : "?";
  let passed = 0;
  let failed = 0;
  const kinds: [string, (c: Case) => Promise<string[]>][] = [
    ["drops", checkDrop],
    ["reveals", checkReveal],
  ];
  for (const [kind, check] of kinds) {
    const cases = doc[kind] ?? [];
    if (!Array.isArray(cases)) {
      console.log("FAIL " + name + ": " + kind + " must be a list");
      failed++;
      continue;
    }
    const singular = kind.slice(0, -1);
    for (const [index, item] of (cases as unknown[]).entries()) {
      const c = typeof item === "object" && item !== null && !Array.isArray(item) ? (item as Case) : undefined;
      const label = c !== undefined && typeof c.name === "string" ? JSON.stringify(c.name) : String(index);
      try {
        if (c === undefined) {
          throw new Failure("case is not an object");
        }
        const notes = await check(c);
        console.log("ok   " + name + " [" + producer + "] " + singular + " " + label + (notes.length > 0 ? " (" + notes.join("; ") + ")" : ""));
        passed++;
      } catch (err) {
        if (err instanceof Failure) {
          console.log("FAIL " + name + " [" + producer + "] " + singular + " " + label + ": " + err.message);
          failed++;
          continue;
        }
        throw err;
      }
    }
  }
  if (passed + failed === 0) {
    console.log("FAIL " + name + ": no cases");
    failed++;
  }
  return { passed, failed };
}

async function main(argv: string[]): Promise<number> {
  const paths =
    argv.length > 0
      ? argv
      : readdirSync(here)
          .filter((f) => f.endsWith(".json"))
          .sort()
          .map((f) => join(here, f));
  if (paths.length === 0) {
    console.log("no interop files found");
    return 1;
  }
  let totalPassed = 0;
  let totalFailed = 0;
  for (const path of paths) {
    const { passed, failed } = await checkFile(path);
    totalPassed += passed;
    totalFailed += failed;
  }
  console.log(String(totalPassed) + " passed, " + String(totalFailed) + " failed, " + String(paths.length) + " file(s)");
  return totalFailed > 0 ? 1 : 0;
}

main(process.argv.slice(2))
  .then((code) => {
    process.exit(code);
  })
  .catch((err: unknown) => {
    console.error(err);
    process.exit(1);
  });
