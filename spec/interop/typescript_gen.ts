/**
 * Writes typescript.json: ciphertext produced by the TypeScript SDK for other
 * implementations to open. Run from sdk/typescript after npm install:
 *
 *   npm run interop:gen        (or: npx tsx ../../spec/interop/typescript_gen.ts)
 *
 * The schema is documented in README.md next to this file (version 1).
 * Secrets are placeholders. Keys are generated for the file and have no
 * other use.
 *
 * The script avoids top-level await and import.meta so that it runs both as
 * an ES module and through tsx's CommonJS mode.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

import {
  PAD_BLOCK,
  VERSION,
  commitment,
  decodeEnvelope,
  encodeBase64Url,
  encodeEnvelope,
  encryptAead,
  fingerprint,
  generateKeyPair,
  newSymmetricKey,
  pad,
  randomBytes,
  revealAad,
  seal,
  secretField,
  sodiumVersion,
  type Envelope,
} from "../../sdk/typescript/src/index.js";

const here = dirname(process.argv[1] ?? ".");
const out = join(here, "typescript.json");

async function dropCase(name: string, secretName: string, purpose: string, storage: string, retention: string, value: Uint8Array): Promise<Record<string, unknown>> {
  const keys = await generateKeyPair();
  const fp = await fingerprint(keys.publicKey);
  const envelope: Envelope = { v: 1, type: "drop", name: secretName, purpose, storage, retention, fingerprint: fp, ...secretField(value) };
  const plaintext = encodeEnvelope(envelope);
  const sealed = await seal(keys.publicKey, pad(plaintext, PAD_BLOCK));
  return {
    name,
    recipient_public_key: encodeBase64Url(keys.publicKey),
    recipient_secret_key: encodeBase64Url(keys.privateKey),
    fingerprint: fp,
    commitment: await commitment(keys.publicKey),
    sealed: encodeBase64Url(sealed),
    plaintext: encodeBase64Url(plaintext),
    envelope: decodeEnvelope(plaintext),
    secret: encodeBase64Url(value),
  };
}

async function revealCase(name: string, displayName: string, keepsCopy: boolean, value: Uint8Array): Promise<Record<string, unknown>> {
  const key = await newSymmetricKey();
  const nonce = await randomBytes(24);
  const envelope: Envelope = { v: 1, type: "reveal", name: displayName, ...secretField(value) };
  const plaintext = encodeEnvelope(envelope);
  const aad = revealAad(displayName, keepsCopy);
  const blob = await encryptAead(key, pad(plaintext, PAD_BLOCK), aad, { nonce });
  return {
    name,
    key: encodeBase64Url(key),
    nonce: encodeBase64Url(nonce),
    display_name: displayName,
    keeps_copy: keepsCopy,
    aad: encodeBase64Url(aad),
    blob: encodeBase64Url(blob),
    plaintext: encodeBase64Url(plaintext),
    envelope: decodeEnvelope(plaintext),
    secret: encodeBase64Url(value),
  };
}

function libraryDescription(): Promise<string> {
  const packageJson = JSON.parse(readFileSync(join(here, "..", "..", "sdk", "typescript", "package.json"), "utf8")) as {
    dependencies?: Record<string, string>;
  };
  const wrappers = packageJson.dependencies?.["libsodium-wrappers"] ?? "unknown";
  return sodiumVersion().then((v) => "burndrop-typescript " + VERSION + ", libsodium-wrappers " + wrappers + " (libsodium " + v + ")");
}

async function build(): Promise<Record<string, unknown>> {
  const purpose = "Call the OpenAI API from the billing script";
  const utf8 = new TextEncoder();
  const BS = String.fromCharCode(92);
  return {
    version: 1,
    producer: "typescript",
    library: await libraryDescription(),
    generated_at: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
    drops: [
      await dropCase("drop text", "openai-api-key", purpose, "macOS Keychain", "until-revoked", utf8.encode("sk-test-0123456789abcdef")),
      await dropCase(
        "drop json characters",
        "openai-api-key",
        'Line 1\nline 2 with <tag> & "quotes"',
        "the agent's process memory only",
        "session",
        utf8.encode('päss "quoted" <tag> & done ' + BS + " end"),
      ),
      await dropCase(
        "drop binary",
        "client-cert",
        purpose,
        "an encrypted vault file on the agent's machine",
        "until:2030-01-01T00:00:00Z",
        new Uint8Array([0, 1, 2, 3, 250, 251, 252, 253, 254, 255]),
      ),
    ],
    reveals: [
      await revealCase("reveal text", "staging-db-url", true, utf8.encode("postgres://app:s3cret@db.staging.example:5432/app")),
      await revealCase("reveal binary no copy", "tls-key", false, new Uint8Array(86).map((_, i) => i * 3)),
      await revealCase("reveal empty secret", "staging-db-url", true, new Uint8Array(0)),
    ],
  };
}

build()
  .then((document) => {
    writeFileSync(out, JSON.stringify(document, null, 2) + "\n");
    const drops = document.drops as unknown[];
    const reveals = document.reveals as unknown[];
    console.error("wrote " + out + " (" + String(drops.length) + " drops, " + String(reveals.length) + " reveals)");
  })
  .catch((err: unknown) => {
    console.error(err);
    process.exit(1);
  });
