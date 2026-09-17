// The agent side of the protocol, spoken directly to the relay so the
// tests exercise the page against the real server.
import * as b64 from "../src/base64.js";
import * as c from "../src/crypto.js";
import { buildDropLink, buildRevealLink } from "../src/link.js";

export const TTL_SECONDS = 600;

export interface ApiResult {
  status: number;
  body: Record<string, unknown>;
}

export async function api(base: string, path: string, body: unknown): Promise<ApiResult> {
  const res = await fetch(base + path, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Client": "burndrop-e2e/1" },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  return { status: res.status, body: text ? (JSON.parse(text) as Record<string, unknown>) : {} };
}

export interface DropFixture {
  kp: c.KeyPair;
  id: string;
  uploadToken: string;
  fetchToken: string;
  fingerprint: string;
  link: string;
  name: string;
  purpose: string;
  storage: string;
  retention: string;
}

export async function createDrop(base: string, opts: { name: string; purpose?: string; storage?: string; retention?: string } = { name: "openai-api-key" }): Promise<DropFixture> {
  await c.ready();
  const kp = c.generateKeyPair();
  const res = await api(base, "/api/v1/drops", { ttl_seconds: TTL_SECONDS, commitment: await c.commitment(kp.publicKey) });
  if (res.status !== 201 && res.status !== 200) {
    throw new Error(`create drop failed: ${res.status} ${JSON.stringify(res.body)}`);
  }
  const d: DropFixture = {
    kp,
    id: res.body["drop_id"] as string,
    uploadToken: res.body["upload_token"] as string,
    fetchToken: res.body["fetch_token"] as string,
    fingerprint: await c.fingerprint(kp.publicKey),
    link: "",
    name: opts.name,
    purpose: opts.purpose ?? "",
    storage: opts.storage ?? "",
    retention: opts.retention ?? "until-revoked",
  };
  d.link = buildDropLink(base, { relay: null, id: d.id, uploadToken: d.uploadToken, recipientKey: kp.publicKey, name: d.name, purpose: d.purpose, storage: d.storage, retention: d.retention });
  return d;
}

export async function fetchDrop(base: string, id: string, fetchToken: string): Promise<Uint8Array> {
  const res = await api(base, "/api/v1/drops/fetch", { drop_id: id, fetch_token: fetchToken });
  if (res.status !== 200) {
    throw new Error(`fetch failed: ${res.status} ${JSON.stringify(res.body)}`);
  }
  return b64.decode(res.body["ciphertext"] as string);
}

/** uploadAsPage does what the page does, for tests that need an uploaded drop. */
export async function uploadAsPage(base: string, d: DropFixture, secret: string): Promise<void> {
  const env: c.Envelope = { v: 1, type: "drop", name: d.name, retention: d.retention, fingerprint: d.fingerprint, format: "text", secret };
  if (d.purpose) env.purpose = d.purpose;
  if (d.storage) env.storage = d.storage;
  const res = await api(base, "/api/v1/drops/upload", { drop_id: d.id, upload_token: d.uploadToken, commitment: await c.commitment(d.kp.publicKey), ciphertext: b64.encode(c.sealEnvelope(d.kp.publicKey, env)) });
  if (res.status !== 200) {
    throw new Error(`upload failed: ${res.status} ${JSON.stringify(res.body)}`);
  }
}

export interface RevealFixture {
  key: Uint8Array;
  id: string;
  revealToken: string;
  revokeToken: string;
  link: string;
  name: string;
  keepsCopy: boolean;
  secret: string;
}

export async function createReveal(base: string, name: string, keepsCopy: boolean, secret: string): Promise<RevealFixture> {
  await c.ready();
  const key = c.newSymmetricKey();
  const env: c.Envelope = { v: 1, type: "reveal", name, format: "text", secret };
  const blob = c.encryptEnvelope(key, env, c.revealAad(name, keepsCopy));
  const res = await api(base, "/api/v1/reveals", { ttl_seconds: TTL_SECONDS, ciphertext: b64.encode(blob) });
  if (res.status !== 201 && res.status !== 200) {
    throw new Error(`create reveal failed: ${res.status} ${JSON.stringify(res.body)}`);
  }
  const r: RevealFixture = {
    key,
    id: res.body["drop_id"] as string,
    revealToken: res.body["reveal_token"] as string,
    revokeToken: res.body["revoke_token"] as string,
    link: "",
    name,
    keepsCopy,
    secret,
  };
  r.link = buildRevealLink(base, { relay: null, id: r.id, revealToken: r.revealToken, key, name, keepsCopy });
  return r;
}

export async function dropState(base: string, id: string): Promise<string> {
  const res = await api(base, "/api/v1/drops/status", { drop_id: id });
  return res.status === 200 ? (res.body["state"] as string) : `http_${res.status}`;
}

export async function revealState(base: string, id: string): Promise<string> {
  const res = await api(base, "/api/v1/reveals/status", { drop_id: id });
  return res.status === 200 ? (res.body["state"] as string) : `http_${res.status}`;
}

export function randomToken(): string {
  return b64.encode(c.randomBytes(16));
}

export { b64, c };
