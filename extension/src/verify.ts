// Verify mode: fetch the page a relay serves, hash it, and compare it with
// the page bundled in this extension. The relay's own claim from
// /api/v1/info is fetched alongside, so a relay that serves one page and
// claims another is visible too.

export interface PageMeta {
  version: string;
  sha256: string;
}

export type Verdict = { kind: "verified"; served: string } | { kind: "mismatch"; served: string } | { kind: "unreachable"; reason: string };

export type Claim = { sha256: string; version: string } | { error: string };

export interface Verification {
  verdict: Verdict;
  claim: Claim;
}

const FETCH: RequestInit = { cache: "no-store", credentials: "omit", referrerPolicy: "no-referrer" };

export async function loadBundledMeta(): Promise<PageMeta> {
  const res = await fetch(chrome.runtime.getURL("page.meta.json"));
  const meta = (await res.json()) as PageMeta;
  return { version: meta.version, sha256: meta.sha256 };
}

export async function verifyRelay(origin: string, bundled: PageMeta): Promise<Verification> {
  const [verdict, claim] = await Promise.all([servedVerdict(origin, bundled), relayClaim(origin)]);
  return { verdict, claim };
}

async function servedVerdict(origin: string, bundled: PageMeta): Promise<Verdict> {
  let res: Response;
  try {
    res = await fetch(`${origin}/drop`, FETCH);
  } catch {
    return { kind: "unreachable", reason: "the relay did not answer" };
  }
  if (!res.ok) {
    return { kind: "unreachable", reason: `the relay answered HTTP ${res.status}` };
  }
  const served = await sha256Hex(await res.arrayBuffer());
  return { kind: served === bundled.sha256 ? "verified" : "mismatch", served };
}

async function relayClaim(origin: string): Promise<Claim> {
  let res: Response;
  try {
    res = await fetch(`${origin}/api/v1/info`, FETCH);
  } catch {
    return { error: "no answer from /api/v1/info" };
  }
  if (!res.ok) {
    return { error: `/api/v1/info answered HTTP ${res.status}` };
  }
  let info: unknown;
  try {
    info = await res.json();
  } catch {
    return { error: "/api/v1/info is not JSON" };
  }
  const fields = (typeof info === "object" && info !== null ? info : {}) as Record<string, unknown>;
  const sha256 = fields["page_sha256"];
  const version = fields["page_version"];
  if (typeof sha256 !== "string" || sha256 === "") {
    return { error: "the relay does not report a page hash" };
  }
  return { sha256, version: typeof version === "string" ? version : "" };
}

export async function sha256Hex(data: ArrayBuffer): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", data));
  return Array.from(digest, (b) => b.toString(16).padStart(2, "0")).join("");
}
