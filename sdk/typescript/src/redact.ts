/**
 * Replaces known secret values, and their common encodings, in text that is
 * about to leave the process: command output, error messages, tool results.
 * It is a safety net behind the rule that values are never put into
 * model-facing output on purpose. Mirrors internal/agent/redact.go.
 */
import { encodeBase64Url } from "./base64url.js";
import { isGoSpace, quoteJsonGo } from "./envelope.js";
import { queryEscape } from "./link.js";

/** Values shorter than this are not registered, so ordinary text is not masked. */
export const MIN_REDACT_LEN = 6;

interface Form {
  name: string;
  text: string;
}

const utf8 = new TextEncoder();

function utf8Length(s: string): number {
  return utf8.encode(s).length;
}

function stdBase64(bytes: Uint8Array, padding: boolean): string {
  let s = encodeBase64Url(bytes).replaceAll("-", "+").replaceAll("_", "/");
  if (padding) {
    while (s.length % 4 !== 0) {
      s += "=";
    }
  }
  return s;
}

function urlBase64(bytes: Uint8Array, padding: boolean): string {
  let s = encodeBase64Url(bytes);
  if (padding) {
    while (s.length % 4 !== 0) {
      s += "=";
    }
  }
  return s;
}

function hex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) {
    out += b.toString(16).padStart(2, "0");
  }
  return out;
}

/** Go's url.PathEscape: a path segment encoding. */
export function pathEscape(s: string): string {
  let out = "";
  for (const b of utf8.encode(s)) {
    if (
      (b >= 0x30 && b <= 0x39) ||
      (b >= 0x41 && b <= 0x5a) ||
      (b >= 0x61 && b <= 0x7a) ||
      b === 0x2d ||
      b === 0x5f ||
      b === 0x2e ||
      b === 0x7e ||
      b === 0x24 ||
      b === 0x26 ||
      b === 0x2b ||
      b === 0x3a ||
      b === 0x3d ||
      b === 0x40
    ) {
      out += String.fromCharCode(b);
    } else {
      out += "%" + b.toString(16).toUpperCase().padStart(2, "0");
    }
  }
  return out;
}

/** Go's strings.TrimSpace. */
export function trimGoSpace(s: string): string {
  const chars = Array.from(s);
  let start = 0;
  let end = chars.length;
  while (start < end && isGoSpace(chars[start].codePointAt(0) ?? 0)) {
    start++;
  }
  while (end > start && isGoSpace(chars[end - 1].codePointAt(0) ?? 0)) {
    end--;
  }
  return chars.slice(start, end).join("");
}

/** Registers secret values and replaces every known form of them in text. */
export class Redactor {
  private forms: Form[] = [];

  /**
   * Registers a value under a name. Encoded forms are registered too:
   * standard and URL-safe base64 (with and without padding), hex, URL query
   * escaping, path escaping, and JSON string escaping when it differs from
   * the raw text.
   */
  add(name: string, value: Uint8Array | string): void {
    const bytes = typeof value === "string" ? utf8.encode(value) : value;
    if (bytes.length < MIN_REDACT_LEN) {
      return;
    }
    const raw = typeof value === "string" ? value : new TextDecoder("utf-8").decode(bytes);
    const candidates = [
      raw,
      stdBase64(bytes, true),
      stdBase64(bytes, false),
      urlBase64(bytes, true),
      urlBase64(bytes, false),
      hex(bytes),
      queryEscape(raw),
      pathEscape(raw),
    ];
    const quoted = quoteJsonGo(raw, true);
    if (quoted.length > 2) {
      candidates.push(quoted.slice(1, -1));
    }
    const trimmed = trimGoSpace(raw);
    if (trimmed.length !== raw.length && trimmed.length > 0) {
      candidates.push(trimmed);
    }
    const seen = new Set(this.forms.map((f) => f.text));
    for (const text of candidates) {
      if (utf8Length(text) < MIN_REDACT_LEN || seen.has(text)) {
        continue;
      }
      seen.add(text);
      this.forms.push({ name, text });
    }
    // Longest first so a longer encoding is replaced before a substring of it.
    this.forms.sort((a, b) => b.text.length - a.text.length);
  }

  /** Forgets every form registered under name. */
  remove(name: string): void {
    this.forms = this.forms.filter((f) => f.name !== name);
  }

  /** Returns s with every known form replaced by [redacted:<name>]. */
  redact(s: string): string {
    if (this.forms.length === 0 || s === "") {
      return s;
    }
    let out = s;
    for (const f of this.forms) {
      if (out.includes(f.text)) {
        out = out.replaceAll(f.text, "[redacted:" + f.name + "]");
      }
    }
    return out;
  }

  /** How many forms are registered; for tests and diagnostics. */
  get count(): number {
    return this.forms.length;
  }
}
