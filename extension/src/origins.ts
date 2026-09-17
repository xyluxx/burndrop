// Relay origins: validation, the match patterns derived from them, and the
// comparison the background makes before it moves a tab. The validation
// mirrors normalizeOrigin in web/src/link.ts so the extension accepts exactly
// the origins a link may name in its r field.

export type Browser = "chrome" | "firefox";

export class OriginError extends Error {}

const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]"]);

/**
 * normalizeOrigin returns scheme://host[:port] in lowercase without a default
 * port, or throws an OriginError whose message is meant for the options page.
 */
export function normalizeOrigin(input: string): string {
  const s = input.trim();
  if (s === "") {
    throw new OriginError("Enter the relay's origin, for example https://relay.example.");
  }
  if (s.length > 512) {
    throw new OriginError("That is too long to be an origin.");
  }
  let u: URL;
  try {
    u = new URL(s);
  } catch {
    throw new OriginError("That is not a URL. Use the form https://relay.example.");
  }
  if (u.username || u.password || u.search || u.hash || (u.pathname !== "/" && u.pathname !== "")) {
    throw new OriginError("Use only the scheme and host, without a path, query, or credentials.");
  }
  const scheme = u.protocol.slice(0, -1).toLowerCase();
  const host = u.hostname.toLowerCase();
  if (scheme === "http") {
    if (!LOOPBACK.has(host)) {
      throw new OriginError("http is only allowed for localhost. A relay on the internet must use https.");
    }
  } else if (scheme !== "https") {
    throw new OriginError("The scheme must be https.");
  }
  return u.port ? `${scheme}://${host}:${u.port}` : `${scheme}://${host}`;
}

/**
 * hostPattern is the match pattern requested as the origin's host permission.
 * Firefox match patterns cannot carry a port (Firefox bug 1362809) and ignore
 * the URL's port when matching, so there one pattern covers every port of the
 * host; Chrome patterns are exact.
 */
export function hostPattern(origin: string, browser: Browser): string {
  return `${patternHost(origin, browser)}/*`;
}

/** contentScriptPatterns covers the two paths a relay serves the page on. */
export function contentScriptPatterns(origin: string, browser: Browser): string[] {
  const host = patternHost(origin, browser);
  return [`${host}/drop*`, `${host}/reveal*`];
}

function patternHost(origin: string, browser: Browser): string {
  const u = new URL(origin);
  return `${u.protocol}//${browser === "firefox" ? u.hostname : u.host}`;
}

export const SCRIPT_ID_PREFIX = "relay:";

export function scriptId(origin: string): string {
  return SCRIPT_ID_PREFIX + origin;
}

/**
 * originMatches tells whether a page at actual belongs to the configured
 * origin, with the same port rule as the patterns above.
 */
export function originMatches(configured: string, actual: string, browser: Browser): boolean {
  if (configured === actual) {
    return true;
  }
  if (browser !== "firefox") {
    return false;
  }
  const a = new URL(configured);
  const b = new URL(actual);
  return a.protocol === b.protocol && a.hostname === b.hostname;
}
