// Builds the extension: bundles the scripts, copies the page built by
// web/build.mjs, writes one manifest per browser, and for release builds
// reproducible zips with their SHA-256. Run with:
//   node build.mjs [--version 1.2.3] [--test]
// --test (or BURNDROP_EXTENSION_TEST=1) grants the localhost host permissions
// up front so the Playwright suite never meets a permission prompt; that
// output goes to dist/chrome-test and dist/firefox-test and is never zipped.
import { build } from "esbuild";
import { createHash } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { zip } from "./scripts/zip.mjs";

const root = dirname(fileURLToPath(import.meta.url));
const pageDir = join(dirname(root), "web", "build", "ext");
const args = process.argv.slice(2);
const test = args.includes("--test") || process.env.BURNDROP_EXTENSION_TEST === "1";
const version = parseVersion();

const BROWSERS = ["chrome", "firefox"];
const ICON_SIZES = [16, 32, 48, 128];
const PAGE_FILES = ["page.html", "page.js", "page.css"];
const LOCALHOST = ["http://localhost/*", "http://127.0.0.1/*"];

// A placeholder until the owner picks the permanent add-on ID for Mozilla
// Add-ons; it cannot change after the first submission (docs/browser-extension.md).
const GECKO_ID = "burndrop-extension@burndrop.example";

// script-src needs 'wasm-unsafe-eval' for libsodium's WebAssembly; connect-src
// keeps the pages talking to https relays (and localhost for development).
const CSP = [
  "default-src 'self'",
  "script-src 'self' 'wasm-unsafe-eval'",
  "object-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "font-src 'self' data:",
  "connect-src 'self' https: http://localhost:* http://127.0.0.1:*",
  "frame-ancestors 'none'",
  "form-action 'none'",
  "base-uri 'none'",
].join("; ");

function parseVersion() {
  const flag = args.indexOf("--version");
  const raw = (flag >= 0 && args[flag + 1]) || process.env.BURNDROP_VERSION || "0.0.0";
  const v = raw.replace(/^v/, "");
  if (!/^\d+(\.\d+){0,3}$/.test(v)) {
    throw new Error(`the extension version must be one to four dot separated integers (Chrome's rule), got ${JSON.stringify(raw)}`);
  }
  return v;
}

function manifest(browser) {
  const icons = Object.fromEntries(ICON_SIZES.map((s) => [s, `icons/icon-${s}.png`]));
  const common = {
    manifest_version: 3,
    name: "burndrop",
    version,
    description: "Opens burndrop drop and reveal links in a bundled copy of the page, so a modified relay page can never see your secret.",
    icons,
    permissions: ["storage", "scripting"],
    optional_host_permissions: test ? ["https://*/*"] : ["https://*/*", ...LOCALHOST],
    ...(test ? { host_permissions: LOCALHOST } : {}),
    action: { default_title: "burndrop: protected relays", default_icon: icons },
    options_ui: { page: "options.html", open_in_tab: true },
    content_security_policy: { extension_pages: CSP },
  };
  if (browser === "chrome") {
    return { ...common, minimum_chrome_version: "110", background: { service_worker: "background.js" } };
  }
  return {
    ...common,
    background: { scripts: ["background.js"] },
    browser_specific_settings: {
      gecko: { id: GECKO_ID, strict_min_version: "140.0", data_collection_permissions: { required: ["none"] } },
    },
  };
}

function listFiles(dir) {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => (entry.isDirectory() ? listFiles(join(dir, entry.name)) : [join(dir, entry.name)]));
}

if (!PAGE_FILES.every((f) => existsSync(join(pageDir, f))) || !existsSync(join(pageDir, "page.meta.json"))) {
  console.error(`The page has not been built (${pageDir} is missing). Run: cd web && npm install && node build.mjs`);
  process.exit(1);
}
const pageMeta = JSON.parse(readFileSync(join(pageDir, "page.meta.json"), "utf8"));

for (const browser of BROWSERS) {
  const out = join(root, "dist", test ? `${browser}-test` : browser);
  rmSync(out, { recursive: true, force: true });
  mkdirSync(join(out, "icons"), { recursive: true });
  await build({
    entryPoints: { background: join(root, "src", "background.ts"), content: join(root, "src", "content.ts"), options: join(root, "src", "options.ts") },
    outdir: out,
    bundle: true,
    format: "iife",
    platform: "browser",
    target: browser === "chrome" ? ["chrome110"] : ["firefox140"],
    define: { __BROWSER__: JSON.stringify(browser), __VERSION__: JSON.stringify(version) },
    legalComments: "none",
    logLevel: "warning",
  });
  for (const f of PAGE_FILES) {
    copyFileSync(join(pageDir, f), join(out, f));
  }
  // Only the fields the extension reads. The web build's file also records
  // the build time, which would make otherwise identical packages differ.
  writeFileSync(join(out, "page.meta.json"), JSON.stringify({ version: pageMeta.version, sha256: pageMeta.sha256 }, null, 2) + "\n");
  for (const f of ["options.html", "options.css"]) {
    copyFileSync(join(root, "src", f), join(out, f));
  }
  for (const size of ICON_SIZES) {
    copyFileSync(join(root, "icons", `icon-${size}.png`), join(out, "icons", `icon-${size}.png`));
  }
  writeFileSync(join(out, "manifest.json"), JSON.stringify(manifest(browser), null, 2) + "\n");
  const files = listFiles(out).map((file) => [relative(out, file).split(sep).join("/"), readFileSync(file)]);
  console.log(`built ${relative(root, out)} (${files.length} files, version ${version}, page ${pageMeta.version})`);
  if (test) {
    continue;
  }
  const name = `burndrop-extension-${browser}.zip`;
  const archive = zip(new Map(files));
  const sha256 = createHash("sha256").update(archive).digest("hex");
  writeFileSync(join(root, "dist", name), archive);
  writeFileSync(join(root, "dist", `${name}.sha256`), `${sha256}  ${name}\n`);
  console.log(`wrote dist/${name} (${archive.length} bytes) sha256 ${sha256}`);
}
