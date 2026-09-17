// Builds dist/page.html (one self-contained file), dist/page.meta.json (the
// hashes the relay bakes into its Content-Security-Policy), and
// dist/page.sha256. Run with: node build.mjs [--version vX.Y.Z]
import { build } from "esbuild";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const versionFlag = args.indexOf("--version");
const version = versionFlag >= 0 && args[versionFlag + 1] ? args[versionFlag + 1] : process.env.BURNDROP_VERSION || "dev";

mkdirSync(join(root, "build"), { recursive: true });
mkdirSync(join(root, "dist"), { recursive: true });

// 1. Tailwind: compile and purge to the classes used by the page.
const tailwindBin = join(root, "node_modules", "@tailwindcss", "cli", "dist", "index.mjs");
execFileSync(process.execPath, [tailwindBin, "-i", join(root, "src", "styles.css"), "-o", join(root, "build", "styles.css"), "--minify"], { stdio: "inherit" });
let css = readFileSync(join(root, "build", "styles.css"), "utf8");

// 2. Font: inline the OFL licensed Outfit face (Latin subset) as base64.
const font = readFileSync(join(root, "fonts", "Outfit-latin.woff2")).toString("base64");
if (!css.includes("__OUTFIT_WOFF2__")) {
  throw new Error("font placeholder missing from the compiled CSS");
}
css = css.replace("__OUTFIT_WOFF2__", font);

// 3. Script: bundle page.ts with libsodium into one IIFE.
const result = await build({
  entryPoints: [join(root, "src", "page.ts")],
  bundle: true,
  format: "iife",
  platform: "browser",
  target: ["es2022", "chrome110", "firefox110", "safari16"],
  minify: true,
  legalComments: "none",
  write: false,
  define: { __VERSION__: JSON.stringify(version), "process.env.NODE_ENV": '"production"' },
  logLevel: "warning",
});
const js = result.outputFiles[0].text;
if (js.includes("</script")) {
  throw new Error("script contains a closing script tag");
}
if (css.includes("</style")) {
  throw new Error("stylesheet contains a closing style tag");
}

// 4. Assemble. The hashes cover exactly the inline bytes, which is what the
// CSP hash sources require.
const template = readFileSync(join(root, "src", "index.html"), "utf8");
if (!template.includes("__CSS__") || !template.includes("__JS__")) {
  throw new Error("template placeholders missing");
}
const html = template.replace("__CSS__", () => css).replace("__JS__", () => js);
// CSP hash sources are base64; the page hash people compare by hand is hex,
// the same form sha256sum prints.
const sha = (s) => createHash("sha256").update(s, "utf8").digest("base64");
const shaHex = (s) => createHash("sha256").update(s, "utf8").digest("hex");
const needsWasm = js.includes("WebAssembly");
const meta = {
  version,
  sha256: shaHex(html),
  script_sha256: sha(js),
  style_sha256: sha(css),
  needs_wasm: needsWasm,
  built_at: new Date().toISOString(),
  bytes: Buffer.byteLength(html, "utf8"),
};
writeFileSync(join(root, "dist", "page.html"), html);
writeFileSync(join(root, "dist", "page.meta.json"), JSON.stringify(meta, null, 2) + "\n");
writeFileSync(join(root, "dist", "page.sha256"), `${meta.sha256}  page.html\n`);
console.log(`built dist/page.html (${meta.bytes} bytes, version ${version}, sha256 ${meta.sha256}, wasm ${needsWasm})`);

// 5. The same page split into three files for the browser extension, whose
// Manifest V3 policy forbids inline script. Not embedded in the relay.
const ext = join(root, "build", "ext");
mkdirSync(ext, { recursive: true });
writeFileSync(join(ext, "page.html"), template.replace("<style>__CSS__</style>", '<link rel="stylesheet" href="page.css" />').replace("<script>__JS__</script>", '<script src="page.js"></script>'));
writeFileSync(join(ext, "page.js"), js);
writeFileSync(join(ext, "page.css"), css);
writeFileSync(join(ext, "page.meta.json"), JSON.stringify(meta, null, 2) + "\n");
console.log(`built build/ext/ (page.html, page.js, page.css) for the extension`);
