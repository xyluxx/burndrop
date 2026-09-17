// Builds the page and then the relay binary that embeds it, for the
// end-to-end suite. Run from web/: node e2e/build-relay.mjs
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const web = dirname(dirname(fileURLToPath(import.meta.url)));
const repo = dirname(web);
const exe = process.platform === "win32" ? ".exe" : "";
const out = join(web, "build", `burndrop-relay${exe}`);

execFileSync(process.execPath, [join(web, "build.mjs")], { stdio: "inherit", cwd: web });
execFileSync("go", ["build", "-trimpath", "-o", out, "./cmd/burndrop-relay"], { stdio: "inherit", cwd: repo });
if (!existsSync(out)) {
  throw new Error(`relay binary missing at ${out}`);
}
console.log(`built ${out}`);
