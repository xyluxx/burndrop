// Builds the npm packages that wrap the Go binary so `npx burndrop mcp`
// works without a manual download: one package per platform holding the
// binary, and the `burndrop` package whose bin script picks the right one
// through optionalDependencies (the pattern esbuild uses).
//
//   node npm/make-packages.mjs --version 1.2.3 --dist dist --out npm/out
//
// `dist` is GoReleaser's output directory (dist/burndrop_<os>_<arch>[_v1]/burndrop).
import { copyFileSync, existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync, chmodSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));

export const PLATFORMS = [
  { goos: "linux", goarch: "amd64", os: "linux", cpu: "x64" },
  { goos: "linux", goarch: "arm64", os: "linux", cpu: "arm64" },
  { goos: "darwin", goarch: "amd64", os: "darwin", cpu: "x64" },
  { goos: "darwin", goarch: "arm64", os: "darwin", cpu: "arm64" },
  { goos: "windows", goarch: "amd64", os: "win32", cpu: "x64" },
  { goos: "windows", goarch: "arm64", os: "win32", cpu: "arm64" },
];

export function platformPackageName(os, cpu) {
  return `@burndrop/cli-${os}-${cpu}`;
}

function findBinary(dist, goos, goarch) {
  const exe = goos === "windows" ? "burndrop.exe" : "burndrop";
  const dirs = readdirSync(dist).filter((d) => d.startsWith(`burndrop_${goos}_${goarch}`));
  for (const d of dirs) {
    const candidate = join(dist, d, exe);
    if (existsSync(candidate)) return candidate;
  }
  throw new Error(`no ${exe} for ${goos}/${goarch} under ${dist}`);
}

export function makePackages({ version, dist, out }) {
  if (!/^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/.test(version)) {
    throw new Error(`version must be semver without a v prefix: ${version}`);
  }
  const optional = {};
  for (const p of PLATFORMS) {
    const name = platformPackageName(p.os, p.cpu);
    const dir = join(out, "platform", `${p.os}-${p.cpu}`);
    mkdirSync(join(dir, "bin"), { recursive: true });
    const exe = p.goos === "windows" ? "burndrop.exe" : "burndrop";
    copyFileSync(findBinary(dist, p.goos, p.goarch), join(dir, "bin", exe));
    if (p.goos !== "windows") chmodSync(join(dir, "bin", exe), 0o755);
    writeFileSync(
      join(dir, "package.json"),
      JSON.stringify(
        {
          name,
          version,
          description: `burndrop CLI binary for ${p.os} ${p.cpu}. Install the burndrop package instead of this one.`,
          license: "Apache-2.0",
          repository: { type: "git", url: "git+https://github.com/burndrop/burndrop.git" },
          os: [p.os],
          cpu: [p.cpu],
          files: ["bin"],
        },
        null,
        2,
      ) + "\n",
    );
    optional[name] = version;
  }
  const wrapper = join(out, "burndrop");
  mkdirSync(join(wrapper, "bin"), { recursive: true });
  const template = JSON.parse(readFileSync(join(here, "package.json"), "utf8"));
  template.version = version;
  template.optionalDependencies = optional;
  delete template.private;
  writeFileSync(join(wrapper, "package.json"), JSON.stringify(template, null, 2) + "\n");
  copyFileSync(join(here, "bin", "burndrop.js"), join(wrapper, "bin", "burndrop.js"));
  copyFileSync(join(here, "README.md"), join(wrapper, "README.md"));
  copyFileSync(join(here, "..", "LICENSE"), join(wrapper, "LICENSE"));
  return { platforms: PLATFORMS.length, wrapper };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const args = process.argv.slice(2);
  const get = (flag, fallback) => {
    const i = args.indexOf(flag);
    return i >= 0 && args[i + 1] ? args[i + 1] : fallback;
  };
  const result = makePackages({ version: get("--version", process.env.BURNDROP_VERSION || ""), dist: get("--dist", "dist"), out: get("--out", join(here, "out")) });
  console.log(`wrote ${result.platforms} platform packages and ${result.wrapper}`);
}
