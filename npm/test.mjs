// node --test npm/test.mjs
// Builds the packages from a fake GoReleaser dist directory, then runs the
// wrapper against the platform package for this machine.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { chmodSync, copyFileSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { PLATFORMS, makePackages, platformPackageName } from "./make-packages.mjs";

const here = dirname(fileURLToPath(import.meta.url));

const CURRENT_OS = process.platform === "win32" ? "windows" : process.platform;
const CURRENT_ARCH = process.arch === "x64" ? "amd64" : process.arch;

// A copy of the Node binary stands in for the real one on this platform, so
// the wrapper can run it on every operating system; the others are stubs.
function fakeDist(root) {
  const dist = join(root, "dist");
  for (const p of PLATFORMS) {
    const dir = join(dist, `burndrop_${p.goos}_${p.goarch}${p.goarch === "amd64" ? "_v1" : ""}`);
    mkdirSync(dir, { recursive: true });
    const exe = join(dir, p.goos === "windows" ? "burndrop.exe" : "burndrop");
    if (p.goos === CURRENT_OS && p.goarch === CURRENT_ARCH) {
      copyFileSync(process.execPath, exe);
    } else {
      writeFileSync(exe, "stub");
    }
    if (p.goos !== "windows") chmodSync(exe, 0o755);
  }
  return dist;
}

// Arguments that make the Node binary behave like a program that echoes
// its arguments and exits with 3.
const ECHO_ARGS = ["-e", "process.stdout.write('fake ' + process.argv.slice(1).join(' ')); process.exit(3)", "mcp", "--flag"];

test("makes six platform packages and the wrapper", () => {
  const root = mkdtempSync(join(tmpdir(), "burndrop-npm-"));
  const dist = fakeDist(root);
  const out = join(root, "out");
  const result = makePackages({ version: "1.2.3", dist, out });
  assert.equal(result.platforms, 6);
  const wrapper = JSON.parse(readFileSync(join(out, "burndrop", "package.json"), "utf8"));
  assert.equal(wrapper.name, "burndrop");
  assert.equal(wrapper.version, "1.2.3");
  assert.equal(wrapper.private, undefined);
  assert.equal(Object.keys(wrapper.optionalDependencies).length, 6);
  for (const p of PLATFORMS) {
    const name = platformPackageName(p.os, p.cpu);
    assert.equal(wrapper.optionalDependencies[name], "1.2.3");
    const pkg = JSON.parse(readFileSync(join(out, "platform", `${p.os}-${p.cpu}`, "package.json"), "utf8"));
    assert.deepEqual(pkg.os, [p.os]);
    assert.deepEqual(pkg.cpu, [p.cpu]);
  }
  assert.throws(() => makePackages({ version: "v1.2.3", dist, out }), /semver/);
});

test("the wrapper runs the platform binary and passes the exit code through", () => {
  const root = mkdtempSync(join(tmpdir(), "burndrop-npm-"));
  const dist = fakeDist(root);
  const out = join(root, "out");
  makePackages({ version: "1.2.3", dist, out });
  // Lay the packages out the way npm would under node_modules.
  const modules = join(root, "node_modules");
  const name = platformPackageName(process.platform, process.arch);
  const [scope, pkg] = name.split("/");
  const target = join(modules, scope, pkg);
  mkdirSync(dirname(target), { recursive: true });
  execFileSync(process.execPath, ["-e", `require("node:fs").cpSync(process.argv[1], process.argv[2], { recursive: true })`, join(out, "platform", `${process.platform}-${process.arch}`), target]);
  const bin = join(root, "bin");
  mkdirSync(bin, { recursive: true });
  writeFileSync(join(bin, "burndrop.js"), readFileSync(join(here, "bin", "burndrop.js")));
  let status = 0;
  let stdout = "";
  try {
    stdout = execFileSync(process.execPath, [join(bin, "burndrop.js"), ...ECHO_ARGS], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  } catch (err) {
    status = err.status;
    stdout = err.stdout;
  }
  assert.equal(status, 3);
  assert.match(stdout, /fake mcp --flag/);
});

test("the wrapper explains when no binary exists for the platform", () => {
  const root = mkdtempSync(join(tmpdir(), "burndrop-npm-"));
  const bin = join(root, "bin");
  mkdirSync(bin, { recursive: true });
  writeFileSync(join(bin, "burndrop.js"), readFileSync(join(here, "bin", "burndrop.js")));
  let status = 0;
  let stderr = "";
  try {
    execFileSync(process.execPath, [join(bin, "burndrop.js"), "version"], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  } catch (err) {
    status = err.status;
    stderr = err.stderr;
  }
  assert.equal(status, 1);
  assert.match(stderr, /no prebuilt binary/);
});
