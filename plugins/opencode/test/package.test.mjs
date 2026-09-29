import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { test } from "node:test";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const manifest = JSON.parse(readFileSync(resolve(root, "package.json"), "utf8"));

test("OpenCode package version matches the core release", () => {
  assert.equal(manifest.name, "@hermes-labs/little-canary-opencode");
  const core = readFileSync(resolve(root, "../../little_canary/__init__.py"), "utf8");
  const version = core.match(/^__version__ = "([^"]+)"/m)?.[1];
  assert.equal(manifest.version, version);
  const readme = readFileSync(resolve(root, "README.md"), "utf8");
  assert.ok(readme.includes('opencode plugin "$(pwd)/little-canary-source/plugins/opencode"'));
  assert.ok(!readme.includes(`opencode plugin ${manifest.name}@`), "unpublished npm package must not be the install route");
});

// OpenCode 1.18.32's installer uses this main-target predicate after checking
// exports["./server"]. A root export alone is not an installer target.
// https://github.com/anomalyco/opencode/blob/545f51d26cc39a907d2867492d498d9607ea5fa4/packages/opencode/src/plugin/install.ts#L139-L154
function hasMainTarget(pkg) {
  const main = pkg.main;
  if (typeof main !== "string") return false;
  return Boolean(main.trim());
}

test("the local package directory resolves its main and loads legacy server hooks", async () => {
  // OpenCode 1.18.32 shared.ts:175-185 resolves an absolute directory with a
  // package.json to a file URL; plugin/index.ts:99-124 loads function exports.
  const target = pathToFileURL(root);
  const directory = fileURLToPath(target);
  const local = JSON.parse(readFileSync(resolve(directory, "package.json"), "utf8"));
  assert.ok(hasMainTarget(local));
  const module = await import(pathToFileURL(resolve(directory, local.main)));
  for (const entry of new Set(Object.values(module))) {
    assert.equal(typeof entry, "function", "legacy server exports must be plugin functions");
    const hooks = await entry({ client: {} });
    assert.equal(typeof hooks["chat.message"], "function");
    assert.equal(typeof hooks["tool.execute.after"], "function");
  }
});

test("npm archive exposes an installable OpenCode server target and loads its hooks", async () => {
  const directory = mkdtempSync(resolve(tmpdir(), "little-canary-opencode-package-"));
  try {
    const output = execFileSync("npm", ["pack", "--json", "--pack-destination", directory], { cwd: root, encoding: "utf8" });
    const [archive] = JSON.parse(output);
    assert.deepEqual(archive.files.map((file) => file.path).sort(), ["LICENSE", "README.md", "index.js", "package.json", "screen.js"]);
    execFileSync("tar", ["-xf", resolve(directory, archive.filename), "-C", directory]);
    const packed = JSON.parse(readFileSync(resolve(directory, "package/package.json"), "utf8"));
    assert.ok(hasMainTarget(packed), "OpenCode's installer must recognize a server target");
    const plugin = await import(pathToFileURL(resolve(directory, "package", packed.main)));
    const hooks = await plugin.LittleCanaryPlugin({ client: {} });
    assert.equal(typeof hooks["chat.message"], "function");
    assert.equal(typeof hooks["tool.execute.after"], "function");
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("the old exports-only manifest is not an OpenCode installer target", () => {
  const exportsOnly = { ...manifest, main: undefined, exports: { ".": "./index.js" } };
  assert.equal(hasMainTarget(exportsOnly), false);
  assert.equal(exportsOnly.exports["./server"], undefined);
});
