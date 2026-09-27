import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const manifest = JSON.parse(readFileSync(resolve(root, "package.json"), "utf8"));

test("Pi package version matches the core release", () => {
  assert.equal(manifest.name, "@hermes-labs/little-canary-pi");
  const core = readFileSync(resolve(root, "../../little_canary/__init__.py"), "utf8");
  const version = core.match(/^__version__ = "([^"]+)"/m)?.[1];
  assert.equal(manifest.version, version);
  const readme = readFileSync(resolve(root, "README.md"), "utf8");
  assert.ok(readme.includes(`pi install npm:${manifest.name}@${version}`));
});

test("npm archive contains only the standalone Pi package", () => {
  const output = execFileSync("npm", ["pack", "--dry-run", "--json"], { cwd: root, encoding: "utf8" });
  const files = JSON.parse(output)[0].files.map((file) => file.path).sort();
  assert.deepEqual(files, ["LICENSE", "README.md", "index.js", "package.json", "screen.js"]);
});
