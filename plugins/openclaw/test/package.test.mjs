import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import test from "node:test";
import { fileURLToPath } from "node:url";

const pluginDir = fileURLToPath(new URL("../", import.meta.url));
const manifest = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
const coreSource = readFileSync(new URL("../../../little_canary/__init__.py", import.meta.url), "utf8");
const coreVersion = coreSource.match(/^__version__ = "([^"]+)"$/m)?.[1];

test("package version matches core and ships the intended six files", () => {
  assert.ok(coreVersion, "Little Canary core version is declared");
  assert.equal(manifest.name, "@hermes-labs-ai/little-canary-openclaw");
  assert.equal(manifest.version, coreVersion);
  assert.notEqual(manifest.private, true);
  assert.match(readFileSync(new URL("../README.md", import.meta.url), "utf8"), new RegExp(`little-canary==${coreVersion.replaceAll(".", "\\.")}`));

  const packed = JSON.parse(execFileSync("npm", ["pack", "--dry-run", "--json", "--ignore-scripts"], {
    cwd: pluginDir,
    encoding: "utf8",
  }));
  assert.equal(packed.length, 1);
  assert.equal(packed[0].name, manifest.name);
  assert.equal(packed[0].version, manifest.version);
  assert.deepEqual(
    packed[0].files.map((file) => file.path).sort(),
    ["LICENSE", "README.md", "index.mjs", "openclaw.plugin.json", "package.json", "screen.mjs"],
  );
});
