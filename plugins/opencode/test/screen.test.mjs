import assert from "node:assert/strict";
import { test } from "node:test";
import { DEFAULT_ENDPOINT, screenMessage } from "../screen.js";

const reply = (verdict) => ({ ok: true, json: async () => verdict });

test("clean message sends only its text to loopback and returns no warning", async () => {
  let request;
  const warning = await screenMessage("inspect this", { fetchImpl: async (url, options) => {
    request = { url, options };
    return reply({ safe: true, degraded: false, canary_status: "exercised" });
  } });
  assert.equal(warning, null);
  assert.equal(request.url, DEFAULT_ENDPOINT);
  assert.equal(request.options.redirect, "error");
  assert.deepEqual(JSON.parse(request.options.body), { text: "inspect this" });
});

test("advisory flag warns that OpenCode continues", async () => {
  const warning = await screenMessage("inspect this", { fetchImpl: async () => reply({
    safe: true, degraded: false, canary_status: "exercised", advisory: { flagged: true },
  }) });
  assert.match(warning, /flagged; OpenCode continued/);
});

test("unsafe service verdict is not falsely represented as a host block", async () => {
  const warning = await screenMessage("inspect this", { fetchImpl: async () => reply({ safe: false }) });
  assert.match(warning, /cannot block the turn/);
});

test("degraded or unavailable screening warns and continues", async () => {
  assert.match(await screenMessage("x", { fetchImpl: async () => reply({
    safe: true, degraded: true, canary_status: "failed",
  }) }), /incomplete/);
  assert.match(await screenMessage("x", { fetchImpl: async () => { throw new Error("offline"); } }), /unavailable/);
});

test("invalid endpoint cannot send a prompt to a remote host", async () => {
  let called = false;
  const warning = await screenMessage("private prompt", {
    endpoint: "https://example.com/check",
    fetchImpl: async () => { called = true; return reply({ safe: true }); },
  });
  assert.equal(called, false);
  assert.match(warning, /unavailable/);
});

test("empty text does not call the screening service", async () => {
  assert.equal(await screenMessage("", { fetchImpl: async () => { throw new Error("called"); } }), null);
});


test("degraded coverage preserves known advisory flag", async () => {
  const warning = await screenMessage("inspect this", { fetchImpl: async () => reply({
    safe: true, degraded: true, canary_status: "failed", advisory: { flagged: true },
  }) });
  assert.match(warning, /flagged/);
  assert.match(warning, /coverage is incomplete/);
});
