import assert from "node:assert/strict";
import { test } from "node:test";
import { LittleCanaryPlugin } from "../index.js";

test("chat.message checks only submitted text and leaves the message intact", async () => {
  const originalFetch = globalThis.fetch;
  const originalEndpoint = process.env.LITTLE_CANARY_ENDPOINT;
  const originalWrite = process.stderr.write;
  let sent;
  let terminalWarning = "";
  const toasts = [];
  try {
    delete process.env.LITTLE_CANARY_ENDPOINT;
    process.stderr.write = (chunk) => { terminalWarning += chunk; return true; };
    globalThis.fetch = async (_url, options) => {
      sent = JSON.parse(options.body);
      return { ok: true, json: async () => ({
        safe: true, degraded: false, canary_status: "exercised", advisory: { flagged: true },
      }) };
    };
    const hooks = await LittleCanaryPlugin({
      client: { tui: { showToast: async (toast) => { toasts.push(toast); return { data: true }; } } },
    });
    const output = {
      message: { role: "user" },
      parts: [
        { type: "text", text: "current prompt" },
        { type: "text", text: "hidden", synthetic: true },
        { type: "file", filename: "private.txt" },
      ],
    };
    const before = structuredClone(output);
    await hooks["chat.message"]({ sessionID: "test" }, output);
    assert.deepEqual(sent, { text: "current prompt" });
    assert.deepEqual(output, before);
    assert.equal(toasts.length, 1);
    assert.match(toasts[0].body.message, /flagged; OpenCode continued/);
    assert.match(terminalWarning, /flagged; OpenCode continued/);
  } finally {
    globalThis.fetch = originalFetch;
    process.stderr.write = originalWrite;
    if (originalEndpoint === undefined) delete process.env.LITTLE_CANARY_ENDPOINT;
    else process.env.LITTLE_CANARY_ENDPOINT = originalEndpoint;
  }
});
