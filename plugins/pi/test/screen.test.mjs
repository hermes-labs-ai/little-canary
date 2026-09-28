import assert from "node:assert/strict";
import { test } from "node:test";
import { createInputHandler, DEFAULT_ENDPOINT } from "../screen.js";

const input = { type: "input", source: "interactive", text: "inspect this" };

function context() {
  const notices = [];
  return { ctx: { hasUI: true, ui: { notify: (...args) => notices.push(args) } }, notices };
}

function response(verdict) {
  return { ok: true, json: async () => verdict };
}

test("safe input reaches Pi unchanged", async () => {
  let request;
  const { ctx, notices } = context();
  const handler = createInputHandler({ fetchImpl: async (url, options) => {
    request = { url, options };
    return response({ safe: true, degraded: false, canary_status: "exercised" });
  } });
  assert.deepEqual(await handler(input, ctx), { action: "continue" });
  assert.equal(request.url, DEFAULT_ENDPOINT);
  assert.equal(request.options.redirect, "error");
  assert.deepEqual(JSON.parse(request.options.body), { text: input.text });
  assert.deepEqual(notices, []);
});

test("unsafe verdict handles input before model processing", async () => {
  const { ctx, notices } = context();
  const handler = createInputHandler({ fetchImpl: async () => response({ safe: false }) });
  assert.deepEqual(await handler(input, ctx), { action: "handled" });
  assert.match(notices[0][0], /blocked this input/);
});

test("flagged advisory continues with a warning", async () => {
  const { ctx, notices } = context();
  const handler = createInputHandler({ fetchImpl: async () => response({
    safe: true, degraded: false, canary_status: "exercised", advisory: { flagged: true },
  }) });
  assert.deepEqual(await handler(input, ctx), { action: "continue" });
  assert.match(notices[0][0], /flagged this input/);
});

test("degraded and unavailable screening continue with warnings", async () => {
  const { ctx, notices } = context();
  const degraded = createInputHandler({ fetchImpl: async () => response({
    safe: true, degraded: true, canary_status: "failed",
  }) });
  assert.deepEqual(await degraded(input, ctx), { action: "continue" });
  assert.match(notices[0][0], /incomplete/);
  const unavailable = createInputHandler({ fetchImpl: async () => { throw new Error("offline"); } });
  assert.deepEqual(await unavailable(input, ctx), { action: "continue" });
  assert.match(notices[1][0], /unavailable/);
});

test("invalid endpoint cannot send the input to a remote host", async () => {
  let called = false;
  const { ctx, notices } = context();
  const handler = createInputHandler({
    endpoint: "https://example.com/check",
    fetchImpl: async () => { called = true; return response({ safe: true }); },
  });
  assert.deepEqual(await handler(input, ctx), { action: "continue" });
  assert.equal(called, false);
  assert.match(notices[0][0], /unavailable/);
});

test("empty input does not call the screening service", async () => {
  const handler = createInputHandler({ fetchImpl: async () => { throw new Error("unexpected"); } });
  assert.deepEqual(await handler({ ...input, text: "" }, context().ctx), { action: "continue" });
});
