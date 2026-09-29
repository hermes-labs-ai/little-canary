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

test("tool.execute.after replaces rejected text before OpenCode receives the result", async () => {
  const originalFetch = globalThis.fetch;
  const originalEndpoint = process.env.LITTLE_CANARY_ENDPOINT;
  const originalWrite = process.stderr.write;
  let sent;
  let terminalWarning = "";
  try {
    delete process.env.LITTLE_CANARY_ENDPOINT;
    process.stderr.write = (chunk) => { terminalWarning += chunk; return true; };
    globalThis.fetch = async (_url, options) => {
      sent = JSON.parse(options.body);
      return { ok: true, json: async () => ({ safe: false }) };
    };
    const hooks = await LittleCanaryPlugin({ client: { tui: { showToast: async () => ({ data: true }) } } });
    const output = { title: "read", output: "untrusted tool result", metadata: {} };
    await hooks["tool.execute.after"]({ tool: "read", sessionID: "test", callID: "call" }, output);
    assert.deepEqual(sent, { text: "untrusted tool result" });
    assert.match(output.output, /withheld this tool result/);
    assert.doesNotMatch(output.output, /untrusted tool result/);
    assert.match(terminalWarning, /withheld before OpenCode sent it to the model/);
  } finally {
    globalThis.fetch = originalFetch;
    process.stderr.write = originalWrite;
    if (originalEndpoint === undefined) delete process.env.LITTLE_CANARY_ENDPOINT;
    else process.env.LITTLE_CANARY_ENDPOINT = originalEndpoint;
  }
});

test("tool results stay intact on pass, flag, degraded, and unavailable outcomes", async () => {
  const originalFetch = globalThis.fetch;
  const originalEndpoint = process.env.LITTLE_CANARY_ENDPOINT;
  const originalWrite = process.stderr.write;
  let terminalWarning = "";
  try {
    delete process.env.LITTLE_CANARY_ENDPOINT;
    process.stderr.write = (chunk) => { terminalWarning += chunk; return true; };
    const hooks = await LittleCanaryPlugin({ client: { tui: { showToast: async () => ({ data: true }) } } });
    const cases = [
      [{ safe: true, degraded: false, canary_status: "exercised" }, null],
      [{ safe: true, degraded: false, canary_status: "exercised", advisory: { flagged: true } }, /flagged/],
      [{ safe: true, degraded: true, canary_status: "failed" }, /incomplete/],
      [{ safe: true, degraded: true, canary_status: "failed", advisory: { flagged: true } }, /flagged; screening coverage is incomplete/],
    ];
    for (const [verdict, warning] of cases) {
      globalThis.fetch = async () => ({ ok: true, json: async () => verdict });
      terminalWarning = "";
      const output = { title: "read", output: "original", metadata: {} };
      await hooks["tool.execute.after"]({ tool: "read", sessionID: "test", callID: "call" }, output);
      assert.equal(output.output, "original");
      if (warning) assert.match(terminalWarning, warning);
      else assert.equal(terminalWarning, "");
    }
    globalThis.fetch = async () => { throw new Error("offline"); };
    terminalWarning = "";
    const unavailable = { title: "read", output: "original", metadata: {} };
    await hooks["tool.execute.after"]({ tool: "read", sessionID: "test", callID: "call" }, unavailable);
    assert.equal(unavailable.output, "original");
    assert.match(terminalWarning, /unavailable/);
  } finally {
    globalThis.fetch = originalFetch;
    process.stderr.write = originalWrite;
    if (originalEndpoint === undefined) delete process.env.LITTLE_CANARY_ENDPOINT;
    else process.env.LITTLE_CANARY_ENDPOINT = originalEndpoint;
  }
});

test("raw MCP text content is screened and replaced on an unsafe verdict", async () => {
  const originalFetch = globalThis.fetch;
  const originalWrite = process.stderr.write;
  let sent;
  try {
    process.stderr.write = () => true;
    globalThis.fetch = async (_url, options) => {
      sent = JSON.parse(options.body);
      return { ok: true, json: async () => ({ safe: false }) };
    };
    const hooks = await LittleCanaryPlugin({ client: {} });
    const result = { isError: false, content: [
      { type: "text", text: "untrusted MCP result" },
      { type: "image", data: "opaque", mimeType: "image/png" },
      { type: "text", text: "more untrusted text" },
      { type: "resource", resource: { uri: "test://document", text: "nested untrusted text" } },
    ] };
    await hooks["tool.execute.after"]({ tool: "mcp_example" }, result);
    assert.deepEqual(sent, { text: "untrusted MCP result\nmore untrusted text\nnested untrusted text" });
    assert.ok(result.content[0].text.includes("withheld this tool result"));
    assert.ok(result.content[2].text.includes("withheld this tool result"));
    assert.match(result.content[3].resource.text, /withheld this tool result/);
    assert.equal(result.content[3].resource.uri, "test://document");
    assert.deepEqual(result.content[1], { type: "image", data: "opaque", mimeType: "image/png" });
  } finally {
    globalThis.fetch = originalFetch;
    process.stderr.write = originalWrite;
  }
});
