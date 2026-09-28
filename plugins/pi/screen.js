export const DEFAULT_ENDPOINT = "http://127.0.0.1:18421/check";
export const DEFAULT_TIMEOUT_MS = 3000;

function checkUrl(value) {
  try {
    const url = new URL(value);
    if (
      url.protocol !== "http:" ||
      !["127.0.0.1", "localhost", "[::1]"].includes(url.hostname) ||
      url.pathname !== "/check" ||
      url.username || url.password || url.search || url.hash
    ) return null;
    return url.href;
  } catch {
    return null;
  }
}

function report(ctx, message, level = "warning") {
  try {
    if (ctx?.hasUI && typeof ctx.ui?.notify === "function") {
      ctx.ui.notify(message, level);
    } else {
      process.stderr.write(`${message}\n`);
    }
  } catch {
    // A broken notification channel must not change a handled block.
  }
}

export function createInputHandler({
  endpoint = process.env.LITTLE_CANARY_ENDPOINT || DEFAULT_ENDPOINT,
  fetchImpl = globalThis.fetch,
} = {}) {
  const url = checkUrl(endpoint);
  return async (event, ctx) => {
    if (typeof event?.text !== "string" || event.text.length === 0) {
      return { action: "continue" };
    }
    if (!url || typeof fetchImpl !== "function") {
      report(ctx, "Little Canary screening unavailable; Pi continued.");
      return { action: "continue" };
    }

    try {
      const response = await fetchImpl(url, {
        method: "POST",
        redirect: "error",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ text: event.text }),
        signal: AbortSignal.timeout(DEFAULT_TIMEOUT_MS),
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const verdict = await response.json();
      if (typeof verdict?.safe !== "boolean") throw new Error("invalid verdict");

      if (verdict.safe === false) {
        report(ctx, "Little Canary blocked this input before Pi started the turn.", "error");
        return { action: "handled" };
      }
      if (verdict.degraded === true || verdict.canary_status !== "exercised") {
        report(ctx, "Little Canary coverage is incomplete; Pi continued.");
      } else if (verdict.advisory?.flagged === true) {
        report(ctx, "Little Canary flagged this input; Pi continued.");
      }
      return { action: "continue" };
    } catch {
      report(ctx, "Little Canary screening unavailable; Pi continued.");
      return { action: "continue" };
    }
  };
}
