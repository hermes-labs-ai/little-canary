export const DEFAULT_SERVICE_URL = "http://127.0.0.1:18421";
export const REQUEST_TIMEOUT_MS = 10_000;

const BLOCK_MESSAGE =
  "Little Canary blocked this run. Review the prompt and screening details before retrying.";

function warn(logger, message) {
  try {
    logger?.warn?.(`[little-canary-openclaw] ${message}`);
  } catch {
    // Logging must never change the host's fail-open behavior.
  }
}

export function checkUrlFor(serviceUrl = DEFAULT_SERVICE_URL) {
  try {
    const url = new URL(serviceUrl);
    if (
      url.protocol !== "http:" ||
      url.hostname !== "127.0.0.1" ||
      url.username ||
      url.password ||
      url.pathname !== "/" ||
      url.search ||
      url.hash
    ) {
      return null;
    }
    return `${url.origin}/check`;
  } catch {
    return null;
  }
}

export function createBeforeAgentRunHandler({
  serviceUrl = DEFAULT_SERVICE_URL,
  fetchImpl = globalThis.fetch,
  logger,
} = {}) {
  const checkUrl = checkUrlFor(serviceUrl);

  return async (event) => {
    const prompt = event?.prompt;
    if (typeof prompt !== "string" || prompt.length === 0) {
      return { outcome: "pass" };
    }
    if (!checkUrl || typeof fetchImpl !== "function") {
      warn(logger, "screening service URL or fetch is unavailable; allowing run");
      return { outcome: "pass" };
    }

    try {
      const response = await fetchImpl(checkUrl, {
        method: "POST",
        // Never forward the prompt if a local service attempts to redirect it.
        redirect: "error",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ text: prompt }),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
      if (!response.ok) {
        warn(logger, `screening service returned HTTP ${response.status}; allowing run`);
        return { outcome: "pass" };
      }

      const verdict = await response.json();
      if (!verdict || typeof verdict !== "object" || typeof verdict.safe !== "boolean") {
        warn(logger, "screening service returned an unreadable verdict; allowing run");
        return { outcome: "pass" };
      }
      if (verdict.safe === false) {
        return {
          outcome: "block",
          reason: "Little Canary returned an unsafe verdict.",
          message: BLOCK_MESSAGE,
        };
      }
      if (verdict.degraded === true) {
        warn(logger, "screening coverage is degraded; allowing run");
      }
      return { outcome: "pass" };
    } catch (error) {
      const kind = error instanceof Error ? error.name : "unknown error";
      warn(logger, `screening failed (${kind}); allowing run`);
      return { outcome: "pass" };
    }
  };
}
