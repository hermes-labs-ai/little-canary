export const DEFAULT_ENDPOINT = "http://127.0.0.1:18421/check";
const TIMEOUT_MS = 3000;

function loopbackUrl(value) {
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

export async function screenMessage(text, {
  endpoint = process.env.LITTLE_CANARY_ENDPOINT || DEFAULT_ENDPOINT,
  fetchImpl = globalThis.fetch,
} = {}) {
  if (typeof text !== "string" || text.length === 0) return null;
  const url = loopbackUrl(endpoint);
  if (!url || typeof fetchImpl !== "function") return "Screening unavailable; OpenCode continued.";

  try {
    const response = await fetchImpl(url, {
      method: "POST",
      redirect: "error",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ text }),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (!response.ok) throw new Error("service error");
    const verdict = await response.json();
    if (typeof verdict?.safe !== "boolean") throw new Error("invalid verdict");
    if (verdict.safe === false) {
      return "Prompt rejected by the screening service; this OpenCode hook cannot block the turn.";
    }
    if (verdict.degraded === true || verdict.canary_status !== "exercised") {
      return "Screening coverage is incomplete; OpenCode continued.";
    }
    if (verdict.advisory?.flagged === true) return "Prompt flagged; OpenCode continued.";
    return null;
  } catch {
    return "Screening unavailable; OpenCode continued.";
  }
}
