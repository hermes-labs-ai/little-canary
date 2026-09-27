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

export async function checkText(text, {
  endpoint = process.env.LITTLE_CANARY_ENDPOINT || DEFAULT_ENDPOINT,
  fetchImpl = globalThis.fetch,
} = {}) {
  if (typeof text !== "string" || text.length === 0) return "skip";
  const url = loopbackUrl(endpoint);
  if (!url || typeof fetchImpl !== "function") return "unavailable";

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
    if (verdict.safe === false) return "block";
    if (verdict.degraded === true || verdict.canary_status !== "exercised") {
      return "degraded";
    }
    if (verdict.advisory?.flagged === true) return "flag";
    return "pass";
  } catch {
    return "unavailable";
  }
}

export async function screenMessage(text, options) {
  const result = await checkText(text, options);
  if (result === "block") return "Prompt rejected by the screening service; this OpenCode hook cannot block the turn.";
  if (result === "degraded") return "Screening coverage is incomplete; OpenCode continued.";
  if (result === "flag") return "Prompt flagged; OpenCode continued.";
  if (result === "unavailable") return "Screening unavailable; OpenCode continued.";
  return null;
}
