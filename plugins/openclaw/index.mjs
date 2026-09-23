import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import { createBeforeAgentRunHandler, DEFAULT_SERVICE_URL } from "./screen.mjs";

export default definePluginEntry({
  id: "little-canary-openclaw",
  name: "Little Canary",
  description: "Screen the current prompt through the local Little Canary service.",
  register(api) {
    const config = api.pluginConfig ?? {};
    const serviceUrl =
      typeof config.serviceUrl === "string" ? config.serviceUrl : DEFAULT_SERVICE_URL;
    api.on(
      "before_agent_run",
      createBeforeAgentRunHandler({
        serviceUrl,
        logger: api.logger,
      }),
      { timeoutMs: 12_000 },
    );
  },
});
