import { screenMessage } from "./screen.js";

export const LittleCanaryPlugin = async ({ client }) => ({
  "chat.message": async (_input, output) => {
    const text = output.parts
      .filter((part) => part.type === "text" && !part.synthetic && !part.ignored)
      .map((part) => part.text)
      .join("\n");
    if (!text) return;

    const warning = await screenMessage(text);
    if (!warning) return;
    try {
      await client.tui.showToast({ body: {
        title: "Little Canary",
        message: warning,
        variant: "warning",
      } });
    } catch {
      // A CLI run may have no TUI subscriber.
    }
    process.stderr.write(`Little Canary: ${warning}\n`);
  },
});
