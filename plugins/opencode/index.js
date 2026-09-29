import { checkText, screenMessage } from "./screen.js";

async function warn(client, message) {
  try {
    await client?.tui?.showToast({ body: {
      title: "Little Canary",
      message,
      variant: "warning",
    } });
  } catch {
    // A CLI run may have no TUI subscriber.
  }
  process.stderr.write(`Little Canary: ${message}\n`);
}

export const LittleCanaryPlugin = async ({ client }) => ({
  "chat.message": async (_input, output) => {
    const text = output.parts
      .filter((part) => part.type === "text" && !part.synthetic && !part.ignored)
      .map((part) => part.text)
      .join("\n");
    if (!text) return;

    const warning = await screenMessage(text);
    if (!warning) return;
    await warn(client, warning);
  },
  "tool.execute.after": async (_input, output) => {
    const resultText = typeof output?.output === "string" ? output.output : "";
    const contentText = Array.isArray(output?.content)
      ? output.content.flatMap((part) => {
          const target = part?.type === "resource" ? part.resource : part?.type === "text" ? part : null;
          return typeof target?.text === "string" && target.text ? [target] : [];
        })
      : [];
    const text = [resultText, ...contentText.map((part) => part.text)].filter(Boolean).join("\n");
    if (!text) return;
    const result = await checkText(text);
    if (result === "block") {
      const notice = "[Little Canary withheld this tool result after the tool ran; the screening service rejected its text.]";
      if (resultText) output.output = notice;
      for (const part of contentText) part.text = notice;
      await warn(client, "Tool result withheld before OpenCode sent it to the model.");
    } else if (result === "flag-degraded") {
      await warn(client, "Tool result flagged; screening coverage is incomplete; OpenCode continued.");
    } else if (result === "flag") {
      await warn(client, "Tool result flagged; OpenCode continued.");
    } else if (result === "degraded") {
      await warn(client, "Tool-result screening coverage is incomplete; OpenCode continued.");
    } else if (result === "unavailable") {
      await warn(client, "Tool-result screening unavailable; OpenCode continued.");
    }
  },
});
