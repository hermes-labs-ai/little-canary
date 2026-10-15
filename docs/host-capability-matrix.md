# Host capability matrix

Little Canary is an **inbound** sensor. It screens text on its way to a model.
Whether that screening can actually *stop* anything depends on the host, and
hosts differ more than their marketing copy suggests. This page records what
each host version can do, with the evidence, so a claim here can be checked
rather than believed.

Two capabilities are tracked separately and must not be conflated:

- **Inbound prompt screening** — can the host hand a plugin the submitted
  prompt, and can the plugin refuse it?
- **Outbound tool-execution blocking** — can the host let a plugin veto a
  tool call the model has already decided to make?

A host can have one without the other. The matrix tracks nine host surfaces;
Little Canary ships an outbound tool gate for exactly one.
OpenCode also has a separate text tool-result boundary described below: it
runs after tool execution and before the next model request.

The machine-readable source of truth for this page is
[`host-capability-matrix.json`](host-capability-matrix.json), enforced by
`tests/test_host_capability_matrix.py`.

## Matrix

| Host | Observed version | Inbound event | Can refuse the prompt? | Little Canary ships it | Outbound tool veto shipped |
|---|---|---|---|---|---|
| Claude Code | 2.1.261 | `UserPromptSubmit` | **yes** — `{"decision":"block"}` | yes | no |
| OpenCode | 1.18.32 | `chat.message` | **no** — warning only | yes | no |
| Pi | 0.87.1 and 0.99.2 | `input` | **yes** — `{"action":"handled"}` | yes | no |
| Codex CLI | 0.154.0 | `UserPromptSubmit` | **yes** — `{"decision":"block"}` | yes, install route certified; interception not observed | no |
| Gemini CLI | 0.32.1 | `BeforeAgent` | **yes** — `{"decision":"deny"}` | yes | no |
| OpenClaw | 2026.9.5 and 2026.9.6 | `before_agent_run` | **yes** — `{ "outcome": "block" }` | yes, supported embedded/CLI runners | no |
| OpenAI Agents SDK | 0.22.0 | `InputGuardrail` | **yes** — tripwire | yes | no |
| Hermes Agent | 0.21.4 | `pre_llm_call` | **no** — context injection only | yes, annotation only | **yes** — `pre_tool_call` |
| GitHub Copilot CLI | 1.0.84-5 | `userPromptSubmitted` | **no** — rewrite/annotate only | **no artifact shipped** | no |

### OpenCode

The [OpenCode package](../plugins/opencode) uses the 1.18.32 `chat.message`
hook to send the current user message's text parts to the Little Canary
loopback service. In an isolated run, a synthetic flagged verdict produced a
loopback request and a warning on stderr before the host reached its model
call. The same package also uses `tool.execute.after` to screen string tool
results. The five-file npm archive was installed in an isolated OpenCode
1.18.32 profile. A local mock provider requested a synthetic file read; pass,
unsafe, and unavailable service responses were exercised in separate runs.
The next model request received the original text on pass and unavailable, and
only a replacement notice on unsafe. Unavailable screening warned. This
certifies those hook paths with synthetic verdicts, not detector efficacy.

This stable hook has no typed input-rejection result. Even if a blocking
Little Canary service returns an unsafe verdict, the plugin warns and OpenCode
continues. A rejected string tool result can be withheld after the tool runs;
the hook cannot undo that tool call. Earlier conversation, attachments, tool
arguments, and non-text results are not screened. File text is screened only
after a tool returns it. Text items and embedded `resource.text` in raw MCP
results are screened; rejected resource text is replaced while its URI and
non-text content are preserved. Known advisory flags remain visible alongside
degraded-coverage warnings. These MCP and mixed-warning paths have offline
adapter tests backed by OpenCode 1.18.32 source inspection; they were not
exercised in an installed-host run. Service failures and results over
the server's 64 KiB request limit warn and continue with the original text. The
separate OpenCode V2 plugin API is not covered by this 1.18.32 result.

### Pi

The [Pi package](../plugins/pi) registers `input`, which Pi calls after input
arrives and before agent processing. It sends only that input's text to the
Little Canary loopback service. Pi 0.87.1 loaded the package from a local path
in an isolated profile. In a print-mode run, a loopback service returning
`safe: false` caused the extension to return `{ "action": "handled" }`; Pi
reported the block and exited without a model call. Offline tests cover clean,
flagged, degraded, and unavailable-service results. This is host-dispatch
evidence using a synthetic verdict, not a live-model detection test.
Pi 0.99.2 also installed the extension natively with
`pi install git:github.com/hermes-labs-ai/little-canary@<commit>` in an isolated
profile; the same synthetic `safe: false` verdict was handled before any model
call, and a degraded verdict continued with a coverage warning. The npm
package is not published.

The recommended advisory service mode emits warnings and lets input continue.
The Pi extension handles input only when the service explicitly returns an
unsafe verdict. It does not separately screen prior conversation, files, tool
results, or images. Pi runs registered extension commands before the `input`
event; those commands bypass this check. Skill and prompt-template expansion
happens after the event, so added content is not screened. Service failures
pass through with a warning.

## Codex CLI — what was and was not certified

Codex CLI 0.154.0 reads Claude-shaped `hooks/hooks.json` manifests, resolves
`CLAUDE_PLUGIN_ROOT`, and implements a `UserPromptSubmit` hook whose command
output schema carries a real deny channel. Its embedded schema
`user-prompt-submit.command.output` is vendored verbatim at
[`host-evidence/codex-0.154.0-user-prompt-submit.command.output.schema.json`](host-evidence/codex-0.154.0-user-prompt-submit.command.output.schema.json):
`decision` accepts the single value `"block"`, alongside `reason`,
`continue`, `stopReason`, `suppressOutput`, `systemMessage`, and
`hookSpecificOutput`, with `additionalProperties: false`.

Every object the shipped adapter can emit — the block object, the advisory
`systemMessage` object, and the bare `{}` — validates against that schema.
`tests/test_host_capability_matrix.py` asserts this against the vendored copy,
so a future adapter change that adds a field Codex rejects fails offline.

**Install route — observed.** Against an isolated `CODEX_HOME`:

```bash
codex plugin marketplace add /path/to/little-canary
codex plugin add little-canary@hermes-labs
codex plugin list
```

reported `little-canary@hermes-labs  installed, enabled  0.3.8` and copied
`hooks/hooks.json` and `scripts/little_canary_user_prompt_submit.py` into the
plugin cache.

**Interception — not observed, and this matters.** In a headless `codex exec`
run with that plugin installed and enabled, the hook did not execute, the
prompt proceeded to the model call, and Codex printed nothing about it. No
hook-trust state was written. Codex gates hook execution behind an explicit
trust approval, which a non-interactive run cannot give.

The consequence is a security property, not a footnote: **under Codex, an
untrusted Little Canary hook screens nothing and says nothing.** Installed and
enabled is not the same as screening. A maintainer must approve the hook in an
interactive Codex session, and should confirm the approval took effect before
relying on it. Until someone records that observation, this row stays
`runtime_certified: false`.

## OpenClaw — supported embedded and CLI runners

The native plugin at [`plugins/openclaw`](../plugins/openclaw) registers the
typed `before_agent_run` gate. [OpenClaw's hook contract](https://docs.openclaw.ai/plugins/hooks/prompt-and-session)
documents this hook after prompt construction and before model submission on
embedded and CLI runners;
it is not an input gate for Codex or Copilot harnesses. The adapter sends only
`event.prompt` to the local Little Canary `/check` endpoint and blocks only an
explicit `safe: false` verdict. It does not separately inspect `event.messages`
history or anything the agent reads or does later in the turn.

The operator must start Little Canary in `block` mode and grant this
non-bundled plugin `hooks.allowConversationAccess`. Service errors, malformed
results, degraded coverage, and request bodies over the service's 64 KiB limit
pass through with a warning. We verified blocking and a benign control through
`openclaw agent --local` on OpenClaw 2026.9.5 using a loopback test service and
fake local model. On 2026.9.6, the packed package loaded one hook after the
conversation-access grant; a host-dispatched block stopped before the fake
model, while pass, degraded, and unavailable-service controls reached it. In
2026.9.5, the isolated `openclaw agent exec` path bypassed plugin hooks; it
is outside tested coverage. Runtime
certification covers hook dispatch and adapter behavior only. It does not
certify the detector against a live model or establish prompt-injection
detection efficacy. The package supports the tested OpenClaw 2026.9.5–2026.9.6
range; later host versions need a separate compatibility check.

## GitHub Copilot CLI — certified as unable to refuse a prompt

GitHub Copilot CLI 1.0.84-5 (app bundle 1.1.22, SDK protocol 3) has a hook
subsystem that includes `userPromptSubmitted`, documented as running *after*
the user submits a prompt. It has no deny channel. The SDK's own declarations,
vendored at
[`host-evidence/copilot-cli-1.0.84-5-hook-outputs.d.ts`](host-evidence/copilot-cli-1.0.84-5-hook-outputs.d.ts),
are unambiguous:

```ts
export interface UserPromptSubmittedHookOutput {
    modifiedPrompt?: string;
    additionalContext?: string;
    suppressOutput?: boolean;
}
```

A hook may rewrite the prompt or append context. It cannot refuse it. The
prompt reaches the model either way. Only `PreToolUseHookOutput` carries
`permissionDecision?: "allow" | "deny" | "ask"` — that is an *outbound* tool
control, not inbound screening.

Copilot's file-configured hooks also use a different manifest than Claude Code
and Codex: `.github/hooks/*.json`, `version: 1`, camelCase event names, and
`bash`/`timeoutSec` rather than `command`/`timeout`. The `plugins/claude-code`
manifest is not loadable by Copilot.

Little Canary therefore ships **no GitHub Copilot artifact**. A Copilot-facing
marketplace that lists this plugin is offering an install route for other
hosts; it is not evidence that Copilot screens prompts. This row is
artifact-certified from the installed SDK declarations. The Copilot CLI itself
was not installed on the machine used, so no run was exercised.

## Hermes Agent — the inverted case

Hermes Agent is the one host where Little Canary blocks on the way *out*
rather than on the way *in*. `pre_llm_call` is a context-injection hook with
no deny channel, so a `BLOCK` verdict cannot stop prompt delivery: the turn
still reaches the model, annotated with the disposition, and loses its tool
authority instead. `pre_tool_call` returns the host's documented
`{"action": "block", "message": ...}` directive and the tool does not execute.

Read the matrix row rather than assuming: a blocked Hermes Agent turn is a
turn whose *tools* were withdrawn, not a turn that was refused.

## Live-model caveats

Nothing in this matrix is a claim about detection quality, and none of these
acceptance tests exercise a model.

- The repository's acceptance suite is offline. Network calls are mocked, and
  a passing suite proves wire contracts and routing semantics, not detection
  accuracy.
- Behavioral coverage that did not run is never a PASS. `degraded`,
  `unexercised`, and an unavailable replay are reported as themselves.
- All inbound adapters are **fail-open by default**. A canary backend that is
  down, a transport error, or an unexercised probe allows the prompt through
  with a visible warning. `LITTLE_CANARY_FAILURE_MODE=deny` reverses this for
  the hook adapters; `on_degraded="fail_closed"` does so for the Agents SDK
  guardrail.
- A live result is bound to one backend, model digest, runtime, and
  configuration. Evidence gathered on one endpoint does not transfer to
  another.
- Screening covers the submitted prompt only. Tool results, retrieved
  documents, file contents, and model output are outside every adapter here.

## Re-certifying

Host versions move. To re-check a row, install the host, re-read its shipped
declarations, and update both `host-capability-matrix.json` and this page in
the same change. Do not raise a `runtime_certified` flag on manifest parsing
alone — that is the exact failure this page exists to prevent.
