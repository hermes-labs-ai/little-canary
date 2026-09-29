# 04 — Why the same screening cannot stop a prompt on one host

**Evidence:** quoted upstream SDK declarations, `docs/host-evidence/copilot-cli-1.0.84-5-hook-outputs.d.ts` (GitHub Copilot CLI `1.0.84-5`, SDK protocol 3, read 2026-09-18), and the matching row in `docs/host-capability-matrix.json`.

## Input

Copilot's hook output types, abridged from the committed declarations (`// ...` marks omitted members):

```ts
export interface PreToolUseHookOutput {
    permissionDecision?: "allow" | "deny" | "ask";
    // ...
}
export interface UserPromptSubmittedHookOutput {
    modifiedPrompt?: string;
    additionalContext?: string;
    suppressOutput?: boolean;
}
```

## Output

The matrix records for `github-copilot`: inbound event `userPromptSubmitted`, `deny_channel: false`, `shipped: false`; the outbound `preToolUse` event does have a host deny channel, but Little Canary ships no artifact for it. Little Canary therefore ships **no Copilot artifact**: a hook there could rewrite or annotate a prompt, but the prompt would still reach the model.

## Limits

- Artifact-certified only: the Copilot CLI was not installed on the certifying machine, so no run was exercised.
- Read from one version (`1.0.84-5`). A later Copilot release may change the types.
- A Copilot marketplace listing of this plugin is an install route for other hosts, not evidence of Copilot prompt screening.
