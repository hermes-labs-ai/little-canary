// Verbatim excerpts from the GitHub Copilot CLI SDK type declarations.
//
// Source file:  <GitHub Copilot.app>/Contents/Resources/copilot-sdk/types.d.ts
// COPILOT_CLI_VERSION: 1.0.84-5   (copilot-sdk/cliVersion.d.ts)
// App CFBundleShortVersionString: 1.1.22
// SDK_PROTOCOL_VERSION: 3
// Read on: 2026-09-18
//
// Evidence for one claim in docs/host-capability-matrix.md: the Copilot
// pre-tool-use hook carries a deny channel and the user-prompt-submitted hook
// does not. Do not edit; re-extract from the installed CLI instead.

/**
 * Output for pre-tool-use hook
 */
export interface PreToolUseHookOutput {
    permissionDecision?: "allow" | "deny" | "ask";
    permissionDecisionReason?: string;
    modifiedArgs?: unknown;
    additionalContext?: string;
    suppressOutput?: boolean;
}

/**
 * Input for user-prompt-submitted hook
 */
export interface UserPromptSubmittedHookInput extends BaseHookInput {
    prompt: string;
}
/**
 * Output for user-prompt-submitted hook
 */
export interface UserPromptSubmittedHookOutput {
    modifiedPrompt?: string;
    additionalContext?: string;
    suppressOutput?: boolean;
}
/**
 * Handler for user-prompt-submitted hook
 */
export type UserPromptSubmittedHandler = (input: UserPromptSubmittedHookInput, invocation: {
    sessionId: string;
}) => Promise<UserPromptSubmittedHookOutput | void> | UserPromptSubmittedHookOutput | void;
