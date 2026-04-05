# ADR-0001: Verification Unit Is Agent Execution

## Status

Accepted

## Date

2026-04-05

## Context

libverify was originally designed to verify SDLC artifacts at commit/PR/release boundaries. The 44 existing controls assume a human-driven workflow: PRs exist, reviewers approve, branches are protected.

AI agent-driven development ("Dark Factory", "AI-ops") breaks these assumptions. Agents push directly to main, bypass PRs, and perform tool calls (MCP, shell, API) autonomously.

The initial reaction was to limit libverify's scope to commit-time verification only, excluding runtime agent behavior. However, this creates a gap: agent tool use (MCP tool calls, shell commands, API invocations) is the primary surface area where safety violations occur, and these are observable as structured evidence after an agent execution unit completes.

## Decision

**The verification unit for AI-ops controls is the agent execution, not just the commit.**

An agent execution is a bounded unit of work: an agent receives an intent, performs a sequence of tool calls, and produces artifacts (code changes, commits). libverify verifies this execution unit as a whole, after it completes but before its outputs are promoted (merged, released, deployed).

This means:

1. **MCP tool use is a first-class evidence source.** `AgentActionLog` captures tool calls with tool name, command, timestamps, and required permissions. This is not runtime interception — it is structured evidence collected from the agent's execution log after the execution completes.

2. **AI-ops controls are verifiers, not classifiers.** They detect sandbox bypass and spec deviation from monitoring logs. No fine-grained permission taxonomy — just "did the agent do something it shouldn't have?"
   - `harness-result` — CI harnesses passed for this execution's output
   - `destructive-action-detection` — execution log contains no destructive tool calls
   - `agent-spec-conformance` — execution conformed to spec (paths, tools, budget)
   - `privileged-operation-audit` — no unauthorized privileged git operations occurred

3. **The verification timing is post-execution, pre-promotion.** Like how existing controls verify a PR before merge, AI-ops controls verify an agent execution before its outputs are accepted.

```
agent receives intent
  -> agent executes (tool calls, file edits, commits)
  -> execution completes
  -> evidence collected (action log, execution record, check runs, git events)
  -> libverify evaluates (all 48 controls)
  -> gate decision (pass/review/fail)
  -> outputs promoted or rejected
```

## Consequences

- `AgentActionLog`, `AgentSpec`, `AgentExecution`, `PrivilegedGitEvent` remain as evidence types in `EvidenceBundle`
- Agent frameworks (Claude Code, Cursor, Copilot) are expected to produce structured execution logs that adapters convert to `EvidenceBundle`
- libverify does NOT intercept or block tool calls at runtime. That is the agent framework's responsibility. libverify verifies the completed execution record.
- The `aiops` OPA preset treats AI-ops controls as strict (violated -> fail) and PR-ceremony controls as advisory (violated -> review)
- Future evidence adapters will parse MCP tool_use events, Claude Code session logs, and similar sources into `AgentActionLog` format

## Alternatives Considered

### Commit-only verification (rejected)

Limit AI-ops controls to what is observable at `git commit` time (file diffs, check runs, git events). This excludes the agent's tool call history, which is the primary attack surface. Rejected because it leaves a critical verification gap.

### Runtime interception (out of scope)

Have libverify intercept and gate tool calls in real-time. Rejected because libverify is a verification engine, not an agent runtime. Runtime gating is the responsibility of the agent framework or orchestrator (e.g., pleno-cockpit). libverify provides the patterns and policy; the runtime enforces them.
