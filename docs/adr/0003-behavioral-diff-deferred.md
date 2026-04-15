# ADR-0003: Behavioral Diff Controls Deferred

## Status
Accepted

## Context
Layer 3 (Behavioral Diff) controls `behavioral-regression` and `deployment-health` were implemented with evaluation logic and formal verification predicates. However, they depend on `BehavioralDiff` evidence (post-deployment metrics like latency, error rate, throughput) that requires integration with external metrics platforms (Prometheus, Datadog, CloudWatch, etc.).

gh-verify is a GitHub CLI tool. Collecting metrics from production monitoring systems is fundamentally outside its scope. No adapter can populate this evidence today, making these controls always return `NotApplicable`.

## Decision
Remove `behavioral-regression` and `deployment-health` controls from the built-in control registry. Retain the evidence model types (`MetricObservation`, `BehavioralDiff`, `behavioral_diff` field on `EvidenceBundle`) for future use.

## Rationale
- Controls that never fire are worse than no controls — they create a false sense of coverage
- The evidence model is correct and should be preserved for when a metrics adapter is implemented
- A dedicated `libverify-metrics` adapter crate is the right place for metrics collection
- Metrics platform integration requires authentication, rate limiting, and query DSL handling that don't belong in core

## Consequences
- Built-in control count decreases (keeping only controls that can actually fire)
- Evidence types remain available for external adapters
- When `libverify-metrics` or equivalent is built, controls can be re-added with wired evidence
