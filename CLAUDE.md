# libverify — Platform-agnostic SDLC Verification Engine

Shared verification library. Think libghostty for SDLC verification.
gh-verify and atlassian-verify are thin platform-specific shells consuming this library.

## Commands

```bash
cargo test --workspace --exclude libverify-verif   # All tests (421+)
cargo check --workspace                             # Type check
cargo clippy --workspace --exclude libverify-verif  # Lint
```

## Architecture

Five-crate workspace:

- `libverify-core` — evidence model, Control trait, 24 built-in controls, assessment engine, SLSA v1.2 mapping (Source/Build/Dependencies tracks). Pure logic, serde only.
- `libverify-policy` — OPA Rego policy engine (regorus). 9 presets: default, oss, aiops, soc1, soc2, slsa-l1, slsa-l2, slsa-l3, slsa-l4.
- `libverify-output` — SARIF/JSON output formatters. Tool name/version configurable per consumer.
- `libverify-github` — GitHub API client, evidence adapter, verification orchestration. Used by [gh-verify](https://github.com/HikaruEgashira/gh-verify).
- `libverify-verif` — Creusot formal verification targets.

## Key types

| Type | Crate | Purpose |
|---|---|---|
| `EvidenceBundle` | core | Platform-normalized evidence container |
| `GovernedChange` | core | A change request (PR, MR, etc.) |
| `Control` trait | core | Evaluates evidence → findings |
| `ControlId` | core | String-based open ID (`builtin::` constants for 24 built-in) |
| `ControlRegistry` | core | Dynamic control collection. `::builtin()` for all 24 |
| `DependencySignatureEvidence` | core | Per-dependency verification evidence with provenance fields |
| `VerificationOutcome` | core | `Verified` / `ChecksumMatch` / failure variants (7 total) |
| `ControlProfile` trait | core | Maps findings → severity + gate decision. All profiles (including SLSA) are OPA policy presets. |
| `OpaProfile` | policy | Rego-based profile implementation |
| `VerificationResult` | core | Assessment report + optional evidence |
| `BatchReport` | core | Multiple verification results |
| `GitHubConfig` | github | GitHub API token/host/repo resolution |
| `GitHubClient` | github | REST + GraphQL client with retry/pagination |
| `verify_pr` | github | Single PR verification orchestration |
| `verify_release` | github | Release verification orchestration |
| `verify_repo` | github | Repository-level dependency verification |
| `TreeSearchResult` | github | Git Tree API result with truncated flag |

## Adding a new control

0. If new evidence types are needed, add structs + `EvidenceState` field to `crates/core/src/evidence.rs`
1. Create `crates/core/src/controls/<name>.rs`, impl `Control` trait
2. Add `&str` constant to `crates/core/src/control.rs::builtin` module and `ALL` array (update count comment)
3. Register in `crates/core/src/controls/mod.rs`: `pub mod`, `use`, `instantiate()` match arm, and collection function (`compliance_controls()` or SLSA group)
4. If SLSA-mapped, add to `crates/core/src/slsa.rs::control_slsa_mapping()` and `ALL_SLSA_CONTROLS`. If compliance-only, no changes needed in slsa.rs.
5. Add SARIF rule description to `crates/output/src/sarif.rs::builtin_rule_description()`
6. Add Creusot spec if the predicate is verifiable

## Naming

- Control ID: kebab-case string (`"review-independence"`)
- File name: snake_case (`review_independence.rs`)
- Crate name: kebab-case (`libverify-core`)
- Built-in constant: SCREAMING_SNAKE_CASE (`REVIEW_INDEPENDENCE`)
