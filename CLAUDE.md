# libverify — Platform-agnostic SDLC Verification Engine

Shared verification library. Think libghostty for SDLC verification.
gh-verify and atlassian-verify are thin platform-specific shells consuming this library.

## Commands

```bash
cargo test --workspace --exclude libverify-verif   # All tests (358+)
cargo check --workspace                             # Type check
cargo clippy --workspace --exclude libverify-verif  # Lint
```

## Architecture

Four-crate workspace:

- `libverify-core` — evidence model, Control trait, 20 built-in controls, assessment engine, SLSA v1.2 mapping, profile system. Pure logic, serde only.
- `libverify-policy` — OPA Rego policy engine (regorus). 5 presets: default, oss, aiops, soc1, soc2.
- `libverify-output` — SARIF/JSON output formatters. Tool name/version configurable per consumer.
- `libverify-verif` — Creusot formal verification targets.

## Key types

| Type | Crate | Purpose |
|---|---|---|
| `EvidenceBundle` | core | Platform-normalized evidence container |
| `GovernedChange` | core | A change request (PR, MR, etc.) |
| `Control` trait | core | Evaluates evidence → findings |
| `ControlId` | core | String-based open ID (`builtin::` constants for 20 built-in) |
| `ControlRegistry` | core | Dynamic control collection. `::builtin()` for all 20 |
| `ControlProfile` trait | core | Maps findings → severity + gate decision |
| `OpaProfile` | policy | Rego-based profile implementation |
| `VerificationResult` | core | Assessment report + optional evidence |
| `BatchReport` | core | Multiple verification results |

## Adding a new control

1. Create `crates/core/src/controls/<name>.rs`, impl `Control` trait
2. Add `&str` constant to `crates/core/src/control.rs::builtin` module
3. Register in `crates/core/src/controls/mod.rs::instantiate()` and appropriate collection function
4. If SLSA-mapped, add to `crates/core/src/slsa.rs::control_slsa_mapping()`
5. Add Creusot spec if the predicate is verifiable

## Naming

- Control ID: kebab-case string (`"review-independence"`)
- File name: snake_case (`review_independence.rs`)
- Crate name: kebab-case (`libverify-core`)
- Built-in constant: SCREAMING_SNAKE_CASE (`REVIEW_INDEPENDENCE`)
