# libverify — Platform-agnostic SDLC Verification Engine

Shared verification library. Platform-specific shells (CLI extensions, IDE plugins, etc.) consume this library.

## Commands

```bash
cargo test --workspace --exclude libverify-verif
cargo check --workspace                             # Type check
cargo clippy --workspace --exclude libverify-verif  # Lint
cargo mutants -p libverify-core -- --lib            # Mutation testing (core)
```

## Architecture

Seven-crate workspace:

- `libverify-core` — evidence model, Control trait, 34 built-in controls, assessment engine. Pure logic, serde only.
- `libverify-policy` — OPA Rego policy engine (regorus).
- `libverify-output` — SARIF/JSON output formatters.
- `libverify-github` — GitHub API client, evidence adapter, verification orchestration.
- `libverify-gitlab` — GitLab API client, evidence adapter.
- `libverify-verif` — Creusot formal verification targets.
- `gen-docs` — Rule specification static site generator.

## Adding a new control

0. If new evidence types are needed, add structs + `EvidenceState` field to `crates/core/src/evidence.rs`
1. Create `crates/core/src/controls/<name>.rs`, impl `Control` trait
2. Add `&str` constant to `crates/core/src/control.rs::builtin` module and `ALL` array (update count comment)
3. Register in `crates/core/src/controls/mod.rs`: `pub mod`, `use`, `instantiate()` match arm, and collection function (`compliance_controls()`, `posture_controls()`, `aiops_controls()`, or SLSA group)
4. If SLSA-mapped, add to `crates/core/src/slsa.rs::control_slsa_mapping()` and `ALL_SLSA_CONTROLS`. If compliance-only, no changes needed in slsa.rs. If agent-safety, add to `aiops_controls()`.
5. Add Creusot spec if the predicate is verifiable
6. Add remediation hint in `control.rs::builtin_remediation_hint()`. Add TSC mapping in `builtin_tsc_mapping()` only if the control has a defensible SOC2 justification — do not map best-practice-only controls
