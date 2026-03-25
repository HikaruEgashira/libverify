# Hacking on libverify

## Setup

```bash
rustup toolchain install stable
```

## Development

```bash
cargo test --workspace --exclude libverify-verif
cargo check --workspace                             # Type check
cargo clippy --workspace --exclude libverify-verif  # Lint
cargo fmt --all                                     # Format
```

## Architecture

Six-crate workspace.

```
┌─────────────────────────────────────────────────────────┐
│                      Consumers                          │
│                                                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │  GitHub CLI  │  │  GitLab CLI  │  │     ...      │  │
│  │  extension   │  │  (future)    │  │              │  │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  │
│         │                 │                 │           │
└─────────┼─────────────────┼─────────────────┼───────────┘
          │                 │                 │
          ▼                 ▼                 ▼
┌─────────────────────────────────────────────────────────┐
│                    libverify                             │
│                                                         │
│  ┌──────────────────────────────────────────────────┐   │
│  │              Platform Connectors                  │   │
│  │                                                   │   │
│  │  libverify-github     libverify-gitlab (future)   │   │
│  │  ├─ GitHubClient      ├─ GitLabClient             │   │
│  │  ├─ adapter            ├─ adapter                  │   │
│  │  ├─ verify_pr          ├─ verify_mr                │   │
│  │  └─ verify_release     └─ verify_release           │   │
│  └──────────────────────┬───────────────────────────┘   │
│                         │                               │
│                         ▼                               │
│  ┌──────────────────────────────────────────────────┐   │
│  │              Core Engine                          │   │
│  │                                                   │   │
│  │  libverify-core                                   │   │
│  │  ├─ EvidenceBundle    (platform-neutral model)    │   │
│  │  ├─ Control trait     (28 built-in controls)      │   │
│  │  ├─ ControlRegistry   (dynamic collection)        │   │
│  │  ├─ assessment        (evidence → findings)       │   │
│  │  └─ SLSA v1.2 + SOC2 CC7/CC8 + ASPM mapping      │   │
│  └──────────────────────┬───────────────────────────┘   │
│                         │                               │
│              ┌──────────┴──────────┐                    │
│              ▼                     ▼                    │
│  ┌─────────────────┐  ┌─────────────────┐              │
│  │ libverify-policy │  │ libverify-output│              │
│  │ OPA Rego engine  │  │ SARIF / JSON    │              │
│  │ 9 presets        │  │ rendering       │              │
│  └─────────────────┘  └─────────────────┘              │
│                                                         │
│  ┌──────────────────────────────────────────────────┐   │
│  │ libverify-verif  (Creusot, excluded from builds)  │   │
│  │ SMT-proven decision predicates                    │   │
│  └──────────────────────────────────────────────────┘   │
│                                                         │
│  ┌──────────────────────────────────────────────────┐   │
│  │ gen-docs  (rule spec site generator)              │   │
│  │ Extracts Creusot specs + test metadata → HTML     │   │
│  └──────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

### Dependency graph

```
libverify-github ──→ libverify-core ←── libverify-policy
                 ──→ libverify-policy        │
                                        libverify-output ──→ libverify-core

libverify-verif     (independent, not linked at runtime)
```

### Data flow (GitHub example)

```
GitHub API ──→ GitHubClient ──→ adapter ──→ EvidenceBundle
                                                │
               ┌────────────────────────────────┘
               ▼
         Control::evaluate()  → Vec<ControlFinding>     (per control)
               │
               ▼
         ControlProfile::map() → ProfileOutcome          (severity + gate)
               │
               ▼
         assess()             → AssessmentReport         (aggregated)
               │
               ▼
         render()             → SARIF / JSON string      (output)
```

### Key types

| Type | Crate | Purpose |
|---|---|---|
| `EvidenceBundle` | core | Platform-normalized evidence container |
| `GovernedChange` | core | A change request (PR, MR, etc.) |
| `PromotionBatch` | core | A release / deployment batch |
| `EvidenceState<T>` | core | Tri-state: complete, partial (with gaps), missing, or N/A |
| `Control` trait | core | Evaluates evidence → `Vec<ControlFinding>` |
| `ControlId` | core | String-based open ID (`builtin::` constants for 28 built-in) |
| `ControlRegistry` | core | Dynamic control collection. `::builtin()` for all 28 |
| `ControlProfile` trait | core | Maps findings → severity + gate decision |
| `OpaProfile` | policy | Rego-based profile. 9 presets (incl. slsa-l1..l4) + custom file support |
| `AssessmentReport` | core | Assessment result with findings + profile outcomes |
| `VerificationResult` | core | Report + optional evidence for audit trail |
| `BatchReport` | core | Multiple verification results |
| `OutputOptions` | output | Format selection + tool metadata |

### Evidence model

`EvidenceState<T>` distinguishes between:
- **Complete** — evidence collected successfully
- **Partial** — collected with gaps (`Vec<EvidenceGap>`)
- **Missing** — collection failed entirely
- **Not applicable** — evidence does not apply to this context

This enables controls to return `Indeterminate` when evidence is incomplete,
rather than incorrectly reporting `Satisfied` or `Violated`.

### Control evaluation flow

```
EvidenceBundle
    → Control::evaluate()      → Vec<ControlFinding>      (per control)
    → ControlProfile::map()    → ProfileOutcome            (per finding)
    → assess_with_registry()   → AssessmentReport          (aggregated)
    → render()                 → SARIF / JSON string       (output)
```

## Adding a control

### SLSA control

1. Create `crates/core/src/controls/<name>.rs`, impl `Control` trait
2. Add `&str` constant to `crates/core/src/control.rs::builtin` module
3. Register in `crates/core/src/controls/mod.rs::instantiate()` and `all_slsa_controls()`
4. Map in `crates/core/src/slsa.rs::control_slsa_mapping()`
5. Add integrity predicate in `crates/core/src/integrity.rs`
6. Add Creusot spec in `crates/verif/src/lib.rs`

### Compliance control

1. Create `crates/core/src/controls/<name>.rs`, impl `Control` trait
2. Add `&str` constant to `crates/core/src/control.rs::builtin` module
3. Register in `crates/core/src/controls/mod.rs::instantiate()` and `compliance_controls()`

### Naming conventions

- Control ID: kebab-case (`"review-independence"`)
- File name: snake_case (`review_independence.rs`)
- Crate name: kebab-case (`libverify-core`)
- Built-in constant: SCREAMING_SNAKE_CASE (`REVIEW_INDEPENDENCE`)

## Adding a policy preset

1. Create `crates/policy/src/<name>.rego` implementing `verify.profile.map` rule
2. Add `include_str!` constant in `crates/policy/src/lib.rs`
3. Add constructor method and match arm in `from_preset_or_file()`

## Custom OPA policies

A Rego policy must define `data.verify.profile.map` returning:

```rego
package verify.profile

map = {"severity": severity, "decision": decision} {
    # input.control_id  — the control ID string
    # input.status      — "satisfied" | "violated" | "indeterminate" | "not_applicable"
    # severity           — "info" | "warning" | "error"
    # decision           — "pass" | "review" | "fail"
}
```

## Formal verification with Creusot

### Setup

```bash
brew install opam z3
opam init --bare
opam switch create creusot 4.14.2
eval $(opam env --switch=creusot)
opam install alt-ergo why3 why3find

cargo install --git https://github.com/creusot-rs/creusot cargo-creusot
NIGHTLY=$(cargo creusot version 2>&1 | grep 'Rust toolchain' | awk '{print $3}')
rustup toolchain install "$NIGHTLY"
rustup component add rustc-dev --toolchain "$NIGHTLY"
cargo +"$NIGHTLY" install --git https://github.com/creusot-rs/creusot creusot-rustc

CREUSOT_BIN="$HOME/Library/Application Support/creusot.creusot/bin"
mkdir -p "$CREUSOT_BIN"
for cmd in why3 why3find alt-ergo; do
  ln -sf "$(which $cmd)" "$CREUSOT_BIN/$cmd"
done
ln -sf "$(which z3)" "$CREUSOT_BIN/z3"

cargo creusot why3-conf
```

### Usage

```bash
eval $(opam env --switch=creusot)
cargo creusot -p libverify-verif
cargo creusot prove '<predicate_name>' -- -p libverify-verif
```

### Design constraints

- **No `format!`/`String`/`Vec`** in verif crate — Creusot cannot translate these
- **`DeepModel` derive** required on enums used in `#[ensures]` comparisons
- **Primitive types only** — extract `bool`/`usize` predicates from complex functions
- **Severity enum duplicated** in verif crate to avoid pulling serde

## CI

GitHub Actions runs on push/PR to main:

1. `cargo test --workspace --exclude libverify-verif`
2. `cargo clippy --workspace --exclude libverify-verif -- -D warnings`
3. `cargo fmt --all -- --check`
