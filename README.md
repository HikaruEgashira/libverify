<h1 align="center">libverify</h1>

<p align="center">
  Platform-agnostic SDLC verification engine.
</p>

<p align="center">
  <a href="HACKING.md">Hacking</a>
</p>

---

libverify is a shared verification library for supply chain security
and compliance checks. Think libghostty for SDLC verification.
Platform-specific tools like [gh-verify](https://github.com/HikaruEgashira/gh-verify)
are thin shells that consume this library.

Each control evaluates evidence and produces a verdict:
Satisfied, Violated, Indeterminate, or Not Applicable.
A profile maps these to gate decisions — pass, review, or fail.
Core decision predicates are formally proven via [Creusot](https://github.com/creusot-rs/creusot).

> [!WARNING]
>
> This project is under active development. Controls and output format may change.

## Usage

```rust
use libverify_core::registry::ControlRegistry;
use libverify_core::evidence::EvidenceBundle;
use libverify_core::assessment::assess_with_registry;
use libverify_core::profile::SlsaLevelProfile;
use libverify_core::slsa::SlsaLevel;
use libverify_policy::OpaProfile;
use libverify_output::{OutputOptions, Format, render};

// 1. Collect evidence from your platform
let evidence = EvidenceBundle { /* ... */ };

// 2. Run all 24 built-in controls with an OPA policy
let registry = ControlRegistry::builtin();
let profile = OpaProfile::from_preset_or_file("soc2")?;
let report = assess_with_registry(&evidence, &registry, &profile);

// 3. Or use SLSA level-based assessment
let slsa_profile = SlsaLevelProfile::new(SlsaLevel::L3, SlsaLevel::L2);
let report = assess_with_registry(&evidence, &registry, &slsa_profile);

// 4. Format output (JSON or SARIF)
let opts = OutputOptions {
    format: Format::Sarif,
    only_failures: false,
    tool_name: "my-verify".into(),
    tool_version: "1.0.0".into(),
};
let sarif = render(&opts, &report.into())?;
```

## Workspace

| Crate | Purpose |
|-------|---------|
| `libverify-core` | Evidence model, `Control` trait, 21 built-in controls, assessment engine, SLSA v1.2 mapping, profile system. Pure logic, serde only. |
| `libverify-policy` | OPA Rego policy engine ([regorus](https://github.com/nicholasbishop/regorus)). 5 built-in presets + custom `.rego` support. |
| `libverify-output` | SARIF 2.1.0 / JSON formatters. Tool name/version configurable per consumer. |
| `libverify-verif` | [Creusot](https://github.com/creusot-rs/creusot) formal verification targets. SMT-proven decision predicates. |

## Controls

24 built-in controls covering SLSA v1.2 and SOC2 CC7/CC8.

### SLSA v1.2

| Track | Level | Control |
|-------|-------|---------|
| Source | L1 | `review-independence`, `source-authenticity` |
| Source | L2 | `branch-history-integrity` |
| Source | L3 | `branch-protection-enforcement` |
| Source | L4 | `two-party-review` |
| Build | L1 | `build-provenance`, `required-status-checks` |
| Build | L2 | `hosted-build-platform`, `provenance-authenticity` |
| Build | L3 | `build-isolation` |
| Dependencies | L1 | `dependency-signature` |
| Dependencies | L2 | `dependency-provenance` |
| Dependencies | L3 | `dependency-signer-verified` |
| Dependencies | L4 | `dependency-completeness` |

> **Note:** Dependencies L1 is achievable with lock-file checksums alone.
> L2+ requires cryptographic provenance (e.g. Sigstore/npm provenance) which
> depends on ecosystem adoption. Lock-file parsers populate `ChecksumMatch`;
> provenance adapters (future) will populate `Verified` + signer fields.

### SOC2 CC7/CC8

| Criteria | Control |
|----------|---------|
| CC7.1 (Traceability) | `issue-linkage`, `release-traceability` |
| CC7.2 (Anomaly detection) | `stale-review`, `security-file-change` |
| CC8.1 (Change management) | `change-request-size`, `test-coverage`, `scoped-change`, `description-quality`, `merge-commit-policy`, `conventional-title` |

### Policy presets

| Preset | Description |
|--------|-------------|
| `default` | All controls strict (indeterminate/violated → fail) |
| `oss` | Tolerates unsigned commits and self-reviewed merges |
| `aiops` | Escalates all indeterminate to human review instead of fail |
| `soc1` | Strict on ICFR-relevant controls; advisory on dev-quality controls |
| `soc2` | Strict on all CC6/CC7/CC8 controls; review on build-track indeterminate |
| `slsa-l1`..`slsa-l4` | SLSA level enforcement (Source + Build + Dependencies tracks) |

Custom OPA Rego policies are supported via `OpaProfile::from_file()`.

## Integrating a new platform

libverify is platform-agnostic. To build a verifier for a new platform (e.g., GitLab, Bitbucket):

1. **Collect evidence** — Map platform API responses to `EvidenceBundle` / `GovernedChange` / `PromotionBatch`
2. **Run controls** — Use `ControlRegistry::builtin()` or register platform-specific controls
3. **Apply policy** — Use a built-in preset or custom Rego policy
4. **Format output** — Render as SARIF or JSON via `libverify-output`

See [gh-verify](https://github.com/HikaruEgashira/gh-verify) as a reference implementation.

## Development

See [HACKING.md](HACKING.md) for architecture, build commands, and contribution guide.

## License

[MIT](LICENSE)
