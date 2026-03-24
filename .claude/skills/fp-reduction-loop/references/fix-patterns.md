# FP修正パターン集

9イテレーションで適用した修正パターン。新FPに遭遇した際の参照用。

## Policy層 (Rego)

### P1: スタイル系コントロールのadvisory化
- **症状**: conventional-title, merge-commit-policy等がOSSプロジェクトで100% fail
- **修正**: `soc2_advisory_controls` / `oss_review_on_violated` セットに追加
- **例**: conventional-title → review (oss.rego, soc2.rego)

### P2: エビデンス不足時のindeterminate → review
- **症状**: Gerritミラー等でevidence欠落 → indeterminate → fail
- **修正**: `oss_review_on_indeterminate` セットに追加
- **例**: branch-history-integrity, branch-protection-enforcement (oss.rego)

### P3: OSS-origin コントロールのenterprise緩和
- **症状**: SECURITY.md不在がSOC2でhard fail（企業は内部ポータル使用）
- **修正**: `soc2_oss_origin_controls` セットに追加
- **例**: security-policy → review (soc2.rego)

## Adapter層 (libverify-github)

### A1: Bot-mediated approval認識
- **症状**: Prow `/lgtm` が COMMENTED 扱い → review-independence fail
- **修正**: `map_review_disposition()` で body 内容チェック
- **パターン**: `/lgtm`, `/approve` をline-start anchored で検出
- **ファイル**: `adapter.rs`, `types.rs` (Review.body追加), `graphql.rs` (body query追加)

### A2: CI platform allowlist拡張
- **症状**: Cirrus CI, Netlify, Buildkite等が "unknown" → hosted-build-platform fail
- **修正**: `classify_ci_platform()` に追加
- **対応済み**: github-actions, cirrus-ci, travis-ci, azure-pipelines, buildkite, netlify, vercel, prow/tide, codecov, codspeed-hq, buildomat, github-advanced-security, pkg-pr-new, dco, readthedocs, vs-code-engineering

### A3: Check run name推定
- **症状**: app_slug=null の check run が "unknown" のまま
- **修正**: `infer_platform_from_name()` で name pattern から推定
- **パターン**: `pull-*`/`ci-*` → prow, `bors*` → github-actions, `buildkite/*` → buildkite, `*netlify*` → netlify, `*readthedocs*` → readthedocs, `*cirrus*` → cirrus-ci, `pr-*` → github-actions

### A4: Unknown app_slug のデフォルト
- **症状**: 未知のCI platform が hosted-build-platform fail を引き起こす
- **修正**: `classify_ci_platform()` のデフォルトを `(true, false, false, false)` に
- **根拠**: check run を GitHub に報告した = 何かの hosted system が実行した

## Control層 (libverify-core)

### C1: Bot-submitted PRのNotApplicable
- **症状**: bors rollup PR に reviewer 0人 → review-independence fail
- **修正**: `GovernedChange::is_bot_submitted()` → 該当コントロールで NotApplicable
- **対象**: review-independence, two-party-review, branch-protection-enforcement
- **Bot判定**: bors, mergify, dependabot, renovate, k8s-ci-robot, `[bot]` suffix

### C2: Bot-authored commit除外 (stale-review)
- **症状**: bors のリベースcommit が最新commit扱い → stale-review fail
- **修正**: `is_bot_author()` で bot commit を latest timestamp 計算から除外
- **ファイル**: `stale_review.rs`

### C3: RFC 3339 タイムゾーン正規化
- **症状**: `02:54:37Z` vs `10:34:00+08:00` の文字列比較が誤判定
- **修正**: `rfc3339_to_epoch_secs()` で UTC 正規化後に比較
- **ファイル**: `stale_review.rs`

### C4: ファイル分類改善
- **症状**: tests.rs, OWNERS, benches/ 等がSource扱い → test-coverage fail
- **修正箇所**:
  - `has_test_marker()`: `tests.rs`, `test.rs`, `_tests.rs` を Test に
  - `NON_CODE_FILENAMES`: OWNERS, LICENSE, Makefile, Dockerfile 等
  - `NON_CODE_PREFIXES`: `benches/`, `benchmarks/`, `examples/`
- **ファイル**: `scope.rs`
