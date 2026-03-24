---
name: fp-reduction-loop
description: |
  libverify/gh-verify の False Positive 削減ループを自律実行するスキル。
  OSSInsight APIでトレンドリポを動的に発見し、gh-verify を実行し、
  失敗をTP/FP分類し、FPをpolicy/adapter/control層で修正し、
  再ビルド・再検証するサイクルをFP=0になるまで繰り返す。

  Trigger: FP削減, false positive, 精度改善, real-world検証, gh-verify品質改善,
  リアルワールドテスト, コントロール精度, 検証精度向上
---

# FP Reduction Loop

## ワークフロー

### 1. リポ発見（動的）

OSSInsight API でトレンドリポを取得し、多様なエコシステムから検証対象を選定する。
固定リポリストはoverfitを招くため、毎回新鮮なリポを含める。

```bash
# 過去1ヶ月のトレンドリポを言語別に取得
curl -s "https://api.ossinsight.io/v1/trends/repos/?period=past_month&language=All" \
  | python3 -c "
import sys, json
data = json.load(sys.stdin)
for row in data['data']['rows'][:30]:
    print(f\"{row['repo_name']}  {row['primary_language']}  ★{row['stars']}\")
"
```

**選定基準** — 以下を満たす10-20リポを選ぶ:
- 5言語以上（Rust, Python, Java, JS/TS, Go は必須）
- GitHub Actions 以外のCI含む（Buildkite, Cirrus CI, Jenkins等）
- 大規模リポ (10k+ stars) と小規模リポ (100-1k stars) の混在
- 企業backed (Meta, Google, Microsoft) と community-maintained の混在

各リポの最新merged PRを取得:
```bash
gh pr list --repo <OWNER/REPO> --state merged --limit 1 --json number -q '.[0].number'
```

プリセット選定: 企業backed → soc2、community → oss

### 2. 検証

```bash
# gh-verify バイナリを探す（PATH、ghqディレクトリ、cargo installの順）
GH_VERIFY=$(which gh-verify 2>/dev/null || find "$HOME/ghq" -path "*/gh-verify/target/release/gh-verify" -type f 2>/dev/null | head -1)
$GH_VERIFY pr <NUMBER> --repo <OWNER/REPO> --policy <oss|soc2> --format human 2>&1 | tail -1
```

`--only-failures` で fail のみ表示。evidence 調査は `--format sarif --with-evidence`。

### 3. 分析

各 fail を分類:
- **TP**: 検出事象が実在 + 当該プリセットで問題 + リポ固有でない
- **FP**: 誤検出 / severity不適切 / adapter gap / 技術的バグ

### 4. 修正

FP 原因に応じて修正レイヤーを選択:

| 原因 | レイヤー | 対象ファイル |
|---|---|---|
| プリセット severity 不適切 | policy | `crates/policy/src/{oss,soc2}.rego` |
| CI platform 未認識 | adapter | `crates/github/src/adapter.rs` |
| Bot review/commit 未処理 | adapter | `crates/github/src/adapter.rs` |
| ファイル分類誤り | control | `crates/core/src/scope.rs` |
| タイムスタンプ比較バグ | control | 該当コントロール `.rs` |
| Bot-submitted PR 扱い | evidence | `crates/core/src/evidence.rs` |

原則: 個別リポ対応ではなくカテゴリレベルの構造的修正。`references/fix-patterns.md` に過去パターン記載。

### 5. 再ビルド

libverifyリポで修正をcommit+pushした後、gh-verifyリポで依存を更新して再ビルド:
```bash
# libverify (現在のリポ)
git add -A && git commit -m "fix: ..." && git push

# gh-verify (git remoteからパスを特定)
GH_VERIFY_DIR=$(find "$HOME/ghq" -name "gh-verify" -type d -maxdepth 4 2>/dev/null | head -1)
cd "$GH_VERIFY_DIR" && cargo update -p libverify-github && cargo build --release
```

### 6. 再検証

Phase 2 を再実行。FP > 0 なら Phase 4 に戻る。

## 完了条件

- 選定した全リポで FP = 0
- 全 fail が TP として説明可能
- `cargo test --workspace --exclude libverify-verif` 全パス
- `cargo clippy --workspace --exclude libverify-verif` 警告なし

## リソース

- `references/fix-patterns.md` — 過去のFP修正パターン集
