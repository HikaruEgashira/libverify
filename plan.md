# libverify: Dark Factory extension

## Why this document exists

libverify は SDLC 検証エンジンとして設計された。28のコントロールは PR、ブランチ保護、レビュアーの存在を前提としている。

2026年、この前提が崩壊しつつある。

---

## What changed

Boris Tane「The SDLC Is Dead」(2026/02) の主張:
- SDLC の工程は Intent → Build → Observe に崩壊した
- コードレビューは儀式であり、機械のワークフローに押し付けると500PR/day vs 10review/day のボトルネックになる
- **Observability が唯一残るセーフティネット**
- 彼は nominal.dev をこの thesis で建設中

watany「ロボットのための工場に灯りは要らない」(2026/03) の主張:
- AI コーディングと OSS コミュニティが同じ結論に達した — PR は廃止されるべき
- strongDM 社は「コードは人間が書いてはならない。コードは人間がレビューしてはならない」というルールで Dark Software Factory を構築した
- 儀式の核（儀礼）を残して、儀式自体は簡素化する
- スイスチーズモデル: 複数オプション比較 → 決定論的ガードレール → 受入基準 → 権限制御 → 敵対的検証

**共通の結論**: 人間のレビューを前提とした工程は消え、自動化された多層ゲート + observability に置き換わる。

---

## Why libverify is positioned correctly — and incorrectly

### Correctly

libverify のエンジン設計は Dark Factory でもそのまま機能する:

- `Control` trait は「evidence を受け取り verdict を返す」という純粋な抽象。PR の存在を前提としていない
- OPA policy engine は gate decision を宣言的に定義する。どのコントロールを strict にし、どれを advisory にするかはプリセットで切り替えるだけ
- Creusot 形式検証は判定述語の正しさを数学的に保証する。これはどの層のコントロールにも適用できる
- Platform adapter パターン（`libverify-github`, `libverify-gitlab`）は新しい evidence source にも拡張可能

エンジンの設計変更は不要。

### Incorrectly

既存28コントロールの大半は、Dark Factory で検証対象が消滅する:

| 消滅する前提 | 影響を受けるコントロール |
|------------|---------------------|
| PR が存在する | `review-independence`, `two-party-review`, `stale-review`, `change-request-size`, `description-quality`, `conventional-title`, `merge-commit-policy` |
| ブランチ戦略がある | `branch-protection-enforcement`, `branch-history-integrity` |
| 人間のレビュアーがいる | `source-authenticity` (署名検証) |

28コントロール中、Dark Factory で無条件に機能するのは `test-coverage`, `secret-scanning`, `vulnerability-scanning`, `security-policy`, `codeowners-coverage` の5つ程度。

**plan.md で「libverify は拡張しない」と書いたが、これは市場の現実と矛盾する。**

---

## What to do

エンジンは変えない。コントロールを追加する。

既存28コントロールは削除しない。Layer 6（SDLC compliance, opt-in）として残す。SOC2 監査を受ける企業は依然として必要とし、Dark Factory に完全移行していない組織（現時点で大多数）には有用。OPA プリセットで `dark-factory` を選べば advisory になり、`soc2` を選べば strict になる。

新しいコントロールは、watany が整理したスイスチーズモデルの5層に対応する。

---

## Layer 1: Spec conformance — なぜ必要か

Dark Factory ではエージェントが main に直接コミットする。PR レビューによるスコープ確認がないため、「エージェントが intent の範囲内で動いているか」を機械的に検証する必要がある。

strongDM の Software Factory が spec + scenario で動くように、エージェントにも spec（許可パス、禁止パス、使用可能ツール、時間/コスト予算）を与え、逸脱を検出する。

**探索すべき問い:**
- spec のフォーマットは何か — TOML? YAML? Rego 自体に統合?
- `agent_spec` は `EvidenceBundle` に含めるべきか、OPA の `input.spec` として渡すべきか
- glob match の仕様は gitignore 互換か、独自か
- scope 違反時に halt するか、alert のみか — policy で決めるべきだが、halt の責務は libverify にあるか cockpit にあるか

---

## Layer 2: Deterministic gates — なぜ必要か

Boris Tane の post-review 世界で最も合意が得られている層。テスト、型チェック、リント、ビルドが通っているかは、誰が書いたコードかに関係なく検証できる。既存の `test-coverage` コントロールと近い思想だが、より汎用的な「ハーネス結果」として抽象化する。

Dark Factory ではこの層が最初のゲートになる。strongDM が「仕様とシナリオに基づいてハーネスを実行し、収束する」と言っているのはこの層。

**探索すべき問い:**
- ハーネス結果の evidence 表現は何か — JUnit XML? TAP? 独自 struct?
- 「どのハーネスが必須か」はコントロール側で持つか、policy 側で持つか
- 既存の `test-coverage` コントロールとの関係 — 統合か共存か
- coverage の数値的な閾値は policy に寄せるべきか

---

## Layer 3: Behavioral diff — なぜ必要か

Boris Tane の核心的な主張: 「Observability without action is just expensive storage」。コードが正しくても、production で regression を起こせば意味がない。

Layer 2 が「コードが壊れていないこと」を検証するのに対し、Layer 3 は「システムの振る舞いが壊れていないこと」を検証する。canary deploy → metrics 比較 → 自動 rollback という流れの中で、libverify は metrics 比較の判定を担う。

これは libverify にとって最も新しい領域。既存コントロールはすべて「コード変更時点」の検証だが、Layer 3 は「デプロイ後」の検証。evidence の収集タイミングが異なる。

**探索すべき問い:**
- どの metrics source と統合するか — Prometheus? OpenTelemetry? Datadog API?
- baseline はどう定義するか — 直前の commit? 過去 N 日の平均?
- 閾値は絶対値か相対値か — 「p99 < 200ms」vs「p99 が 10% 以上悪化」
- libverify の責務はどこまでか — metrics 収集は adapter の仕事だが、異常検知アルゴリズムはコントロールに含めるか
- nominal.dev (Boris Tane) との競合/補完関係
- この層は libverify の scope 外か — cockpit 側に置くべきか

---

## Layer 4: Security boundary — なぜ必要か

既存の `secret-scanning`, `vulnerability-scanning` はリポジトリ設定の有無を検証する。Dark Factory ではこれに加え、エージェントの「行動」を検証する必要がある。

人間は `rm -rf /` を打たない（打っても止まる）。エージェントは打つ。エージェントに本番 DB への直接接続を許可した場合、`DROP TABLE` を実行する可能性がある。この層は「エージェントが破壊的操作を行っていないか」を検証する。

watany のスイスチーズモデルの「権限制御」層に対応する。

**探索すべき問い:**
- 「破壊的操作」のパターン定義は静的リストか、policy で設定可能にするか
- エージェントの行動ログはどのフォーマットで evidence に含めるか
- `agent_actions` の粒度 — コマンド単位? ファイル操作単位? API 呼び出し単位?
- 既存の `secret-scanning` コントロールとの統合方法
- MCP tool call の interception はどの層で行うか — libverify? cockpit? adapter?

---

## Layer 5: Adversarial review — なぜ必要か

Boris Tane: 「A second agent reviews the first agent's output. Adversarial agents plough through the proposed changes, try to break it in every dimension.」

watany のスイスチーズモデルの最終層。libverify 自体が敵対的レビューを実行するのではなく、「敵対的レビューが実行され、pass したか」を検証するコントロール。既存の `review-independence` と構造は同じ — 「レビューが行われたか + 結果は pass か」を evidence から判定する。

**探索すべき問い:**
- 敵対的レビューの evidence はどう表現するか — `HarnessResult` に統合? 独自型?
- 「敵対的」の定義は libverify の責務か、外部に委ねるか
- Layer 2 の harness との境界 — 敵対的レビューも一種のテストハーネスではないか。独立した Layer にする意味はあるか
- この層の Creusot 形式検証は可能か

---

## Existing 28 controls as Layer 6

既存28コントロールは削除しない。SOC2 Type II 監査、SLSA 準拠を必要とする顧客は依然として存在する。

Dark Factory プリセットでは advisory に、SDLC プリセットでは strict に。これは OPA Rego の1ファイルで切り替わる。

---

## Implementation priority

| Priority | Layer | Why first |
|----------|-------|-----------|
| 1 | Layer 2 (deterministic gates) | 最も ROI が高い。「テストが通ったか」は今日でも全員が同意する最小合意点。既存 `test-coverage` の延長線上 |
| 2 | Layer 4 (security boundary) | エージェント暴走防止。顧客に説明しやすい。`destructive-action` は直感的 |
| 3 | Layer 1 (spec conformance) | scope 制御。agent-spec フォーマットの設計が必要だが、技術的には scope.rs が参考になる |
| 4 | Layer 3 (behavioral diff) | 外部 metrics 統合が必要で最も複雑。後回しにしても Dark Factory MVP は成立する |
| 5 | Layer 5 (adversarial review) | エコシステム未成熟。Layer 2 の harness に統合できる可能性がある |

---

## Open decisions

| # | Decision | Depends on |
|---|----------|-----------|
| 1 | agent_spec の配置: EvidenceBundle か OPA input か | Layer 1 の設計 |
| 2 | harness の抽象度: 個別コントロールか汎用 gate + policy 分岐か | Layer 2 の粒度 |
| 3 | behavioral diff の責務境界: metrics 収集も含むか判定のみか | Layer 3 の scope |
| 4 | agent actions の粒度: コマンド/ファイル/intent 単位か | Layer 4 + cockpit 連携 |
| 5 | Layer 5 の独立性: 独立層か Layer 2 harness に統合か | 敵対的レビューの成熟度 |
| 6 | 新 crate の分割: `libverify-harness` + `libverify-agent` か core に統合か | workspace の方針 |

---

## References

- Boris Tane, "The Software Development Lifecycle Is Dead" (2026/02) — https://boristane.com/blog/the-software-development-lifecycle-is-dead/
- watany, "ロボットのための工場に灯りは要らない" (2026/03) — https://speakerdeck.com/watany/dark-factory-for-agent
- Dan Shapiro, "The Five Levels: from Spicy Autocomplete to the Dark Factory" (2026/01) — https://www.danshapiro.com/blog/2026/01/the-five-levels-from-spicy-autocomplete-to-the-software-factory/
- strongDM, "Software Factories And The Agentic Moment" — https://factory.strongdm.ai/
- Latent Space, "How to Kill the Code Review" — https://www.latent.space/p/reviews-dead
- sugino, "なぜAIは組織を速くしないのか" — https://speakerdeck.com/sugino/nazeaihazu-zhi-wosu-kusinainoka-ling-he-nofu-fen-ke
