# 学校インシデント情報収集スクリプト

Security NEXT・教育家庭新聞・ICT教育ニュース・Googleニュース検索などのRSSフィードから、
学校・教育機関の情報セキュリティインシデントを自動収集するスクリプトです。

## 動作

- **3時間おき**（JST 9時・12時・15時…）に GitHub Actions が自動実行
  - GitHub側の混雑で、実行が数十分〜数時間遅れることがあります
- 収集結果は `incidents.json` としてこのリポジトリに保存
  - **記事の内容に変化がないときは、ファイルもコミットも更新しません**（`lastUpdated` も据え置き）
- `incident.okigaru.club` のウェブサイトがこのJSONを参照して表示

## 情報源

| 情報源 | 取得方法 |
|---|---|
| Security NEXT | RSSの1〜3ページ目（`/feed`, `/feed/?paged=2`, `/feed/?paged=3`） |
| 教育家庭新聞・ICT教育ニュース・Yahoo!ニュースIT | RSS |
| Googleニュース | キーワード検索のRSS（直近7日分）。キーワードは `GOOGLE_NEWS_QUERIES` |

## 判定ルール（collect_incidents.py）

1. **教育関連の語**（学校・児童・教育委員会・「…大」など）があること。「機械学習」などは除いて判定
2. **事故関連の語**（紛失・誤送信・閲覧可能・サポート詐欺など）があること
   - Security NEXT は説明文まで、それ以外はタイトルだけで判定
3. タイトルに**除外語**がないこと
   - 必ず除外：病院・患者・脆弱性
   - お知らせ系（セミナー・開催・協定など）は除外。ただし「誤送信」「紛失」など明確な事故語があれば残す

分類は `CATEGORY_RULES` の上から順に当てはめます（タイトル優先）。
ルールを変えると、次回実行時に**既存の記事にも当て直され**、対象外になった記事は `excluded.json` に移ります
（ルールを戻せば自動で `incidents.json` に戻ります）。

## 重複の判定

同じ事件が複数の媒体から入らないよう、**日付が30日以内**の記事とだけ比べます。

- 見出しの一致率（3文字ずつ）が 0.75 以上 → 重複
- 組織名（「… - 厚木市」の末尾）が両方取れて**異なる** → 別の事件
- 組織名が同じで、分類も同じ、一致率 0.4 以上 → 重複
- Googleニュース由来は、地名・学校名が共通で分類も同じ（14日以内・一致率 0.2 以上）→ 重複
- 同じ事件なら Security NEXT など専門メディア側を残します

確認用に `python check_duplicates.py` で「Googleニュース由来の件数」と「重複の可能性がある組み合わせ」を表示できます（データは書き換えません）。

## 収集率の月次記録

毎月1日に `coverage_report.py` が動き、`coverage.md`（表）と `coverage.json` を更新します。

**ISENの件数の入力手順**

1. GitHub で `isen_monthly.json` を開き、右上の鉛筆マーク（Edit）を押す
2. `"counts": {}` の中に、月と件数を書く
   ```json
   "counts": {
     "2026-09": 30,
     "2026-10": 25
   }
   ```
3. 「Commit changes」を押して保存
4. すぐ反映したいときは、Actions タブ →「収集率の月次記録」→「Run workflow」

## ファイル構成

```
collect_incidents.py   # 収集スクリプト本体
incidents.json         # 収集済みインシデントデータ（自動更新）
excluded.json          # 判定ルールで対象外になった過去の記事（表示されない）
check_duplicates.py    # 重複の確認用（表示のみ）
coverage_report.py     # 収集率の月次集計
isen_monthly.json      # ISENの月次件数（手入力）
coverage.md / .json    # 収集率の記録（自動更新）
tests/test_rules.py    # 判定ルールのテスト
requirements.txt       # 依存パッケージ
.github/workflows/
  collect.yml          # 3時間おきの収集
  coverage.yml         # 毎月1日の収集率記録
```

## 手動実行

GitHub の Actions タブ → 「学校インシデント情報収集」→「Run workflow」

## テスト

```bash
python -m unittest discover -s tests
```
