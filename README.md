# 学校インシデント情報収集スクリプト

Security NEXT・教育家庭新聞・ICT教育ニュース等のRSSフィードから、
学校・教育機関の情報セキュリティインシデントを毎日自動収集するスクリプトです。

## 動作

- **毎日 09:00 JST** に GitHub Actions が自動実行
- 収集結果は `incidents.json` としてこのリポジトリに保存
- `incident.okigaru.club` のウェブサイトがこのJSONを参照して表示

## ファイル構成

```
collect_incidents.py   # 収集スクリプト本体
incidents.json         # 収集済みインシデントデータ（自動更新）
requirements.txt       # 依存パッケージ
.github/workflows/
  collect.yml          # GitHub Actions ワークフロー定義
```

## 手動実行

GitHub の Actions タブ → 「学校インシデント情報収集」→「Run workflow」
