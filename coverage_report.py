#!/usr/bin/env python3
"""
収集率の月次レポート（改善案6）

incidents.json の月別件数と、ISEN の月次公表件数（isen_monthly.json に手入力）を比べ、
収集率を coverage.md（表）と coverage.json に記録する。
"""

import json
import re
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

BASE = Path(__file__).parent
INCIDENTS_PATH = BASE / "incidents.json"
ISEN_PATH = BASE / "isen_monthly.json"
OUT_MD = BASE / "coverage.md"
OUT_JSON = BASE / "coverage.json"
JST = timezone(timedelta(hours=9))


DATE_RE = re.compile(r"(\d{4})年(\d{1,2})月")


def month_of(date_str: str):
    m = DATE_RE.search(date_str or "")
    return f"{int(m.group(1)):04d}-{int(m.group(2)):02d}" if m else None


def build_rows(incidents: list, isen_counts: dict) -> list:
    collected = Counter(filter(None, (month_of(i.get("date", "")) for i in incidents)))
    months = sorted(set(collected) | set(isen_counts), reverse=True)
    rows = []
    for month in months:
        ours = collected.get(month, 0)
        isen = isen_counts.get(month)
        rate = round(ours / isen * 100, 1) if isinstance(isen, (int, float)) and isen > 0 else None
        rows.append({"month": month, "collected": ours, "isen": isen, "ratePercent": rate})
    return rows


def render_md(rows: list, generated: str) -> str:
    lines = [
        "# 収集率の月次記録",
        "",
        f"更新: {generated}",
        "",
        "「収集件数」は incidents.json に入っている記事の月別件数（記事の日付で集計）、",
        "「ISEN件数」は isen_monthly.json に手入力した件数です。",
        "",
        "| 月 | 収集件数 | ISEN件数 | 収集率 |",
        "|---|---:|---:|---:|",
    ]
    for r in rows:
        isen = "未入力" if r["isen"] is None else str(r["isen"])
        rate = "—" if r["ratePercent"] is None else f"{r['ratePercent']}%"
        lines.append(f"| {r['month']} | {r['collected']} | {isen} | {rate} |")
    return "\n".join(lines) + "\n"


def main():
    incidents = json.loads(INCIDENTS_PATH.read_text(encoding="utf-8")).get("incidents", [])
    isen = {}
    if ISEN_PATH.exists():
        isen = json.loads(ISEN_PATH.read_text(encoding="utf-8")).get("counts", {})
    rows = build_rows(incidents, isen)

    # 中身が変わらなければファイルを書き換えない（無駄なコミットを防ぐ）
    if OUT_JSON.exists() and json.loads(OUT_JSON.read_text(encoding="utf-8")).get("months") == rows:
        print("[変化なし] coverage は更新しません")
        return
    generated = datetime.now(JST).strftime("%Y年%-m月%-d日 %H:%M")
    OUT_JSON.write_text(json.dumps({"generated": generated, "months": rows}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    OUT_MD.write_text(render_md(rows, generated), encoding="utf-8")
    print(f"[保存完了] {OUT_MD} / {OUT_JSON}（{len(rows)}か月分）")


if __name__ == "__main__":
    main()
