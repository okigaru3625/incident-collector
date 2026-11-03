#!/usr/bin/env python3
"""
重複の確認用スクリプト（データは書き換えません）

- Googleニュース由来の件数
- 「重複の可能性がある組み合わせ」（30日以内で、見出しの一致率が 0.4 以上 0.75 未満、
  または地名・学校名が共通で同じ分類のもの）
を表示します（組織名が両方取れて異なる組み合わせは別の事件として除きます）。

実行方法: python check_duplicates.py
"""

import json
import sys
import types
from pathlib import Path

try:
    import feedparser  # noqa: F401
except ImportError:
    sys.modules["feedparser"] = types.ModuleType("feedparser")

import collect_incidents as c  # noqa: E402

MAYBE_THRESHOLD = 0.4


def candidate_pairs(incidents: list) -> list:
    pairs = []
    for i, a in enumerate(incidents):
        for b in incidents[i + 1:]:
            gap = c.days_apart(a, b)
            if gap is None or gap > c.DUP_WINDOW_DAYS:
                continue
            ta, tb = c.strip_source_suffix(a), c.strip_source_suffix(b)
            oa, ob = c.extract_org(ta), c.extract_org(tb)
            if oa and ob and oa != ob:
                continue  # 組織が違えば別の事件
            sim = c.title_similarity(ta, tb)
            common = c.extract_entities(ta) & c.extract_entities(tb)
            same_cat = a.get("category") == b.get("category")
            if sim >= MAYBE_THRESHOLD or (common and same_cat and (c.is_google_news(a) or c.is_google_news(b))):
                pairs.append((sim, a, b, common))
    pairs.sort(key=lambda p: p[0], reverse=True)
    return pairs


def main():
    data = json.loads(c.OUTPUT_PATH.read_text(encoding="utf-8"))
    incidents = data.get("incidents", [])
    gn = [i for i in incidents if c.is_google_news(i)]
    print(f"全件: {len(incidents)}件 / うちGoogleニュース由来: {len(gn)}件")
    pairs = candidate_pairs(incidents)
    print(f"重複の可能性がある組み合わせ: {len(pairs)}組")
    for sim, a, b, common in pairs:
        extra = f" 共通: {'・'.join(sorted(common))}" if common else ""
        print(f"- 一致率{sim:.2f}{extra}")
        print(f"    {a['date']} [{a['source']}] {a['title']}")
        print(f"    {b['date']} [{b['source']}] {b['title']}")


if __name__ == "__main__":
    main()
