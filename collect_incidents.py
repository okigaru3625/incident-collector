#!/usr/bin/env python3
"""
学校・教育現場の情報インシデント収集スクリプト
各種RSSフィードから教育関連のインシデント情報を収集し、
JSON形式でウェブサイト用データファイルに出力する。
"""

import json
import os
import re
import hashlib
from datetime import datetime, timezone, timedelta
from pathlib import Path

import feedparser
import requests
from bs4 import BeautifulSoup

# 出力先パス（スクリプトと同じディレクトリに出力）
OUTPUT_PATH = Path(__file__).parent / "incidents.json"

# 教育関連キーワード（タイトル・説明文のいずれかに含まれていれば収集対象）
EDU_KEYWORDS = [
    "学校", "大学", "教育", "生徒", "学生", "児童", "教員", "教職員",
    "高校", "中学", "小学", "幼稚園", "保育", "教育委員会", "教育機関",
    "校長", "授業", "学習", "入試", "受験", "スクール", "キャンパス",
    "附属", "付属", "学院", "学部", "研究科", "大学院",
]

# インシデント関連キーワード（教育関連と組み合わせて判定）
INCIDENT_KEYWORDS = [
    "漏えい", "漏洩", "流出", "不正アクセス", "サイバー攻撃", "ランサムウェア",
    "個人情報", "誤送信", "誤公開", "紛失", "盗難", "ウイルス", "マルウェア",
    "情報セキュリティ", "インシデント", "セキュリティ事故", "データ侵害",
    "不正利用", "なりすまし", "フィッシング", "情報漏れ", "誤廃棄",
    "誤アップロード", "誤投稿", "踏み台", "侵害", "暗号化被害",
]

# RSSフィードソース一覧
RSS_SOURCES = [
    {
        "name": "Security NEXT",
        "url": "https://www.security-next.com/feed",
        "type": "security",
    },
    {
        "name": "教育家庭新聞",
        "url": "https://www.kknews.co.jp/feed",
        "type": "education",
    },
    {
        "name": "ICT教育ニュース",
        "url": "https://ict-enews.net/feed/",
        "type": "education",
    },
    {
        "name": "Yahoo!ニュース IT",
        "url": "https://news.yahoo.co.jp/rss/topics/it.xml",
        "type": "news",
    },
]

# インシデントカテゴリの分類ルール
CATEGORY_RULES = [
    {"keywords": ["ランサムウェア", "ransomware"], "category": "ランサムウェア", "color": "red"},
    {"keywords": ["不正アクセス", "サイバー攻撃", "踏み台", "侵害"], "category": "不正アクセス", "color": "orange"},
    {"keywords": ["誤送信", "誤公開", "誤アップロード", "誤投稿", "誤操作", "誤廃棄"], "category": "誤操作・誤公開", "color": "yellow"},
    {"keywords": ["紛失", "盗難", "所在不明"], "category": "紛失・盗難", "color": "amber"},
    {"keywords": ["調査", "報告", "注意喚起", "ガイドライン"], "category": "調査・報告", "color": "blue"},
    {"keywords": ["ウイルス", "マルウェア", "感染"], "category": "マルウェア感染", "color": "red"},
    {"keywords": ["フィッシング", "なりすまし"], "category": "フィッシング", "color": "purple"},
]


def classify_incident(title: str, description: str) -> dict:
    """タイトルと説明文からインシデントカテゴリを分類する"""
    text = (title + " " + description).lower()
    for rule in CATEGORY_RULES:
        for kw in rule["keywords"]:
            if kw in text:
                return {"category": rule["category"], "color": rule["color"]}
    return {"category": "情報セキュリティ", "color": "gray"}


def is_education_related(title: str, description: str) -> bool:
    """教育関連のインシデントかどうかを判定する"""
    text = title + " " + description
    has_edu = any(kw in text for kw in EDU_KEYWORDS)
    has_incident = any(kw in text for kw in INCIDENT_KEYWORDS)
    # Security NEXTは教育キーワードだけで十分（インシデント専門メディアのため）
    return has_edu or (has_edu and has_incident)


def is_incident_related(title: str, description: str) -> bool:
    """インシデント関連かどうかを判定する"""
    text = title + " " + description
    return any(kw in text for kw in INCIDENT_KEYWORDS)


def clean_html(html_text: str) -> str:
    """HTMLタグを除去してプレーンテキストに変換する"""
    if not html_text:
        return ""
    soup = BeautifulSoup(html_text, "html.parser")
    return soup.get_text(separator=" ", strip=True)


def generate_id(url: str) -> str:
    """URLからユニークIDを生成する"""
    return hashlib.md5(url.encode()).hexdigest()[:12]


def parse_date(entry) -> str:
    """フィードエントリから日付文字列を取得する"""
    if hasattr(entry, "published_parsed") and entry.published_parsed:
        dt = datetime(*entry.published_parsed[:6], tzinfo=timezone.utc)
        jst = timezone(timedelta(hours=9))
        dt_jst = dt.astimezone(jst)
        return dt_jst.strftime("%Y年%-m月%-d日")
    return datetime.now(timezone(timedelta(hours=9))).strftime("%Y年%-m月%-d日")


def fetch_rss_incidents() -> list:
    """全RSSフィードからインシデント情報を収集する"""
    all_incidents = []
    seen_ids = set()

    for source in RSS_SOURCES:
        print(f"[収集中] {source['name']} ({source['url']})")
        try:
            feed = feedparser.parse(source["url"])
            count = 0

            for entry in feed.entries:
                title = getattr(entry, "title", "") or ""
                link = getattr(entry, "link", "") or ""
                summary = getattr(entry, "summary", "") or ""
                description = clean_html(summary)

                # 重複チェック
                entry_id = generate_id(link)
                if entry_id in seen_ids:
                    continue

                # 教育関連かつインシデント関連かを判定
                if source["type"] == "security":
                    # Security NEXTは教育キーワードのみで判定（インシデント専門サイト）
                    if not is_education_related(title, description):
                        continue
                else:
                    # 他のソースは教育キーワード＋インシデントキーワードの両方が必要
                    if not (is_education_related(title, description) and is_incident_related(title, description)):
                        continue

                seen_ids.add(entry_id)
                category_info = classify_incident(title, description)
                date_str = parse_date(entry)

                incident = {
                    "id": entry_id,
                    "date": date_str,
                    "title": title,
                    "description": description[:400] + "…" if len(description) > 400 else description,
                    "url": link,
                    "source": source["name"],
                    "category": category_info["category"],
                    "color": category_info["color"],
                    "scale": "",  # 漏えい規模（自動収集では空欄）
                }
                all_incidents.append(incident)
                count += 1

            print(f"  → {count}件の教育関連インシデントを取得")

        except Exception as e:
            print(f"  [エラー] {source['name']}: {e}")

    return all_incidents


def load_existing_incidents() -> list:
    """既存のJSONデータを読み込む"""
    if OUTPUT_PATH.exists():
        with open(OUTPUT_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data.get("incidents", [])
    return []


def normalize_title(title: str) -> str:
    """タイトルを正規化して比較用文字列を生成する（記号・空白除去）"""
    # 記号・空白・句読点を除去して小文字化
    t = re.sub(r"[\s\u3000\u30fb\uff65・。、,.\-\|｜/／「」【】『』（）()\[\]\{\}]+", "", title)
    return t.lower()


def is_similar_title(title_a: str, title_b: str, threshold: float = 0.75) -> bool:
    """2つのタイトルが類似しているかをJaccard係数で判定する"""
    a = normalize_title(title_a)
    b = normalize_title(title_b)
    if not a or not b:
        return False
    # 文字n-gramで比較（n=3）
    def ngrams(s: str, n: int = 3) -> set:
        return {s[i:i+n] for i in range(len(s) - n + 1)} if len(s) >= n else set(s)
    set_a = ngrams(a)
    set_b = ngrams(b)
    if not set_a or not set_b:
        return a == b
    intersection = len(set_a & set_b)
    union = len(set_a | set_b)
    return (intersection / union) >= threshold


def merge_incidents(existing: list, new_items: list) -> list:
    """既存データと新規データをマージして重複を除去する（ID＋タイトル類似度の二重チェック）"""
    existing_ids = {item["id"] for item in existing}
    existing_titles = [item["title"] for item in existing]
    merged = list(existing)

    added = 0
    skipped_similar = 0
    for item in new_items:
        # IDによる重複チェック
        if item["id"] in existing_ids:
            continue
        # タイトル類似度による重複チェック（同一事件の複数ソース報道を排除）
        title_dup = any(is_similar_title(item["title"], t) for t in existing_titles)
        if title_dup:
            skipped_similar += 1
            print(f"  [類似重複スキップ] {item['title'][:40]}")
            continue
        merged.append(item)
        existing_ids.add(item["id"])
        existing_titles.append(item["title"])
        added += 1

    print(f"[マージ] 新規追加: {added}件 / 類似重複スキップ: {skipped_similar}件 / 既存: {len(existing)}件 / 合計: {len(merged)}件")

    # 日付でソート（新しい順）
    def sort_key(item):
        date_str = item.get("date", "")
        # "2026年3月19日" → ソート可能な形式に変換
        match = re.search(r"(\d{4})年(\d{1,2})月(\d{1,2})日", date_str)
        if match:
            y, m, d = int(match.group(1)), int(match.group(2)), int(match.group(3))
            return (y, m, d)
        return (0, 0, 0)

    merged.sort(key=sort_key, reverse=True)
    return merged


def save_incidents(incidents: list):
    """インシデントデータをJSONファイルに保存する"""
    jst = timezone(timedelta(hours=9))
    now = datetime.now(jst)

    data = {
        "lastUpdated": now.strftime("%Y年%-m月%-d日 %H:%M"),
        "lastUpdatedISO": now.isoformat(),
        "totalCount": len(incidents),
        "incidents": incidents,
    }

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

    print(f"[保存完了] {OUTPUT_PATH} ({len(incidents)}件)")


def main():
    print("=" * 60)
    print("学校インシデント情報収集スクリプト")
    print(f"実行時刻: {datetime.now(timezone(timedelta(hours=9))).strftime('%Y-%m-%d %H:%M:%S JST')}")
    print("=" * 60)

    # 既存データを読み込む
    existing = load_existing_incidents()
    print(f"[既存データ] {len(existing)}件")

    # 新規データを収集する
    new_items = fetch_rss_incidents()
    print(f"[新規収集] {len(new_items)}件")

    # マージして保存
    merged = merge_incidents(existing, new_items)
    save_incidents(merged)

    print("=" * 60)
    print("収集完了")


if __name__ == "__main__":
    main()
