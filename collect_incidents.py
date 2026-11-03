#!/usr/bin/env python3
"""
学校・教育現場の情報インシデント収集スクリプト
各種RSSフィード（Security NEXT・教育系メディア・Googleニュース検索）から
教育関連のインシデント情報を収集し、JSON形式でウェブサイト用データファイルに出力する。
"""

import json
import re
import hashlib
from datetime import datetime, timezone, timedelta, date
from pathlib import Path
from urllib.parse import quote

import feedparser
from bs4 import BeautifulSoup

JST = timezone(timedelta(hours=9))

# 出力先パス（スクリプトと同じディレクトリに出力）
OUTPUT_PATH = Path(__file__).parent / "incidents.json"
# 新ルールで対象外になった既存記事の退避先（ページには表示されない。ルールを戻せば自動で復帰）
EXCLUDED_PATH = Path(__file__).parent / "excluded.json"

GOOGLE_NEWS_SOURCE_PREFIX = "Googleニュース"

# ---------------------------------------------------------------------------
# 判定用キーワード
# ---------------------------------------------------------------------------

# 教育関連キーワード（タイトル・説明文のいずれかに含まれていれば教育関連）
EDU_KEYWORDS = [
    "学校", "大学", "教育", "生徒", "学生", "児童", "教員", "教職員", "教諭",
    "高校", "中学", "小学", "幼稚園", "保育", "こども園", "教育委員会", "教委",
    "教育機関", "校長", "授業", "学習", "入試", "受験", "スクール", "キャンパス",
    "附属", "付属", "学院", "学園", "学部", "研究科", "大学院", "高専",
    "PTA", "部活", "修学旅行", "卒業",
]
# 「…大」「…高」で終わる学校名（Security NEXTの「 - 佐賀大」「 - 日大法学部」など）
EDU_ORG_PATTERN = re.compile(r"(大|大学|高|高専|学園|学院|中高校|小学校|中学校)(法学部|医学部|学部)?$")

# 教育語の誤反応を起こす言い回し（判定前に取り除く）
EDU_FALSE_POSITIVE_PHRASES = [
    "機械学習", "深層学習", "強化学習", "連合学習", "学習データ", "学習モデル",
    "事前学習", "追加学習", "教師データ", "教師あり", "教師なし",
]

# インシデント関連キーワード
INCIDENT_KEYWORDS = [
    "漏えい", "漏洩", "流出", "不正アクセス", "サイバー攻撃", "ランサム",
    "個人情報", "誤送信", "誤公開", "紛失", "盗難", "ウイルス", "マルウェア",
    "情報セキュリティ", "インシデント", "セキュリティ事故", "データ侵害",
    "不正利用", "なりすまし", "フィッシング", "情報漏れ", "誤廃棄",
    "誤アップロード", "誤投稿", "踏み台", "侵害", "暗号化被害",
    "閲覧可能", "参照可能", "誤掲載", "誤添付", "誤配布", "誤送付", "誤配信",
    "誤交付", "誤記載", "改ざん", "サポート詐欺", "偽警告", "不正ログイン",
    "所在不明", "置き忘れ", "不正持出", "持ち出し", "設定ミス", "送信ミス",
    "同意なく", "同意なし", "目的外", "マスキング不備", "誤って", "別の児童",
    "別の生徒", "SNSに投稿", "が公開され", "第三者がアクセス",
]

# タイトルにあれば必ず対象外にする語（病院の患者情報、製品の脆弱性情報）
HARD_EXCLUDE_KEYWORDS = ["病院", "患者", "脆弱性"]

# タイトルにあれば対象外にする語（お知らせ・宣伝系）。
# ただし、タイトルに明確な事故語（STRONG_INCIDENT_KEYWORDS）があれば対象のまま残す。
SOFT_EXCLUDE_KEYWORDS = [
    "セミナー", "ウェビナー", "開催", "協定", "講話", "講演", "研修教材", "教材",
    "実証", "支援を開始", "提供開始", "発売", "リリース", "機能を拡充", "無償配布",
    "策定", "バージョンアップ", "動画を公開", "導入", "採択", "表彰", "受賞",
]
STRONG_INCIDENT_KEYWORDS = [
    "誤送信", "紛失", "所在不明", "漏えい", "漏洩", "流出", "不正アクセス",
    "被害", "誤公開", "誤掲載", "閲覧可能", "誤廃棄", "盗難", "改ざん",
]

# ---------------------------------------------------------------------------
# 情報源
# ---------------------------------------------------------------------------

# type: security = インシデント専門メディア（説明文まで見て判定）
#       education / news = 一般・教育系メディア（タイトルに事故語が必要）
# pages: WordPressの /feed/?paged=N を何ページ目まで取得するか
RSS_SOURCES = [
    {
        "name": "Security NEXT",
        "url": "https://www.security-next.com/feed",
        "type": "security",
        "pages": 3,
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

# GoogleニュースRSS検索のキーワード（直近7日分を検索）
GOOGLE_NEWS_QUERIES = [
    "小学校 個人情報 紛失",
    "中学校 個人情報 紛失",
    "高校 個人情報 紛失",
    "学校 USBメモリ 紛失",
    "小学校 個人情報 漏えい",
    "中学校 個人情報 漏えい",
    "高校 個人情報 流出",
    "学校 誤送信 個人情報",
    "教育委員会 誤送信",
    "教育委員会 個人情報 漏えい",
    "教育委員会 不正アクセス",
    "学校 不正アクセス",
    "学校 ランサムウェア",
    "学校 サポート詐欺",
    "大学 個人情報 流出",
]


def google_news_url(query: str) -> str:
    q = quote(f"{query} when:7d")
    return f"https://news.google.com/rss/search?q={q}&hl=ja&gl=JP&ceid=JP:ja"


def build_feed_urls(source: dict) -> list:
    """取得するフィードURLの一覧（過去ページを含む）"""
    urls = [source["url"]]
    base = source["url"].rstrip("/")
    for page in range(2, source.get("pages", 1) + 1):
        urls.append(f"{base}/?paged={page}")
    return urls


# ---------------------------------------------------------------------------
# 分類
# ---------------------------------------------------------------------------

# 上から順に判定し、最初に当てはまった分類を採用する。
# カテゴリ名・色は incident.html の表示に合わせて既存のものだけを使う。
CATEGORY_RULES = [
    {"keywords": ["ランサム", "ransomware"], "category": "ランサムウェア", "color": "red"},
    {"keywords": ["フィッシング", "なりすまし", "サポート詐欺", "偽警告", "詐欺"], "category": "フィッシング", "color": "purple"},
    {"keywords": ["不正アクセス", "サイバー攻撃", "踏み台", "侵害", "改ざん", "不正ログイン", "第三者がアクセス", "スパム"], "category": "不正アクセス", "color": "orange"},
    {"keywords": ["ウイルス", "マルウェア", "感染", "不正コード"], "category": "マルウェア感染", "color": "red"},
    {"keywords": ["紛失", "盗難", "所在不明", "置き忘れ", "不正持出", "持ち出し", "持ち帰"], "category": "紛失・盗難", "color": "amber"},
    {"keywords": ["誤送信", "誤公開", "誤アップロード", "誤投稿", "誤操作", "誤廃棄",
                  "誤掲載", "誤添付", "誤配布", "誤送付", "誤配信", "誤交付", "誤記載",
                  "閲覧可能", "参照可能", "設定ミス", "送信ミス", "マスキング不備",
                  "別の児童", "別の生徒", "誤って", "同意なく", "同意なし", "目的外",
                  "掲示", "SNSに投稿", "ブログに", "掲示板投稿", "意図せず"],
     "category": "誤操作・誤公開", "color": "yellow"},
    # 「調査中」の事故を拾わないよう、単独の「調査」「報告」は使わない
    {"keywords": ["調査結果", "実態を調査", "利用実態", "報告書", "注意喚起", "ガイドライン",
                  "調べ", "総研調査", "延べ", "前年"],
     "category": "調査・報告", "color": "blue"},
]
DEFAULT_CATEGORY = {"category": "情報セキュリティ", "color": "gray"}


def _match_category(text: str):
    text = text.lower()
    for rule in CATEGORY_RULES:
        for kw in rule["keywords"]:
            if kw.lower() in text:
                return {"category": rule["category"], "color": rule["color"]}
    return None


def classify_incident(title: str, description: str) -> dict:
    """タイトルを優先して分類し、決まらなければ説明文も見る"""
    return _match_category(title) or _match_category(description) or dict(DEFAULT_CATEGORY)


# ---------------------------------------------------------------------------
# 対象判定
# ---------------------------------------------------------------------------

def _strip_false_positives(text: str) -> str:
    for phrase in EDU_FALSE_POSITIVE_PHRASES:
        text = text.replace(phrase, "")
    return text


def is_education_related(title: str, description: str) -> bool:
    """教育関連の記事かどうか（教育語だけを見る）"""
    text = _strip_false_positives(title + " " + description)
    if any(kw in text for kw in EDU_KEYWORDS):
        return True
    org = extract_org(title)
    return bool(org and EDU_ORG_PATTERN.search(org))


def is_incident_related(text: str) -> bool:
    """インシデント関連の語を含むかどうか"""
    return any(kw in text for kw in INCIDENT_KEYWORDS)


def exclusion_reason(title: str):
    """タイトルが除外対象なら理由を返す（対象なら None）"""
    for kw in HARD_EXCLUDE_KEYWORDS:
        if kw in title:
            return f"除外語「{kw}」"
    if not any(kw in title for kw in STRONG_INCIDENT_KEYWORDS):
        for kw in SOFT_EXCLUDE_KEYWORDS:
            if kw in title:
                return f"除外語「{kw}」"
    return None


def judge(title: str, description: str, source_type: str):
    """対象なら None、対象外なら理由（文字列）を返す"""
    if not is_education_related(title, description):
        return "教育関連の語なし"
    # 専門メディアは説明文まで、それ以外はタイトルだけで事故語を探す
    incident_text = title + " " + description if source_type == "security" else title
    if not is_incident_related(incident_text):
        return "事故関連の語なし"
    return exclusion_reason(title)


def is_target(title: str, description: str, source_type: str) -> bool:
    return judge(title, description, source_type) is None


def source_type_of(source_name: str) -> str:
    """保存済みデータの source 名から判定用の種別を求める"""
    for src in RSS_SOURCES:
        if src["name"] == source_name:
            return src["type"]
    if source_name.startswith(GOOGLE_NEWS_SOURCE_PREFIX):
        return "news"
    return "education"


# ---------------------------------------------------------------------------
# 共通処理
# ---------------------------------------------------------------------------

def clean_html(html_text: str) -> str:
    """HTMLタグを除去してプレーンテキストに変換する"""
    if not html_text:
        return ""
    soup = BeautifulSoup(html_text, "html.parser")
    return soup.get_text(separator=" ", strip=True)


def generate_id(url: str) -> str:
    """URLからユニークIDを生成する"""
    return hashlib.md5(url.encode()).hexdigest()[:12]


def format_date(d: date) -> str:
    return f"{d.year}年{d.month}月{d.day}日"


def parse_date(entry) -> str:
    """フィードエントリから日付文字列を取得する"""
    if getattr(entry, "published_parsed", None):
        dt = datetime(*entry.published_parsed[:6], tzinfo=timezone.utc).astimezone(JST)
        return format_date(dt.date())
    return format_date(datetime.now(JST).date())


def to_date(date_str: str):
    """「2026年3月19日」形式を date に変換する（失敗時 None）"""
    m = re.search(r"(\d{4})年(\d{1,2})月(\d{1,2})日", date_str or "")
    if not m:
        return None
    return date(int(m.group(1)), int(m.group(2)), int(m.group(3)))


def split_google_news_title(title: str, publisher: str = ""):
    """Googleニュースの「見出し - 媒体名」を（見出し, 媒体名）に分ける"""
    if publisher and title.endswith(" - " + publisher):
        return title[: -len(" - " + publisher)].strip(), publisher
    if " - " in title:
        head, tail = title.rsplit(" - ", 1)
        return head.strip(), tail.strip()
    return title.strip(), publisher


def make_incident(title, description, link, source_name, date_str) -> dict:
    category_info = classify_incident(title, description)
    return {
        "id": generate_id(link),
        "date": date_str,
        "title": title,
        "description": description[:400] + "…" if len(description) > 400 else description,
        "url": link,
        "source": source_name,
        "category": category_info["category"],
        "color": category_info["color"],
        "scale": "",  # 漏えい規模（自動収集では空欄）
    }


# ---------------------------------------------------------------------------
# 収集
# ---------------------------------------------------------------------------

def fetch_rss_incidents() -> list:
    """専門・教育系RSSフィードからインシデント情報を収集する"""
    all_incidents = []
    seen_ids = set()

    for source in RSS_SOURCES:
        count = 0
        for url in build_feed_urls(source):
            print(f"[収集中] {source['name']} ({url})")
            try:
                feed = feedparser.parse(url)
                for entry in feed.entries:
                    title = (getattr(entry, "title", "") or "").strip()
                    link = getattr(entry, "link", "") or ""
                    description = clean_html(getattr(entry, "summary", "") or "")
                    if not link:
                        continue
                    entry_id = generate_id(link)
                    if entry_id in seen_ids:
                        continue
                    if not is_target(title, description, source["type"]):
                        continue
                    seen_ids.add(entry_id)
                    all_incidents.append(
                        make_incident(title, description, link, source["name"], parse_date(entry))
                    )
                    count += 1
            except Exception as e:
                print(f"  [エラー] {source['name']}: {e}")
        print(f"  → {source['name']}: {count}件の教育関連インシデントを取得")

    return all_incidents


def fetch_google_news_incidents() -> list:
    """GoogleニュースのRSS検索からインシデント情報を収集する"""
    all_incidents = []
    seen_ids = set()

    for query in GOOGLE_NEWS_QUERIES:
        url = google_news_url(query)
        count = 0
        try:
            feed = feedparser.parse(url)
            for entry in feed.entries:
                raw_title = (getattr(entry, "title", "") or "").strip()
                link = getattr(entry, "link", "") or ""
                publisher = ""
                src = getattr(entry, "source", None)
                if src is not None:
                    publisher = (src.get("title") if hasattr(src, "get") else "") or ""
                title, publisher = split_google_news_title(raw_title, publisher)
                if not link:
                    continue
                entry_id = generate_id(link)
                if entry_id in seen_ids:
                    continue
                # Googleニュースの説明文は見出しの繰り返しなので、タイトルで判定する
                if not is_target(title, "", "news"):
                    continue
                seen_ids.add(entry_id)
                source_name = f"{GOOGLE_NEWS_SOURCE_PREFIX}（{publisher}）" if publisher else GOOGLE_NEWS_SOURCE_PREFIX
                all_incidents.append(make_incident(title, "", link, source_name, parse_date(entry)))
                count += 1
        except Exception as e:
            print(f"  [エラー] Googleニュース「{query}」: {e}")
        print(f"[Googleニュース] 「{query}」: {count}件")

    return all_incidents


# ---------------------------------------------------------------------------
# 重複判定
# ---------------------------------------------------------------------------

DUP_WINDOW_DAYS = 30          # この日数以内の記事とだけ比べる
ENTITY_DUP_WINDOW_DAYS = 14   # Googleニュースの「地名・学校名＋分類」一致で比べる日数
SIMILAR_THRESHOLD = 0.75      # 見出しの3文字一致率（これ以上なら重複）
SAME_ORG_THRESHOLD = 0.4      # 同じ組織・同じ分類なら、この一致率で重複
ENTITY_THRESHOLD = 0.2        # Googleニュース由来で地名・学校名が共通なら、この一致率で重複

ORG_SUFFIX_PATTERN = re.compile(
    r"(都|道|府|県|市|区|町|村|大|大学|大学院|高|高専|学園|学院|学校|校|園|会社|グループ|協議会|組合|機構|学部|病院|センター)$"
)
ENTITY_PATTERNS = [
    re.compile(r"[一-龥]{1,5}(?:都|道|府|県|市|区|町|村)"),
    re.compile(r"[一-龥ァ-ヶー]{1,8}(?:大学|大|高校|高専|学園|学院|中学校|小学校)"),
]


def strip_source_suffix(item: dict) -> str:
    """比較用の見出し（Googleニュース由来は媒体名を除く）"""
    title = item.get("title", "")
    if item.get("source", "").startswith(GOOGLE_NEWS_SOURCE_PREFIX):
        title, _ = split_google_news_title(title)
    return title


def extract_org(title: str):
    """「… - 厚木市」形式の末尾から組織名を取り出す（取れなければ None）"""
    if " - " not in title:
        return None
    tail = title.rsplit(" - ", 1)[1].strip()
    if 0 < len(tail) <= 20 and "、" not in tail and ORG_SUFFIX_PATTERN.search(tail):
        return tail
    return None


def extract_entities(title: str) -> set:
    """見出しに含まれる地名・学校名の候補"""
    found = set()
    for pat in ENTITY_PATTERNS:
        found.update(m.group(0) for m in pat.finditer(title))
    org = extract_org(title)
    if org:
        found.add(org)
    return found


def normalize_title(title: str) -> str:
    """タイトルを正規化して比較用文字列を生成する（記号・空白除去）"""
    t = re.sub(r"[\s　・･・。、,.\-\|｜/／「」【】『』（）()\[\]\{\}]+", "", title)
    return t.lower()


def title_similarity(title_a: str, title_b: str) -> float:
    """2つのタイトルの3文字一致率（Jaccard係数）"""
    a = normalize_title(title_a)
    b = normalize_title(title_b)
    if not a or not b:
        return 0.0

    def ngrams(s: str, n: int = 3) -> set:
        return {s[i:i + n] for i in range(len(s) - n + 1)} if len(s) >= n else {s}

    set_a, set_b = ngrams(a), ngrams(b)
    return len(set_a & set_b) / len(set_a | set_b)


def is_similar_title(title_a: str, title_b: str, threshold: float = SIMILAR_THRESHOLD) -> bool:
    return title_similarity(title_a, title_b) >= threshold


def is_google_news(item: dict) -> bool:
    return item.get("source", "").startswith(GOOGLE_NEWS_SOURCE_PREFIX)


def days_apart(a: dict, b: dict):
    da, db = to_date(a.get("date", "")), to_date(b.get("date", ""))
    if da is None or db is None:
        return None
    return abs((da - db).days)


def duplicate_reason(new: dict, old: dict):
    """new が old と同じ事件なら理由を返す（別の事件なら None）"""
    gap = days_apart(new, old)
    if gap is None or gap > DUP_WINDOW_DAYS:
        return None
    t_new, t_old = strip_source_suffix(new), strip_source_suffix(old)
    org_new, org_old = extract_org(t_new), extract_org(t_old)
    if org_new and org_old and org_new != org_old:
        return None  # 組織が違えば別の事件
    sim = title_similarity(t_new, t_old)
    if sim >= SIMILAR_THRESHOLD:
        return f"見出し一致率{sim:.2f}"
    same_category = new.get("category") == old.get("category")
    if org_new and org_new == org_old and same_category and sim >= SAME_ORG_THRESHOLD:
        return f"同じ組織「{org_new}」・同じ分類・一致率{sim:.2f}"
    if (is_google_news(new) or is_google_news(old)) and same_category and gap <= ENTITY_DUP_WINDOW_DAYS:
        common = extract_entities(t_new) & extract_entities(t_old)
        if common and sim >= ENTITY_THRESHOLD:
            return f"地名・学校名「{'・'.join(sorted(common))}」・同じ分類・一致率{sim:.2f}"
    return None


def date_sort_key(item: dict):
    d = to_date(item.get("date", ""))
    return (d.year, d.month, d.day) if d else (0, 0, 0)


def merge_incidents(existing: list, new_items: list) -> list:
    """既存データと新規データをマージして重複を除去する（ID＋直近30日の見出し・組織チェック）"""
    existing_ids = {item["id"] for item in existing}
    merged = list(existing)

    # 専門メディアを先に処理し、同じ事件ならGoogleニュース側を捨てる
    ordered = sorted(new_items, key=is_google_news)

    added = 0
    skipped_similar = 0
    for item in ordered:
        if item["id"] in existing_ids:
            continue
        dup_of = None
        for old in merged:
            reason = duplicate_reason(item, old)
            if reason:
                dup_of = (old, reason)
                break
        if dup_of:
            skipped_similar += 1
            print(f"  [重複スキップ] {item['title'][:40]} ≒ {dup_of[0]['title'][:40]}（{dup_of[1]}）")
            continue
        merged.append(item)
        existing_ids.add(item["id"])
        added += 1

    print(f"[マージ] 新規追加: {added}件 / 重複スキップ: {skipped_similar}件 / 既存: {len(existing)}件 / 合計: {len(merged)}件")

    merged.sort(key=date_sort_key, reverse=True)
    return merged


# ---------------------------------------------------------------------------
# 既存データへの新ルール適用
# ---------------------------------------------------------------------------

def reapply_rules(existing: list, excluded: list):
    """既存データに現在の判定・分類ルールを当て直す。

    戻り値: (表示する記事, 退避する記事)
    退避済みの記事も毎回判定し直し、対象に戻ったものは表示側へ復帰させる。
    """
    kept, removed = [], []
    for item in existing + excluded:
        base = {k: v for k, v in item.items() if k != "excludedReason"}
        title = base.get("title", "")
        desc = base.get("description", "")
        reason = judge(strip_source_suffix(base), desc, source_type_of(base.get("source", "")))
        if reason:
            base["excludedReason"] = reason
            removed.append(base)
        else:
            base.update(classify_incident(strip_source_suffix(base), desc))
            kept.append(base)
    kept.sort(key=date_sort_key, reverse=True)
    removed.sort(key=date_sort_key, reverse=True)
    return kept, removed


# ---------------------------------------------------------------------------
# 入出力
# ---------------------------------------------------------------------------

def _load(path: Path, key: str) -> list:
    if path.exists():
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f).get(key, [])
    return []


def load_existing_incidents() -> list:
    """既存のJSONデータを読み込む"""
    return _load(OUTPUT_PATH, "incidents")


def load_excluded_incidents() -> list:
    return _load(EXCLUDED_PATH, "excluded")


def save_incidents(incidents: list) -> bool:
    """インシデントデータを保存する。記事内容に変化がなければ何もしない（lastUpdatedも据え置き）"""
    if OUTPUT_PATH.exists() and load_existing_incidents() == incidents:
        print("[保存スキップ] 記事内容に変化がないため incidents.json は更新しません")
        return False

    now = datetime.now(JST)
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
    return True


def save_excluded(excluded: list) -> bool:
    """対象外にした記事を保存する（変化がなければ何もしない）"""
    if load_excluded_incidents() == excluded and (EXCLUDED_PATH.exists() or not excluded):
        return False
    data = {
        "note": "判定ルールで対象外になった過去の記事です。incident.html には表示されません。",
        "totalCount": len(excluded),
        "excluded": excluded,
    }
    with open(EXCLUDED_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"[保存完了] {EXCLUDED_PATH} ({len(excluded)}件)")
    return True


def main():
    print("=" * 60)
    print("学校インシデント情報収集スクリプト")
    print(f"実行時刻: {datetime.now(JST).strftime('%Y-%m-%d %H:%M:%S JST')}")
    print("=" * 60)

    existing, excluded = reapply_rules(load_existing_incidents(), load_excluded_incidents())
    print(f"[既存データ] 表示対象 {len(existing)}件 / 対象外 {len(excluded)}件")

    new_items = fetch_rss_incidents() + fetch_google_news_incidents()
    print(f"[新規収集] {len(new_items)}件")

    merged = merge_incidents(existing, new_items)
    save_incidents(merged)
    save_excluded(excluded)

    print("=" * 60)
    print("収集完了")


if __name__ == "__main__":
    main()
