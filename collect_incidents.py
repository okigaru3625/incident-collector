#!/usr/bin/env python3
"""
学校・教育現場の情報インシデント収集スクリプト
各種RSSフィード（Security NEXT・教育系メディア・Googleニュース検索）から
教育関連のインシデント情報を収集し、JSON形式でウェブサイト用データファイルに出力する。
"""

import json
import re
import hashlib
import unicodedata
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
# 事故の報道ではない記事（予防・解説・まとめなど）。明確な事故語があっても除外する
NON_REPORT_KEYWORDS = [
    "予防的", "解説", "コラム", "まとめ", "教授が指摘", "の恐怖", "衆院", "参院",
    "文科委", "国会",
]
# 「〇〇とは？」のような解説記事（「…とは別の」などは除かない）
NON_REPORT_PATTERN = re.compile(r"とは(?:[？?！!」』]|$)")

# 海外の事件（タイトルで判定）
OVERSEAS_KEYWORDS = ["韓国", "台湾", "米国", "アメリカ", "ベトナム"]
# 「海外から不正アクセス」は国内の事件なので除かない
OVERSEAS_PATTERN = re.compile(r"海外(?!から|の(?:IP|ＩＰ|サーバ|第三者))")
# 「中国地方」「中国放送」などの国内の言い方は除く
CHINA_PATTERN = re.compile(r"中国(?!地方|放送|新聞|電力|銀行|四国|・四国|自動車道)")
HANGUL_PATTERN = re.compile(r"[ᄀ-ᇿ㄰-㆏가-힣]")
# 海外の媒体（Googleニュースの媒体名で判定）
OVERSEAS_PUBLISHERS = [
    "Vietnam.vn", "BigGo", "中央日報", "朝鮮日報", "東亜日報", "ハンギョレ",
    "聯合ニュース", "Record China", "レコードチャイナ", "人民網", "新華社",
]
FOREIGN_DOMAIN_PATTERN = re.compile(r"\.(vn|kr|cn|tw)\b", re.IGNORECASE)
# まとめサイトなど、事故の報道ではない媒体
EXCLUDED_PUBLISHERS = ["Togetter", "まとめ", "はてな匿名ダイアリー", "5ch", "2ch"]

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
    {"keywords": ["不正アクセス", "サイバー攻撃", "踏み台", "侵害", "改ざん", "不正ログイン", "第三者がアクセス", "スパム", "不正利用"], "category": "不正アクセス", "color": "orange"},
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
    if org and EDU_ORG_PATTERN.search(org):
        return True
    # 「九州大、…」のように見出しの中に学校名がある場合
    return any(_school_in_run(run) for run in JP_RUN.findall(unicodedata.normalize("NFKC", title)))


def is_incident_related(text: str) -> bool:
    """インシデント関連の語を含むかどうか"""
    return any(kw in text for kw in INCIDENT_KEYWORDS)


def overseas_reason(title: str, publisher: str = ""):
    """海外の事件・海外サイトなら理由を返す"""
    for kw in OVERSEAS_KEYWORDS:
        if kw in title:
            return f"海外の事件「{kw}」"
    if OVERSEAS_PATTERN.search(title):
        return "海外の事件「海外」"
    if CHINA_PATTERN.search(title):
        return "海外の事件「中国」"
    if HANGUL_PATTERN.search(title):
        return "海外の事件（ハングル）"
    if publisher:
        if HANGUL_PATTERN.search(publisher) or FOREIGN_DOMAIN_PATTERN.search(publisher):
            return f"海外の媒体「{publisher}」"
        for name in OVERSEAS_PUBLISHERS:
            if name.lower() in publisher.lower():
                return f"海外の媒体「{publisher}」"
    return None


def exclusion_reason(title: str, publisher: str = ""):
    """タイトル・媒体名が除外対象なら理由を返す（対象なら None）"""
    for name in EXCLUDED_PUBLISHERS:
        if publisher and name.lower() in publisher.lower():
            return f"除外媒体「{publisher}」"
    reason = overseas_reason(title, publisher)
    if reason:
        return reason
    for kw in HARD_EXCLUDE_KEYWORDS:
        if kw in title:
            return f"除外語「{kw}」"
    for kw in NON_REPORT_KEYWORDS:
        if kw in title:
            return f"事故の報道ではない「{kw}」"
    if NON_REPORT_PATTERN.search(title):
        return "事故の報道ではない「とは」"
    if not any(kw in title for kw in STRONG_INCIDENT_KEYWORDS):
        for kw in SOFT_EXCLUDE_KEYWORDS:
            if kw in title:
                return f"除外語「{kw}」"
    return None


def judge(title: str, description: str, source_type: str, publisher: str = ""):
    """対象なら None、対象外なら理由（文字列）を返す"""
    if not is_education_related(title, description):
        return "教育関連の語なし"
    # 専門メディアは説明文まで、それ以外はタイトルだけで事故語を探す
    incident_text = title + " " + description if source_type == "security" else title
    if not is_incident_related(incident_text):
        return "事故関連の語なし"
    return exclusion_reason(title, publisher)


def is_target(title: str, description: str, source_type: str, publisher: str = "") -> bool:
    return judge(title, description, source_type, publisher) is None


def publisher_of(source_name: str) -> str:
    """「Googleニュース（媒体名）」から媒体名を取り出す"""
    m = re.match(re.escape(GOOGLE_NEWS_SOURCE_PREFIX) + r"（(.+)）$", source_name or "")
    return m.group(1) if m else ""


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
                if not is_target(clean_google_news_title(title), "", "news", publisher):
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
ENTITY_DUP_WINDOW_DAYS = 14   # Googleニュースの「組織名・地名＋分類」一致で比べる日数
NUMBER_DUP_WINDOW_DAYS = 7    # Googleニュース同士で「人数・件数＋分類」一致で比べる日数
SIMILAR_THRESHOLD = 0.75      # 見出しの3文字一致率（これ以上なら重複）
SAME_ORG_THRESHOLD = 0.4      # 同じ組織・同じ分類なら、この一致率で重複
ENTITY_THRESHOLD = 0.2        # Googleニュース由来で地名が共通なら、この一致率で重複
MIN_EXACT_NUMBER = 10         # 人数・件数の一致に使う最小の数（「1人」「2件」などは使わない）

ORG_SUFFIX_PATTERN = re.compile(
    r"(都|道|府|県|市|区|町|村|大|大学|大学院|高|高専|学園|学院|学校|校|園|会社|グループ|協議会|組合|機構|学部|病院|センター)$"
)

PREFECTURES = [
    "北海道", "青森県", "岩手県", "宮城県", "秋田県", "山形県", "福島県", "茨城県", "栃木県",
    "群馬県", "埼玉県", "千葉県", "東京都", "神奈川県", "新潟県", "富山県", "石川県", "福井県",
    "山梨県", "長野県", "岐阜県", "静岡県", "愛知県", "三重県", "滋賀県", "京都府", "大阪府",
    "兵庫県", "奈良県", "和歌山県", "鳥取県", "島根県", "岡山県", "広島県", "山口県", "徳島県",
    "香川県", "愛媛県", "高知県", "福岡県", "佐賀県", "長崎県", "熊本県", "大分県", "宮崎県",
    "鹿児島県", "沖縄県",
]
# 「千葉」のように県名だけが単独で書かれた場合の対応表
PREFECTURE_BASES = {p[:-1] if p != "北海道" else p: p for p in PREFECTURES}

# 漢字・カタカナの連なり（組織名・地名はこの中から探す）
JP_RUN = re.compile(r"[一-龥々〆ヶァ-ヴー]+")
# 学校名の末尾（短いものを優先して取り出す）
SCHOOL_SUFFIXES = ["大学院", "大学", "高等専門学校", "高等学校", "高専", "高校", "中学校", "小学校", "学園", "学院", "大"]
# 「大」で終わっても学校名ではない言葉
NOT_SCHOOL_WORDS = ("最大", "拡大", "増大", "重大", "巨大", "膨大", "甚大", "莫大", "過大", "多大", "絶大", "特大", "大量", "強大", "盛大")
# 学校名の前に付いても、それだけでは学校を特定できない言葉
GENERIC_SCHOOL_PREFIXES = {
    "", "小", "中", "小中", "中高", "県内", "市内", "府内", "都内", "町内", "村内", "区内", "道内",
    "国内", "全国", "各", "同", "本", "他", "両", "私立", "公立", "国立", "県立", "市立", "府立",
    "都立", "道立", "町立", "村立", "区立", "附属", "付属", "女子", "短期", "短期大", "大",
}
MUNICIPALITY_PATTERN = re.compile(r"([一-龥々ヶ]{1,5}?)(市|区|町|村)")
NOT_PLACE_WORDS = ("地区", "学区", "校区", "市区", "都市", "同市", "本市", "各市", "全市", "当市", "同町", "同村", "同区", "市町", "町村")
BOARD_PATTERN = re.compile(r"(県|府|都|道|市|区|町|村)教委")
SCHOOL_CORP_PATTERN = re.compile(r"学校法人([一-龥々ヶァ-ヴー]+)")

NUMBER_PATTERN = re.compile(r"(約|最大|およそ)?(\d[\d,]*)(?:(万)(\d[\d,]*)?)?(件|人|名|世帯)")


def clean_google_news_title(title: str) -> str:
    """Googleニュースの見出しから、媒体名・ページ名などの付け足しを外す

    例: 「…最大９９９９件登録か（読売新聞オンライン）」→「…最大９９９９件登録か」
        「九州大学 - 九州大、不正アクセス… - 写真・画像(1/1)」→「九州大、不正アクセス…」
        「…漏えいのおそれも | RCC NEWS | 広島ニュース」→「…漏えいのおそれも」
    """
    t = re.split(r"\s*[|｜]\s*", title.strip())[0]
    parts = [p.strip() for p in re.split(r"\s+-\s+", t) if p.strip()]
    if parts:
        t = max(parts, key=len)
    # 末尾の括弧書き（媒体名・ページ番号など）を外す
    while True:
        m = re.search(r"\s*[（(][^（）()]{1,25}[）)]\s*$", t)
        if not m or m.start() == 0:
            break
        t = t[: m.start()]
    return t.strip()


def strip_source_suffix(item: dict) -> str:
    """比較用の見出し（Googleニュース由来は媒体名などを除く）"""
    title = item.get("title", "")
    if item.get("source", "").startswith(GOOGLE_NEWS_SOURCE_PREFIX):
        title = clean_google_news_title(title)
    return title


def extract_org(title: str):
    """「… - 厚木市」形式の末尾から組織名を取り出す（取れなければ None）"""
    if " - " not in title:
        return None
    tail = title.rsplit(" - ", 1)[1].strip()
    if 0 < len(tail) <= 20 and "、" not in tail and ORG_SUFFIX_PATTERN.search(tail):
        return tail
    return None


def normalize_org(name: str) -> str:
    """「九州大学」「九州大」などの表記ゆれをそろえる"""
    return (name.replace("大学院", "大").replace("大学", "大")
            .replace("高等専門学校", "高専").replace("高等学校", "高校"))


def _school_in_run(run: str):
    """漢字の連なりから学校名を1つ取り出す（なければ None）"""
    best = None
    for suffix in SCHOOL_SUFFIXES:
        for m in re.finditer(re.escape(suffix), run):
            name = run[: m.end()]
            prefix = run[: m.start()]
            if prefix in GENERIC_SCHOOL_PREFIXES or name.endswith(NOT_SCHOOL_WORDS):
                continue
            if suffix == "大" and len(prefix) < 2:
                continue
            if best is None or len(name) < len(best):
                best = name
            break
    return best


def extract_places(title: str) -> set:
    """見出しの中の都道府県・市区町村名"""
    found = set()
    text = unicodedata.normalize("NFKC", title)
    for run in JP_RUN.findall(text):
        if run in PREFECTURE_BASES:          # 「… 千葉」のように県名だけの場合
            found.add(PREFECTURE_BASES[run])
            continue
        for pref in PREFECTURES:
            if run.startswith(pref):
                found.add(pref)
                break
        else:
            m = MUNICIPALITY_PATTERN.match(run)
            if m and not m.group(0).endswith(NOT_PLACE_WORDS) and len(m.group(1)) >= 1:
                if m.group(0) not in NOT_PLACE_WORDS:
                    found.add(m.group(0))
    return found


def extract_prefectures(title: str) -> set:
    return {p for p in extract_places(title) if p in PREFECTURES}


def extract_orgs(title: str) -> set:
    """見出しの中の組織名（大学・高校・中学校・小学校・学園・教委・学校法人など）"""
    text = unicodedata.normalize("NFKC", title)
    found = set()
    org = extract_org(text)
    if org:
        found.add(normalize_org(org))
    for run in JP_RUN.findall(text):
        name = _school_in_run(run)
        if name:
            found.add(normalize_org(name))
    for m in SCHOOL_CORP_PATTERN.finditer(text):
        found.add(m.group(1))
    if BOARD_PATTERN.search(text):
        # 「千葉県教委」「県教委」→ 見出しの都道府県・市町村と組み合わせて「千葉県教委」に
        for m in BOARD_PATTERN.finditer(text):
            head = text[: m.start() + 1]
            places = [p for p in extract_places(head) if p.endswith(m.group(1))]
            if not places:
                places = [p for p in extract_places(text) if p.endswith(m.group(1))]
            for p in places:
                found.add(p + "教委")
    return found


def extract_entities(title: str) -> set:
    """見出しに含まれる組織名・地名の候補"""
    return extract_orgs(title) | extract_places(title)


def extract_number_keys(title: str) -> set:
    """人数・件数を比較用の文字列にする（例: 48万5,446件 → 485446件 と ~48万件）"""
    text = unicodedata.normalize("NFKC", title)
    keys = set()
    for m in NUMBER_PATTERN.finditer(text):
        approx, head, man, tail, unit = m.groups()
        value = int(head.replace(",", ""))
        if man:
            value = value * 10000 + (int(tail.replace(",", "")) if tail else 0)
        if value >= MIN_EXACT_NUMBER:
            keys.add(f"{value}{unit}")
        if value >= 10000:
            keys.add(f"約{value // 10000}万{unit}")
    return keys


def normalize_title(title: str) -> str:
    """タイトルを正規化して比較用文字列を生成する（記号・空白除去）"""
    t = unicodedata.normalize("NFKC", title)
    t = re.sub(r"[\s　・･・。、,.\-\|｜/／「」【】『』（）()\[\]\{\}…”“\"']+", "", t)
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


def _join(values) -> str:
    return "・".join(sorted(values))


def duplicate_reason(new: dict, old: dict):
    """new が old と同じ事件なら理由を返す（別の事件なら None）"""
    gap = days_apart(new, old)
    if gap is None or gap > DUP_WINDOW_DAYS:
        return None
    t_new, t_old = strip_source_suffix(new), strip_source_suffix(old)
    org_new, org_old = extract_org(t_new), extract_org(t_old)
    if org_new and org_old and org_new != org_old:
        return None  # 組織が違えば別の事件（Security NEXT形式どうし）
    sim = title_similarity(t_new, t_old)
    if sim >= SIMILAR_THRESHOLD:
        return f"見出し一致率{sim:.2f}"
    same_category = new.get("category") == old.get("category")
    if org_new and org_new == org_old and same_category and sim >= SAME_ORG_THRESHOLD:
        return f"同じ組織「{org_new}」・同じ分類・一致率{sim:.2f}"

    involves_gn = is_google_news(new) or is_google_news(old)
    if not involves_gn:
        return None
    both_gn = is_google_news(new) and is_google_news(old)

    orgs = extract_orgs(t_new) & extract_orgs(t_old)
    prefs = extract_prefectures(t_new) & extract_prefectures(t_old)
    places = extract_places(t_new) & extract_places(t_old)
    numbers = extract_number_keys(t_new) & extract_number_keys(t_old)

    # 人数・件数が同じで、組織名か都道府県（市町村）が同じ
    if numbers and (orgs or prefs or places):
        return f"人数・件数「{_join(numbers)}」と「{_join(orgs or prefs or places)}」が共通"
    if gap <= ENTITY_DUP_WINDOW_DAYS and both_gn:
        # Googleニュース同士：学校名・市町村名が同じなら分類が違っても重複。
        # 都道府県だけが同じ場合は、別の事件を混ぜないよう同じ分類のときに限る。
        municipalities = places - prefs
        if orgs or municipalities:
            return f"Googleニュース同士で組織名「{_join(orgs | municipalities)}」が共通"
        if prefs and same_category:
            return f"Googleニュース同士で「{_join(prefs)}」・同じ分類"
    if gap <= ENTITY_DUP_WINDOW_DAYS and orgs and same_category:
        return f"組織名「{_join(orgs)}」・同じ分類"
    if gap <= ENTITY_DUP_WINDOW_DAYS and same_category and places and sim >= ENTITY_THRESHOLD:
        return f"地名「{_join(places)}」・同じ分類・一致率{sim:.2f}"
    if both_gn and gap <= NUMBER_DUP_WINDOW_DAYS and same_category and numbers:
        return f"Googleニュース同士で人数・件数「{_join(numbers)}」・同じ分類"
    return None


def date_sort_key(item: dict):
    d = to_date(item.get("date", ""))
    return (d.year, d.month, d.day) if d else (0, 0, 0)


def find_duplicate(item: dict, candidates: list):
    """candidates の中で item と同じ事件の記事と理由を返す（なければ None）"""
    for old in candidates:
        reason = duplicate_reason(item, old)
        if reason:
            return old, reason
    return None


def merge_incidents(existing: list, new_items: list, duplicates: list = None) -> list:
    """既存データと新規データをマージして重複を除去する（ID＋直近30日の見出し・組織チェック）

    duplicates: 重複として退避済みの記事。同じ事件の別の報道を見つける手がかりとして比較にも使う
    """
    existing_ids = {item["id"] for item in existing}
    merged = list(existing)
    absorbed = list(duplicates or [])
    existing_ids.update(item["id"] for item in absorbed)

    # 専門メディアを先に処理し、同じ事件ならGoogleニュース側を捨てる
    ordered = sorted(new_items, key=is_google_news)

    added = 0
    skipped_similar = 0
    for item in ordered:
        if item["id"] in existing_ids:
            continue
        dup_of = find_duplicate(item, merged) or find_duplicate(item, absorbed)
        if dup_of:
            absorbed.append(item)
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

DUPLICATE_REASON_PREFIX = "重複："
# 既存のGoogleニュース由来の記事に、重複判定を一度だけかけ直すための版番号。
# excluded.json に記録し、同じ版では二度と実行しない。
GOOGLE_NEWS_REDEDUP_VERSION = 1


def reapply_rules(existing: list, excluded: list):
    """既存データに現在の判定・分類ルールを当て直す。

    戻り値: (表示する記事, 退避する記事)
    退避済みの記事も毎回判定し直し、対象に戻ったものは表示側へ復帰させる。
    ただし「重複」で退避した記事は、戻さずにそのまま残す。
    """
    kept, removed = [], []
    for item in existing + excluded:
        if item.get("excludedReason", "").startswith(DUPLICATE_REASON_PREFIX):
            removed.append(item)
            continue
        base = {k: v for k, v in item.items() if k != "excludedReason"}
        desc = base.get("description", "")
        source = base.get("source", "")
        title = strip_source_suffix(base)
        reason = judge(title, desc, source_type_of(source), publisher_of(source))
        if reason:
            base["excludedReason"] = reason
            removed.append(base)
        else:
            base.update(classify_incident(title, desc))
            kept.append(base)
    kept.sort(key=date_sort_key, reverse=True)
    removed.sort(key=date_sort_key, reverse=True)
    return kept, removed


def rededup_google_news(incidents: list):
    """既存のGoogleニュース由来の記事に重複判定をかけ直す。

    専門メディアの記事はすべて残し、Googleニュース由来は古い順に見て、
    すでに残した記事と同じ事件なら退避する。
    戻り値: (残す記事, 重複として退避する記事)
    """
    kept = [i for i in incidents if not is_google_news(i)]
    gn_items = sorted((i for i in incidents if is_google_news(i)), key=date_sort_key)
    removed = []
    for item in gn_items:
        # 残した記事に加え、すでに重複とした記事（同じ事件の別の報道）とも比べる
        dup = find_duplicate(item, kept) or find_duplicate(item, removed)
        if dup:
            moved = dict(item)
            moved["excludedReason"] = f"{DUPLICATE_REASON_PREFIX}{dup[0]['title'][:60]}（{dup[1]}）"
            removed.append(moved)
            print(f"  [重複を退避] {item['title'][:40]} ≒ {dup[0]['title'][:40]}（{dup[1]}）")
        else:
            kept.append(item)
    kept.sort(key=date_sort_key, reverse=True)
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


def load_excluded_meta() -> dict:
    """excluded.json の付帯情報（一度だけの処理を済ませたかどうかなど）"""
    if EXCLUDED_PATH.exists():
        with open(EXCLUDED_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        return {k: v for k, v in data.items() if k not in ("note", "totalCount", "excluded")}
    return {}


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


def save_excluded(excluded: list, meta: dict = None) -> bool:
    """対象外にした記事を保存する（変化がなければ何もしない）"""
    meta = meta or {}
    if (load_excluded_incidents() == excluded and load_excluded_meta() == meta
            and (EXCLUDED_PATH.exists() or not excluded)):
        return False
    data = {
        "note": "判定ルールで対象外になった過去の記事です。incident.html には表示されません。",
        **meta,
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

    meta = load_excluded_meta()
    existing, excluded = reapply_rules(load_existing_incidents(), load_excluded_incidents())
    if meta.get("googleNewsRededupVersion", 0) < GOOGLE_NEWS_REDEDUP_VERSION:
        print("[一度だけの処理] 既存のGoogleニュース由来の記事に重複判定をかけ直します")
        existing, dups = rededup_google_news(existing)
        excluded = sorted(excluded + dups, key=date_sort_key, reverse=True)
        meta["googleNewsRededupVersion"] = GOOGLE_NEWS_REDEDUP_VERSION
        print(f"  → 重複として {len(dups)}件を excluded.json に移しました")
    print(f"[既存データ] 表示対象 {len(existing)}件 / 対象外 {len(excluded)}件")

    new_items = fetch_rss_incidents() + fetch_google_news_incidents()
    print(f"[新規収集] {len(new_items)}件")

    duplicates = [i for i in excluded if i.get("excludedReason", "").startswith(DUPLICATE_REASON_PREFIX)]
    merged = merge_incidents(existing, new_items, duplicates)
    save_incidents(merged)
    save_excluded(excluded, meta)

    print("=" * 60)
    print("収集完了")


if __name__ == "__main__":
    main()
