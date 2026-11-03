"""判定・分類・重複ルールのテスト（ネットワーク不要）

実行方法: python -m unittest discover -s tests
"""
import sys
import types
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
try:
    import feedparser  # noqa: F401
except ImportError:  # テストでは通信しないので、未インストールでも動くようにする
    sys.modules["feedparser"] = types.ModuleType("feedparser")

import collect_incidents as c  # noqa: E402


def item(title, date="2026年10月1日", source="Security NEXT", category=None):
    cat = category or c.classify_incident(title, "")["category"]
    return {"id": title, "title": title, "date": date, "source": source, "category": cat}


class TestJudge(unittest.TestCase):
    def test_school_incident_is_target(self):
        self.assertTrue(c.is_target("小学校で児童の個人情報含むUSBメモリを紛失 - 柏市", "", "security"))

    def test_machine_learning_is_not_education(self):
        self.assertFalse(c.is_target("「MLflow」に深刻な脆弱性", "機械学習プラットフォームに情報流出のおそれ", "security"))

    def test_hospital_is_excluded(self):
        self.assertFalse(c.is_target("患者情報含むUSBメモリを紛失 - 関西医科大病院", "", "security"))

    def test_seminar_is_excluded(self):
        self.assertFalse(c.is_target("学校情報セキュリティのセミナーを開催", "", "education"))

    def test_edu_only_is_not_enough(self):
        # 以前は教育の言葉だけで通っていた
        self.assertFalse(c.is_target("愛媛県とマイナビが協定締結 高校生の探究学習", "", "education"))

    def test_strong_word_overrides_soft_exclusion(self):
        self.assertTrue(c.is_target("公開講座の開催案内でメール誤送信 - 島根県立大", "", "security"))

    def test_university_short_name(self):
        self.assertTrue(c.is_education_related("事務用NASがランサム被害 - 佐賀大", ""))


class TestClassify(unittest.TestCase):
    def cat(self, title):
        return c.classify_incident(title, "")["category"]

    def test_ransom(self):
        self.assertEqual(self.cat("事務用NASがランサム被害、通常業務は再開 - 佐賀大"), "ランサムウェア")

    def test_investigating_is_not_report(self):
        self.assertEqual(self.cat("摂南大のサイトが一部改ざん、原因を調査中"), "不正アクセス")

    def test_support_scam(self):
        self.assertEqual(self.cat("教員がサポート詐欺被害 - 那覇市"), "フィッシング")

    def test_viewable(self):
        self.assertEqual(self.cat("申込フォームで個人情報が閲覧可能に - 群馬県"), "誤操作・誤公開")


class TestDuplicate(unittest.TestCase):
    def test_same_title_is_duplicate(self):
        a = item("小学校で児童の個人情報含む書類を紛失 - 名古屋市")
        b = item("小学校で児童の個人情報含む書類を紛失 - 名古屋市", "2026年10月3日")
        self.assertIsNotNone(c.duplicate_reason(b, a))

    def test_different_org_is_not_duplicate(self):
        a = item("小学校で成績含むUSBメモリを紛失 - 都城市")
        b = item("小学校で成績含むUSBメモリを紛失 - 柏市")
        self.assertIsNone(c.duplicate_reason(b, a))

    def test_older_than_30_days_is_not_duplicate(self):
        a = item("県立高で生徒の保健調査票が所在不明 - 新潟県", "2026年4月28日")
        b = item("県立高で生徒の保健調査票が所在不明 - 新潟県", "2026年10月1日")
        self.assertIsNone(c.duplicate_reason(b, a))

    def test_google_news_same_case(self):
        a = item("小学校で児童の個人情報含む絵画作品を紛失 - 大阪市")
        b = item("大阪市の小学校、児童の絵画作品を紛失 個人情報記載 - 毎日新聞",
                 "2026年10月2日", source="Googleニュース（毎日新聞）")
        self.assertIsNotNone(c.duplicate_reason(b, a))

    def test_merge_prefers_specialist_source(self):
        gn = item("大阪市の小学校、児童の絵画作品を紛失 個人情報記載 - 毎日新聞",
                  source="Googleニュース（毎日新聞）")
        gn["id"] = "gn"
        sn = item("小学校で児童の個人情報含む絵画作品を紛失 - 大阪市")
        sn["id"] = "sn"
        merged = c.merge_incidents([], [gn, sn])
        self.assertEqual([m["id"] for m in merged], ["sn"])


class TestGoogleNews(unittest.TestCase):
    def test_split_title(self):
        self.assertEqual(c.split_google_news_title("見出し - 朝日新聞", "朝日新聞"), ("見出し", "朝日新聞"))

    def test_url(self):
        self.assertIn("ceid=JP:ja", c.google_news_url("教育委員会 誤送信"))


if __name__ == "__main__":
    unittest.main()
