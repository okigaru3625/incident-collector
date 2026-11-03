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


def gn(title, date="2026年10月29日", publisher="Yahoo!ニュース", category=None):
    return item(title, date, source=f"Googleニュース（{publisher}）", category=category)


class TestGoogleNewsDuplicates(unittest.TestCase):
    """2026-11-03 の初回実行で入った重複の例"""

    def assert_dup(self, a, b):
        self.assertIsNotNone(c.duplicate_reason(a, b), f"{a['title']} / {b['title']}")

    def test_chiba_seven_schools(self):
        chibatere = gn("県立高校7校でメールアカウント不正利用 約48万件の迷惑メール送信（チバテレ）", "2026年10月28日")
        lab = gn("千葉県立高校7校のメールアカウントに不正アクセス 迷惑メール48万5,446件を送信、個人情報の漏えいは認められず",
                 publisher="合同会社ロケットボーイズ")
        board = gn("学校メールに不正アクセス 大量送信を停止 千葉県教委（千葉日報オンライン）")
        mainichi = gn("県立高の教諭と生徒のメールアカウントが不正アクセス被害 千葉（毎日新聞）", "2026年10月30日")
        kept, removed = c.rededup_google_news([chibatere, lab, board, mainichi])
        self.assertEqual(len(kept), 1)
        self.assertEqual(len(removed), 3)

    def test_kyushu_alumni(self):
        a = gn("九州大学校友会の”メール配信サービス”に不正アクセス 最大9999件の氏名とアドレスが流出した可能性（RKB毎日放送）", "2026年10月28日")
        b = gn("九州大学同窓生のメール配信サービスに不正アクセス、個人情報漏えい…最大９９９９件登録か（読売新聞オンライン）")
        d = gn("九州大学 - 九州大、不正アクセス受け情報流出 校友会メールサービス - 写真・画像(1/1)", publisher="西日本新聞me")
        kept, removed = c.rededup_google_news([a, b, d])
        self.assertEqual(len(kept), 1)

    def test_saga(self):
        self.assert_dup(
            gn("佐賀大学、ランサムウェアによるサイバー攻撃で約8万人の個人情報漏洩のおそれ", "2026年10月31日"),
            gn("佐賀大学 ランサムウェア被害で8万人分の個人情報流出か", "2026年10月30日", publisher="NHKニュース"))

    def test_kushiro_different_wording(self):
        self.assert_dup(
            gn("釧路市の学習用端末の委託先がランサムウェア被害、児童生徒・教職員のアカウント情報が流出の恐れ", "2026年11月2日"),
            gn("釧路市が市立小中学校の学習用端末の管理運用を委託しているポータスにランサムウェア攻撃", "2026年10月28日"))

    def test_different_schools_are_not_duplicates(self):
        self.assertIsNone(c.duplicate_reason(
            gn("生徒82人分の志望校や受験先など進路情報が教室に誤掲示、誤配布も…北見柏陽高校", "2026年10月30日"),
            gn("生徒の受験予定大学などを教室に約2か月間掲示…北海道夕張高校が「個人情報流出」としてお詫び", "2026年10月31日")))

    def test_specialist_source_is_kept(self):
        sn = item("小学校で児童の個人情報含む書類を紛失 - 釧路市", "2026年10月28日")
        sn["id"] = "sn"
        g = gn("釧路市の小学校で児童の個人情報を含む書類を紛失", "2026年10月29日")
        g["id"] = "gn"
        kept, removed = c.rededup_google_news([g, sn])
        self.assertEqual([k["id"] for k in kept], ["sn"])

    def test_new_item_matching_absorbed_duplicate_is_skipped(self):
        absorbed = gn("九州大学同窓生のメール配信サービスに不正アクセス、最大９９９９件登録か")
        new = gn("九州大、不正アクセス受け情報流出 校友会メールサービス", publisher="西日本新聞me")
        new["id"] = "new"
        self.assertEqual(c.merge_incidents([], [new], [absorbed]), [])


class TestGoogleNewsTitle(unittest.TestCase):
    def test_strip_trailing_publisher(self):
        self.assertEqual(c.clean_google_news_title("最大９９９９件登録か（読売新聞オンライン）"), "最大９９９９件登録か")

    def test_strip_pipe_and_page(self):
        self.assertEqual(
            c.clean_google_news_title("九州大学 - 九州大、不正アクセス受け情報流出 校友会メールサービス - 写真・画像(1/1)"),
            "九州大、不正アクセス受け情報流出 校友会メールサービス")
        self.assertEqual(c.clean_google_news_title("児童の姓など漏えいのおそれも | RCC NEWS | 広島ニュース"), "児童の姓など漏えいのおそれも")

    def test_extract_orgs(self):
        self.assertIn("九州大", c.extract_orgs("九州大学校友会のメール配信サービスに不正アクセス"))
        self.assertIn("千葉県教委", c.extract_orgs("学校メールに不正アクセス 千葉県教委"))
        self.assertIn("茨城県教委", c.extract_orgs("茨城県の学習システム 1390件漏えいか 県教委"))
        self.assertIn("同志社", c.extract_orgs("学校法人同志社が記者会見"))
        self.assertNotIn("最大", c.extract_orgs("最大9999件の氏名が流出"))

    def test_extract_places(self):
        self.assertEqual(c.extract_places("不正アクセス被害 千葉"), {"千葉県"})
        self.assertIn("釧路市", c.extract_places("釧路市が市立小中学校の端末"))

    def test_number_keys(self):
        self.assertTrue(c.extract_number_keys("迷惑メール48万5,446件を送信") & c.extract_number_keys("約48万件の迷惑メール"))
        self.assertIn("9999件", c.extract_number_keys("最大９９９９件登録か"))


class TestOverseasAndNonReport(unittest.TestCase):
    def reason(self, title, publisher=""):
        return c.judge(title, "", "news", publisher)

    def test_korea(self):
        self.assertIsNotNone(self.reason("韓国・国立釜慶大学の学費システムがハッキング、学生5,106人の個人情報流出", "BigGo ファイナンス"))
        self.assertIsNotNone(self.reason("金融機関から教育、飲食まで被害拡大 韓国でも相次ぐ個人情報流出", "朝日新聞"))

    def test_hangul_publisher(self):
        self.assertIsNotNone(self.reason("国立釜慶大、授業料収納システムに不正アクセス…5108人の個人情報流出", "조선일보"))

    def test_vietnam_publisher(self):
        self.assertIsNotNone(self.reason("保険代理店や学校職員になりすまして金銭をだまし取る詐欺行為に関する警告です。", "Vietnam.vn"))

    def test_access_from_abroad_is_domestic(self):
        self.assertIsNone(c.judge("学生の複数アカウントに海外から不正アクセス - 千葉大", "", "security"))

    def test_chugoku_region_is_domestic(self):
        self.assertIsNone(c.exclusion_reason("児童の個人情報を紛失 RCC中国放送"))

    def test_togetter(self):
        self.assertIsNotNone(self.reason("学校法人同志社が記者会見、遺族の個人情報までうっかり漏洩", "Togetter"))

    def test_preventive(self):
        self.assertIsNotNone(self.reason("不正アクセスに備え予防的メンテナンスで小学校も対応追われる", "NHKニュース"))

    def test_expert_commentary(self):
        self.assertIsNotNone(self.reason("顔写真流出で…大阪大学・猪俣敦夫教授が指摘する「なりすましログイン」の恐怖"))

    def test_what_is(self):
        self.assertIsNotNone(self.reason("学校の個人情報漏えいとは？"))

    def test_real_report_is_kept(self):
        self.assertIsNone(self.reason("修学旅行中に県立高校教員がリュックサック紛失 生徒226人分の個人情報記載"))
        self.assertIsNone(self.reason("十文字学園女子大学のシステムに先月サイバー攻撃か 個人情報漏えいの可能性も", "TBS NEWS DIG"))


class TestReapply(unittest.TestCase):
    def test_duplicate_is_not_restored(self):
        dup = gn("佐賀大学 ランサムウェア被害で8万人分の個人情報流出か")
        dup["excludedReason"] = c.DUPLICATE_REASON_PREFIX + "テスト"
        kept, removed = c.reapply_rules([], [dup])
        self.assertEqual(kept, [])
        self.assertEqual(len(removed), 1)


if __name__ == "__main__":
    unittest.main()
