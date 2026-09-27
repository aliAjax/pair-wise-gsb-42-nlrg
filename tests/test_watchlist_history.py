import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import DomainError, FinancialCrimeService, ListReviewQueue, ScreeningArchive, WatchlistHistory  # noqa: E402


class WatchlistHistoryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "test.db"
        self.service = FinancialCrimeService(self.db)
        self.entity = self.service.create_entity("analyst1", "analyst", "organization", "远海贸易", ["远海"])
        self.customer = self.service.create_customer(
            "analyst1", "analyst", self.entity["id"], "C-001", "CN", risk_score=0.2
        )

    def tearDown(self):
        self.tmp.cleanup()

    def _entry_id(self):
        return self.service.add_or_update_watchlist(
            "sup1", "supervisor", "OFAC", "远海贸易", ["CN"]
        )["entry"]["id"]

    def test_correction_and_deactivation_keep_old_versions_with_effective_time(self):
        entry_id = self._entry_id()
        corrected = self.service.add_or_update_watchlist(
            "sup1", "supervisor", "OFAC", "远海贸易股份", ["CN", "HK"],
            entry_id=entry_id, expected_version=1
        )
        self.assertEqual(2, corrected["entry"]["version"])
        deactivated = self.service.add_or_update_watchlist(
            "sup1", "supervisor", "OFAC", "远海贸易股份", ["CN", "HK"], active=False,
            entry_id=entry_id, expected_version=2
        )
        self.assertEqual(3, deactivated["entry"]["version"])

        history = self.service.get_watchlist_history("sup1", "supervisor", entry_id)
        versions = history["versions"]
        self.assertEqual(["created", "corrected", "deactivated"], [v["change_type"] for v in versions])
        # 旧版内容仍保留：旧名称/旧国家/版本号都能回看
        self.assertEqual("远海贸易", versions[0]["name"])
        self.assertEqual(["CN"], json.loads(versions[0]["countries"]))
        self.assertEqual("远海贸易股份", versions[1]["name"])
        self.assertEqual(["CN", "HK"], json.loads(versions[1]["countries"]))
        self.assertEqual(0, versions[2]["active"])
        # 每个版本都有生效时间和操作人
        self.assertTrue(all(v["effective_at"] for v in versions))
        self.assertEqual({"sup1"}, {v["changed_by"] for v in versions})
        # 当前名单表内容已变更，但历史不受影响
        self.assertEqual("远海贸易股份", history["entry"]["name"])

    def test_screening_archives_hit_version_snapshot(self):
        entry_id = self._entry_id()
        ingested = self.service.ingest_transaction(
            "analyst1", "analyst", "T-001", self.customer["id"], 1000, "USD", "远海贸易", "CN"
        )
        archive = ingested["screen_archive"]
        self.assertIsNotNone(archive)
        self.assertEqual(entry_id, archive["watchlist_entry_id"])
        self.assertEqual(1, archive["entry_version"])
        self.assertEqual("远海贸易", archive["entry_name"])
        self.assertEqual("initial", archive["kind"])
        # 停用名单不影响已存档版本
        self.service.add_or_update_watchlist(
            "sup1", "supervisor", "OFAC", "远海贸易", ["CN"], active=False,
            entry_id=entry_id, expected_version=1
        )
        trace = self.service.get_transaction_trace("sup1", "supervisor", ingested["transaction"]["id"])
        self.assertEqual("远海贸易", trace["screening_archives"][0]["entry_name"])
        self.assertEqual(1, trace["screening_archives"][0]["entry_version"])

    def test_affected_transactions_auto_pending_once_per_version(self):
        entry_id = self._entry_id()
        first = self.service.ingest_transaction(
            "analyst1", "analyst", "T-101", self.customer["id"], 100, "USD", "远海贸易", "CN"
        )["transaction"]
        second = self.service.ingest_transaction(
            "analyst1", "analyst", "T-102", self.customer["id"], 200, "USD", "远海贸易", "CN"
        )["transaction"]

        changed = self.service.add_or_update_watchlist(
            "sup1", "supervisor", "OFAC", "远海贸易股份", ["CN"],
            entry_id=entry_id, expected_version=1
        )
        self.assertEqual(2, changed["enqueued_reviews"])
        pending = [r for r in self.service.state("sup1", "supervisor")["watchlist_reviews"]
                   if r["status"] == "pending"]
        self.assertEqual({first["id"], second["id"]}, {r["transaction_id"] for r in pending})
        self.assertTrue(all(r["to_version"] == 2 for r in pending))

        # 直接重复入队同一版本不会再生成记录
        with self.service.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            again = ListReviewQueue(conn).enqueue_affected(entry_id, 2, "corrected", "2026-01-01T00:00:00+00:00")
            conn.commit()
        self.assertEqual(0, again)

        # 再停用（新版本）每笔交易再生成一次
        deactivated = self.service.add_or_update_watchlist(
            "sup1", "supervisor", "OFAC", "远海贸易股份", ["CN"], active=False,
            entry_id=entry_id, expected_version=2
        )
        self.assertEqual(2, deactivated["enqueued_reviews"])
        all_reviews = self.service.state("sup1", "supervisor")["watchlist_reviews"]
        self.assertEqual(4, len(all_reviews))

    def test_review_records_handler_conclusion_and_rescreen(self):
        entry_id = self._entry_id()
        ingested = self.service.ingest_transaction(
            "analyst1", "analyst", "T-201", self.customer["id"], 100, "USD", "远海贸易", "CN"
        )
        self.service.add_or_update_watchlist(
            "sup1", "supervisor", "OFAC", "远海贸易", ["CN"], active=False,
            entry_id=entry_id, expected_version=1
        )
        review_id = [
            r["id"] for r in self.service.state("sup1", "supervisor")["watchlist_reviews"]
            if r["status"] == "pending"
        ][0]
        result = self.service.complete_list_review(
            "inv1", "investigator", review_id, "false_positive", "条目已停用，交易可放行"
        )
        self.assertEqual("reviewed", result["review"]["status"])
        self.assertEqual("false_positive", result["review"]["conclusion"])
        self.assertEqual("inv1", result["review"]["handled_by"])
        self.assertTrue(result["review"]["handled_at"])
        self.assertEqual("rescreen", result["rescreen"]["kind"])
        # 条目已停用：复筛无命中，存档记录停用版本快照
        self.assertEqual(0, result["rescreen"]["entry_active"])
        self.assertEqual(2, result["rescreen"]["entry_version"])
        self.assertIsNotNone(result["rescreen"]["watchlist_version_id"])
        # 同一版本不能重复复核
        with self.assertRaises(DomainError) as ctx:
            self.service.complete_list_review("inv1", "investigator", review_id, "confirmed")
        self.assertEqual(409, ctx.exception.status)

        # 仍命中当前版本时维持命中并产生复筛命中存档
        entry_id2 = self.service.add_or_update_watchlist(
            "sup1", "supervisor", "UN", "环球贸易", ["CN"]
        )["entry"]["id"]
        other = self.service.ingest_transaction(
            "analyst1", "analyst", "T-202", self.customer["id"], 100, "USD", "环球贸易", "CN"
        )
        self.service.add_or_update_watchlist(
            "sup1", "supervisor", "UN", "环球贸易", ["CN", "RU"],
            entry_id=entry_id2, expected_version=1
        )
        rid2 = [r["id"] for r in self.service.state("sup1", "supervisor")["watchlist_reviews"]
                if r["status"] == "pending" and r["transaction_id"] == other["transaction"]["id"]][0]
        confirmed = self.service.complete_list_review("inv1", "investigator", rid2, "confirmed")
        self.assertIsNotNone(confirmed["rescreen"]["watchlist_entry_id"])
        self.assertEqual(2, confirmed["rescreen"]["entry_version"])

    def test_escalated_review_creates_deduped_alert(self):
        entry_id = self._entry_id()
        ingested = self.service.ingest_transaction(
            "analyst1", "analyst", "T-301", self.customer["id"], 100, "USD", "远海贸易", "CN"
        )
        self.service.add_or_update_watchlist(
            "sup1", "supervisor", "OFAC", "远海贸易", ["CN", "RU"],
            entry_id=entry_id, expected_version=1
        )
        rid = [r["id"] for r in self.service.state("sup1", "supervisor")["watchlist_reviews"]
               if r["status"] == "pending"][0]
        first = self.service.complete_list_review("inv1", "investigator", rid, "escalated")
        self.assertIsNotNone(first["alert"])
        alerts_before = len(self.service.state("sup1", "supervisor")["alerts"])
        # 同版本不会再产生第二条线索（复核已关闭，路径本身也拒绝重复）
        with self.assertRaises(DomainError):
            self.service.complete_list_review("inv1", "investigator", rid, "escalated")
        self.assertEqual(alerts_before, len(self.service.state("sup1", "supervisor")["alerts"]))

    def test_case_detail_expands_list_versions_and_persists_after_reopen(self):
        entry_id = self._entry_id()
        ingested = self.service.ingest_transaction(
            "analyst1", "analyst", "T-401", self.customer["id"], 100, "USD", "远海贸易", "CN"
        )
        self.service.add_or_update_watchlist(
            "sup1", "supervisor", "OFAC", "远海贸易股份", ["CN"],
            entry_id=entry_id, expected_version=1
        )
        case = self.service.triage_alert(
            "inv1", "investigator", ingested["alert"]["id"], "escalate", "inv1", "CASE-401"
        )["case"]
        detail = self.service.get_case("inv1", "investigator", case["id"])
        self.assertEqual(1, len(detail["transactions"]))
        txn = detail["transactions"][0]
        self.assertEqual(1, txn["screening_archives"][0]["entry_version"])
        self.assertEqual("created", txn["screening_archives"][0]["version_change_type"])
        self.assertEqual(2, txn["watchlist_reviews"][0]["to_version"])
        self.assertEqual("pending", txn["watchlist_reviews"][0]["status"])

        # 重开服务（同库）仍可追查历史、存档与复核结论
        reopened = FinancialCrimeService(self.db)
        rid = [r["id"] for r in reopened.state("sup1", "supervisor")["watchlist_reviews"]
               if r["status"] == "pending"][0]
        reopened.complete_list_review("inv1", "investigator", rid, "confirmed", "维持制裁命中")
        detail2 = reopened.get_case("inv1", "investigator", case["id"])
        review = detail2["transactions"][0]["watchlist_reviews"][0]
        self.assertEqual("confirmed", review["conclusion"])
        self.assertEqual("inv1", review["handled_by"])
        self.assertEqual(2, len(detail2["transactions"][0]["screening_archives"]))
        self.assertEqual(2, len(reopened.get_watchlist_history("sup1", "supervisor", entry_id)["versions"]))

    def test_permissions_for_history_and_review(self):
        entry_id = self._entry_id()
        self.service.ingest_transaction(
            "analyst1", "analyst", "T-501", self.customer["id"], 100, "USD", "远海贸易", "CN"
        )
        with self.assertRaises(DomainError) as ctx:
            self.service.get_watchlist_history("analyst1", "analyst", entry_id)
        self.assertEqual(403, ctx.exception.status)
        with self.assertRaises(DomainError) as ctx2:
            self.service.add_or_update_watchlist("inv1", "investigator", "OFAC", "远海贸易", ["CN"])
        self.assertEqual(403, ctx2.exception.status)
        self.service.add_or_update_watchlist(
            "sup1", "supervisor", "OFAC", "远海贸易", ["CN"], active=False,
            entry_id=entry_id, expected_version=1
        )
        rid = [r["id"] for r in self.service.state("sup1", "supervisor")["watchlist_reviews"]
               if r["status"] == "pending"][0]
        # 审计员只读，不能复核；分析师也不能
        with self.assertRaises(DomainError):
            self.service.complete_list_review("aud1", "auditor", rid, "confirmed")
        with self.assertRaises(DomainError):
            self.service.complete_list_review("analyst1", "analyst", rid, "confirmed")


if __name__ == "__main__":
    unittest.main()
