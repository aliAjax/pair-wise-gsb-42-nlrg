import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import DomainError, FinancialCrimeService  # noqa: E402


class WatchlistHistoryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.service = FinancialCrimeService(Path(self.tmp.name) / "test.db")
        self.entity = self.service.create_entity("a1", "analyst", "organization", "远海贸易", [])
        self.customer = self.service.create_customer("a1", "analyst", self.entity["id"], "C-1", "CN", risk_score=0.2)

    def tearDown(self):
        self.tmp.cleanup()

    def _hit_txn(self, ref="T-1"):
        return self.service.ingest_transaction("a1", "analyst", ref, self.customer["id"], 1000, "USD", "远海贸易", "CN")

    def test_correction_and_deactivation_keep_versions_with_effective_time(self):
        w = self.service.add_or_update_watchlist("s1", "supervisor", "OFAC", "远海贸易", ["CN"])
        corrected = self.service.add_or_update_watchlist(
            "s1", "supervisor", "OFAC", "远海贸易股份", ["CN"], entry_id=w["id"], expected_version=1
        )
        deactivated = self.service.add_or_update_watchlist(
            "s1", "supervisor", "OFAC", "远海贸易股份", ["CN"], active=False, entry_id=w["id"], expected_version=2
        )
        self.assertEqual(2, corrected["version"])
        self.assertEqual(3, deactivated["version"])
        history = self.service.watchlist_history("s1", "supervisor")["entries"]
        versions = history[0]["versions"]
        self.assertEqual(["created", "corrected", "deactivated"], [v["change_type"] for v in versions])
        self.assertEqual(["远海贸易", "远海贸易股份", "远海贸易股份"], [v["name"] for v in versions])
        self.assertEqual([1, 1, 0], [v["active"] for v in versions])
        self.assertTrue(all(v["effective_at"] for v in versions))
        # 当前态为停用，筛查不再命中
        later = self.service.ingest_transaction("a1", "analyst", "T-9", self.customer["id"], 1000, "USD", "远海贸易股份", "CN")
        self.assertIsNone(later["screening_archive"])
        self.assertNotEqual("escalated", later["transaction"]["status"])

    def test_noop_does_not_create_version_and_conflict_detected(self):
        w = self.service.add_or_update_watchlist("s1", "supervisor", "OFAC", "远海贸易", ["CN"])
        with self.assertRaises(DomainError) as ctx:
            self.service.add_or_update_watchlist("s1", "supervisor", "OFAC", "远海贸易", ["CN"], entry_id=w["id"], expected_version=1)
        self.assertEqual(400, ctx.exception.status)
        with self.assertRaises(DomainError) as ctx2:
            self.service.add_or_update_watchlist(
                "s1", "supervisor", "OFAC", "远海贸易", ["CN"], active=False, entry_id=w["id"], expected_version=9
            )
        self.assertEqual(409, ctx2.exception.status)

    def test_screening_archives_matched_version_and_change_queues_review_once(self):
        w = self.service.add_or_update_watchlist("s1", "supervisor", "OFAC", "远海贸易", ["CN"])
        txn = self._hit_txn()
        archive = txn["screening_archive"]
        self.assertEqual(w["id"], archive["watchlist_entry_id"])
        self.assertEqual(1, archive["entry_version"])
        self.assertEqual("created", archive["change_type"])
        self.assertTrue(archive["entry_effective_at"])

        updated = self.service.add_or_update_watchlist(
            "s1", "supervisor", "OFAC", "远海贸易", ["IR"], entry_id=w["id"], expected_version=1
        )
        self.assertEqual(1, updated["reviews_queued"])
        # 重复触发同一版本不产生新任务
        with self.service.connect() as conn:
            self.assertEqual(0, self.service.screening_store.enqueue_reviews_for_change(conn, w["id"], 1, 2))
        pending = self.service.list_reviews("i1", "investigator", status="pending")["reviews"]
        self.assertEqual(1, len(pending))
        self.assertEqual(2, pending[0]["to_version"])
        # 再停用一次，仍为同一受影响交易补 v3 复核（只补一条）
        self.service.add_or_update_watchlist(
            "s1", "supervisor", "OFAC", "远海贸易", ["IR"], active=False, entry_id=w["id"], expected_version=2
        )
        pending3 = [r for r in self.service.list_reviews("s1", "supervisor")["reviews"] if r["to_version"] == 3]
        self.assertEqual(1, len(pending3))

    def test_review_records_actor_conclusion_and_case_expands_versions(self):
        w = self.service.add_or_update_watchlist("s1", "supervisor", "OFAC", "远海贸易", ["CN"])
        ingested = self._hit_txn()
        self.service.add_or_update_watchlist(
            "s1", "supervisor", "OFAC", "远海贸易", ["IR"], entry_id=w["id"], expected_version=1
        )
        review = self.service.list_reviews("i1", "investigator", status="pending")["reviews"][0]
        done = self.service.resolve_review("i1", "investigator", review["id"], "false_positive", "旧版误命中")
        self.assertEqual("done", done["status"])
        self.assertEqual("i1", done["reviewed_by"])
        self.assertTrue(done["reviewed_at"])
        with self.assertRaises(DomainError) as ctx:
            self.service.resolve_review("i1", "investigator", review["id"], "confirmed")
        self.assertEqual(409, ctx.exception.status)

        case = self.service.triage_alert("s1", "supervisor", ingested["alert"]["id"], "escalate", "i1", "CASE-1")["case"]
        detail = self.service.get_case("i1", "investigator", case["id"])
        self.assertEqual(1, len(detail["screening_hits"]))
        hit = detail["screening_hits"][0]
        self.assertEqual(1, hit["entry_version"])
        self.assertEqual("远海贸易", hit["matched_name"])
        self.assertEqual([1, 2], [v["version"] for v in hit["entry_versions"]])
        self.assertEqual("false_positive", hit["reviews"][0]["conclusion"])
        self.assertEqual("i1", hit["reviews"][0]["reviewed_by"])

    def test_history_and_reviews_survive_restart(self):
        w = self.service.add_or_update_watchlist("s1", "supervisor", "OFAC", "远海贸易", ["CN"])
        self._hit_txn("T-1")
        self.service.add_or_update_watchlist(
            "s1", "supervisor", "OFAC", "远海贸易", ["IR"], entry_id=w["id"], expected_version=1
        )
        review = self.service.list_reviews("i1", "investigator", status="pending")["reviews"][0]
        self.service.resolve_review("i1", "investigator", review["id"], "confirmed", "维持")

        reopened = FinancialCrimeService(self.service.db_path)
        versions = reopened.watchlist_history("aud1", "auditor")["entries"][0]["versions"]
        self.assertEqual(2, len(versions))
        done = [r for r in reopened.list_reviews("aud1", "auditor")["reviews"]]
        self.assertEqual("confirmed", done[0]["conclusion"])
        self.assertEqual("i1", done[0]["reviewed_by"])

    def test_review_permissions(self):
        with self.assertRaises(DomainError) as ctx:
            self.service.list_reviews("a1", "analyst")
        self.assertEqual(403, ctx.exception.status)
        w = self.service.add_or_update_watchlist("s1", "supervisor", "OFAC", "远海贸易", ["CN"])
        self._hit_txn()
        self.service.add_or_update_watchlist(
            "s1", "supervisor", "OFAC", "远海贸易", ["IR"], entry_id=w["id"], expected_version=1
        )
        review = self.service.list_reviews("i1", "investigator", status="pending")["reviews"][0]
        with self.assertRaises(DomainError) as ctx2:
            self.service.resolve_review("a1", "analyst", review["id"], "confirmed")
        self.assertEqual(403, ctx2.exception.status)


if __name__ == "__main__":
    unittest.main()
