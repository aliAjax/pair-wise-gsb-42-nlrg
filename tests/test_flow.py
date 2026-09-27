import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import DomainError, FinancialCrimeService  # noqa: E402


class FinancialCrimeFlowTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.service = FinancialCrimeService(Path(self.tmp.name) / "test.db")
        self.entity = self.service.create_entity("analyst1", "analyst", "organization", "远海贸易", ["远海"])
        self.customer = self.service.create_customer("analyst1", "analyst", self.entity["id"], "C-001", "CN", risk_score=0.2)

    def tearDown(self):
        self.tmp.cleanup()

    def test_full_screening_case_freeze_and_report_flow(self):
        self.service.add_or_update_watchlist("sup1", "supervisor", "OFAC", "远海贸易", ["CN"])
        ingested = self.service.ingest_transaction(
            "analyst1", "analyst", "T-001", self.customer["id"], 150000, "USD", "远海贸易", "CN"
        )
        self.assertEqual("escalated", ingested["transaction"]["status"])
        alert = ingested["alert"]
        triaged = self.service.triage_alert("inv1", "investigator", alert["id"], "escalate", "inv1", "CASE-001")
        case = triaged["case"]
        case = self.service.update_case("inv1", "investigator", case["id"], "已核实交易链", case["version"], "escalated")
        case = self.service.freeze_entity("sup1", "supervisor", self.entity["id"], "制裁命中", self.entity["version"], case["id"])
        self.assertEqual(1, case["frozen"])
        blocked = self.service.ingest_transaction("analyst1", "analyst", "T-002", self.customer["id"], 100, "USD", "普通供应商", "US")
        self.assertEqual("blocked", blocked["transaction"]["status"])
        current = self.service.get_case("sup1", "supervisor", triaged["case"]["id"])["case"]
        reported = self.service.file_report("sup1", "supervisor", current["id"], "STR-001", current["version"])
        self.assertEqual("report_filed", reported["status"])

    def test_entity_merge_updates_transactions_and_keeps_audit(self):
        target = self.service.create_entity("sup1", "supervisor", "organization", "远海集团", [])
        transaction = self.service.ingest_transaction("analyst1", "analyst", "T-010", self.customer["id"], 1000, "CNY", "普通客户", "CN")["transaction"]
        merged = self.service.merge_entities("sup1", "supervisor", self.entity["id"], target["id"], self.entity["version"], target["version"])
        self.assertEqual(target["id"], merged["source"]["merged_into"])
        self.assertIn("远海贸易", merged["target"]["aliases"])
        later = self.service.ingest_transaction("analyst1", "analyst", "T-011", self.customer["id"], 2000, "CNY", "普通客户", "CN")
        self.assertEqual(target["id"], later["resolved_entity_id"])
        with self.assertRaises(DomainError):
            self.service.create_entity("analyst1", "analyst", "organization", "远海贸易", [])
        self.assertEqual(target["id"], later["transaction"]["entity_id"])

    def test_case_confidentiality_concurrency_and_freeze_permission(self):
        alert = self.service.ingest_transaction(
            "analyst1", "analyst", "T-020", self.customer["id"], 200000, "USD", "未知公司", "US"
        )["alert"]
        case = self.service.triage_alert("sup1", "supervisor", alert["id"], "escalate", "inv1", "CASE-020")["case"]
        with self.assertRaises(DomainError) as ctx:
            self.service.get_case("inv2", "investigator", case["id"])
        self.assertEqual(403, ctx.exception.status)
        with self.assertRaises(DomainError) as ctx2:
            self.service.freeze_entity("analyst1", "analyst", self.entity["id"], "越权", self.entity["version"])
        self.assertEqual(403, ctx2.exception.status)
        updated = self.service.update_case("inv1", "investigator", case["id"], "第一条", case["version"])
        with self.assertRaises(DomainError) as ctx3:
            self.service.update_case("inv1", "investigator", case["id"], "旧版本", case["version"])
        self.assertEqual(409, ctx3.exception.status)
        self.assertEqual(updated["version"] + 1, self.service.update_case("inv1", "investigator", case["id"], "第二条", updated["version"])["version"])


if __name__ == "__main__":
    unittest.main()
