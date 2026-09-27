"""Financial-crime investigation and sanctions-screening service."""
from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
from datetime import datetime, timezone
from difflib import SequenceMatcher
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
DEFAULT_DB = ROOT / "financial_crime.db"
HIGH_RISK_COUNTRIES = {"KP", "IR", "SY", "CU", "RU"}
SENSITIVE_ROLES = {"investigator", "supervisor", "director", "auditor"}


class DomainError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def normalize_name(value: str) -> str:
    return re.sub(r"[^0-9a-z\u4e00-\u9fff]+", "", (value or "").casefold())


def require_role(role: str, allowed: set[str], action: str) -> None:
    if role not in allowed:
        raise DomainError("角色无权执行：%s" % action, 403)


def clean_actor(actor: str) -> str:
    actor = (actor or "").strip()
    if not actor:
        raise DomainError("缺少操作人")
    return actor


def name_similarity(left: str, right: str) -> float:
    left, right = normalize_name(left), normalize_name(right)
    if not left or not right:
        return 0.0
    if left == right:
        return 1.0
    return SequenceMatcher(None, left, right).ratio()


class WatchlistHistory:
    """名单历史：条目每次创建、更正、停用、重新启用都留存版本快照和生效时间。"""

    CREATED = "created"
    CORRECTED = "corrected"
    DEACTIVATED = "deactivated"
    REACTIVATED = "reactivated"

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def record(self, entry: sqlite3.Row, change_type: str, actor: str, effective_at: str) -> int:
        cur = self.conn.execute(
            """INSERT INTO watchlist_versions
               (entry_id,list_name,name,normalized_name,countries,version,active,change_type,changed_by,effective_at)
               VALUES(?,?,?,?,?,?,?,?,?,?)""",
            (entry["id"], entry["list_name"], entry["name"], entry["normalized_name"],
             entry["countries"], entry["version"], entry["active"], change_type, actor, effective_at),
        )
        return cur.lastrowid

    def version_id(self, entry_id: int, version: int) -> int | None:
        row = self.conn.execute(
            "SELECT id FROM watchlist_versions WHERE entry_id=? AND version=?",
            (entry_id, version),
        ).fetchone()
        return row["id"] if row else None

    def versions(self, entry_id: int) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM watchlist_versions WHERE entry_id=? ORDER BY version",
            (entry_id,),
        ).fetchall()
        return [dict(r) for r in rows]


class ScreeningArchive:
    """筛查存档：筛查命中时把命中条目的当时版本随交易一并快照留档。"""

    INITIAL = "initial"
    RESCREEN = "rescreen"

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def _insert(self, transaction_id: int, entry: sqlite3.Row | None, score: float, kind: str,
                actor: str, screened_at: str, review_id: int | None = None) -> dict[str, Any]:
        version_id = (
            WatchlistHistory(self.conn).version_id(entry["id"], entry["version"])
            if entry is not None else None
        )
        cur = self.conn.execute(
            """INSERT INTO screening_archives(transaction_id,watchlist_entry_id,watchlist_version_id,
               list_name,entry_name,entry_version,entry_active,countries,normalized_name,score,
               kind,review_id,screened_by,screened_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (transaction_id, entry["id"] if entry else None, version_id,
             entry["list_name"] if entry else None, entry["name"] if entry else None,
             entry["version"] if entry else None, entry["active"] if entry else None,
             entry["countries"] if entry else "[]", entry["normalized_name"] if entry else None,
             score, kind, review_id, actor, screened_at),
        )
        return dict(self.conn.execute("SELECT * FROM screening_archives WHERE id=?", (cur.lastrowid,)).fetchone())

    def record_initial(self, transaction_id: int, entry: sqlite3.Row, score: float,
                       actor: str, screened_at: str) -> dict[str, Any]:
        return self._insert(transaction_id, entry, score, self.INITIAL, actor, screened_at)

    def record_rescreen(self, transaction_id: int, entry: sqlite3.Row | None, score: float,
                        review_id: int, actor: str, screened_at: str) -> dict[str, Any]:
        return self._insert(transaction_id, entry, score, self.RESCREEN, actor, screened_at, review_id)

    def for_transactions(self, transaction_ids: set[int]) -> dict[int, list[dict[str, Any]]]:
        if not transaction_ids:
            return {}
        marks = ",".join("?" for _ in transaction_ids)
        rows = self.conn.execute(
            """SELECT sa.*, wv.effective_at AS version_effective_at, wv.change_type AS version_change_type
               FROM screening_archives sa
               LEFT JOIN watchlist_versions wv ON wv.id=sa.watchlist_version_id
               WHERE sa.transaction_id IN (%s) ORDER BY sa.id""" % marks,
            tuple(transaction_ids),
        ).fetchall()
        grouped: dict[int, list[dict[str, Any]]] = {}
        for row in rows:
            grouped.setdefault(row["transaction_id"], []).append(dict(row))
        return grouped


class ListReviewQueue:
    """名单变化复核队列：受影响交易自动待复核，同一版本对同一交易只入队一次。"""

    PENDING = "pending"
    REVIEWED = "reviewed"

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def enqueue_affected(self, entry_id: int, to_version: int, trigger_change: str, now: str) -> int:
        cur = self.conn.execute(
            """INSERT OR IGNORE INTO watchlist_reviews
               (transaction_id,watchlist_entry_id,from_version,to_version,trigger_change,status,created_at)
               SELECT sa.transaction_id,?,sa.entry_version,?,?,'pending',?
               FROM screening_archives sa
               WHERE sa.watchlist_entry_id=? AND sa.kind='initial'""",
            (entry_id, to_version, trigger_change, now, entry_id),
        )
        return cur.rowcount

    def for_transactions(self, transaction_ids: set[int]) -> dict[int, list[dict[str, Any]]]:
        if not transaction_ids:
            return {}
        marks = ",".join("?" for _ in transaction_ids)
        rows = self.conn.execute(
            """SELECT r.*, w.list_name AS list_name, w.name AS entry_name
               FROM watchlist_reviews r
               LEFT JOIN watchlist w ON w.id=r.watchlist_entry_id
               WHERE r.transaction_id IN (%s) ORDER BY r.id""" % marks,
            tuple(transaction_ids),
        ).fetchall()
        grouped: dict[int, list[dict[str, Any]]] = {}
        for row in rows:
            grouped.setdefault(row["transaction_id"], []).append(dict(row))
        return grouped

    def pending_transaction_ids(self) -> set[int]:
        rows = self.conn.execute(
            "SELECT DISTINCT transaction_id FROM watchlist_reviews WHERE status='pending'"
        ).fetchall()
        return {row["transaction_id"] for row in rows}

    def list_all(self, limit: int = 100) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """SELECT r.*, w.list_name AS list_name, w.name AS entry_name,
                      t.txn_ref AS txn_ref, t.status AS txn_status,
                      t.counterparty_name AS counterparty_name, t.counterparty_country AS counterparty_country
               FROM watchlist_reviews r
               JOIN transactions t ON t.id=r.transaction_id
               LEFT JOIN watchlist w ON w.id=r.watchlist_entry_id
               ORDER BY CASE r.status WHEN 'pending' THEN 0 ELSE 1 END, r.id DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]


class FinancialCrimeService:
    def __init__(self, db_path: str | os.PathLike[str] = DEFAULT_DB):
        self.db_path = str(db_path)
        self._init_schema()

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=10000")
        return conn

    def _init_schema(self) -> None:
        with self.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS entities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entity_type TEXT NOT NULL,
                    canonical_name TEXT NOT NULL,
                    normalized_name TEXT NOT NULL,
                    aliases TEXT NOT NULL DEFAULT '[]',
                    risk_level TEXT NOT NULL DEFAULT 'low',
                    frozen INTEGER NOT NULL DEFAULT 0,
                    merged_into INTEGER REFERENCES entities(id),
                    version INTEGER NOT NULL DEFAULT 1,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS customers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entity_id INTEGER NOT NULL REFERENCES entities(id),
                    customer_no TEXT NOT NULL UNIQUE,
                    country TEXT NOT NULL,
                    occupation TEXT NOT NULL DEFAULT '',
                    allowlisted INTEGER NOT NULL DEFAULT 0,
                    risk_score REAL NOT NULL DEFAULT 0,
                    merged_into INTEGER REFERENCES customers(id),
                    version INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS watchlist (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    list_name TEXT NOT NULL,
                    name TEXT NOT NULL,
                    normalized_name TEXT NOT NULL,
                    countries TEXT NOT NULL DEFAULT '[]',
                    version INTEGER NOT NULL DEFAULT 1,
                    active INTEGER NOT NULL DEFAULT 1,
                    updated_by TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(list_name, normalized_name)
                );
                CREATE TABLE IF NOT EXISTS transactions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    txn_ref TEXT NOT NULL UNIQUE,
                    customer_id INTEGER NOT NULL REFERENCES customers(id),
                    entity_id INTEGER NOT NULL REFERENCES entities(id),
                    amount REAL NOT NULL,
                    currency TEXT NOT NULL,
                    counterparty_name TEXT NOT NULL,
                    counterparty_country TEXT NOT NULL,
                    status TEXT NOT NULL,
                    risk_score REAL NOT NULL,
                    reason TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    fingerprint TEXT NOT NULL UNIQUE,
                    entity_id INTEGER NOT NULL REFERENCES entities(id),
                    transaction_id INTEGER REFERENCES transactions(id),
                    reason TEXT NOT NULL,
                    risk_score REAL NOT NULL,
                    status TEXT NOT NULL DEFAULT 'new',
                    occurrences INTEGER NOT NULL DEFAULT 1,
                    case_id INTEGER,
                    dismissed_reason TEXT,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS cases (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_no TEXT NOT NULL UNIQUE,
                    entity_id INTEGER NOT NULL REFERENCES entities(id),
                    alert_id INTEGER REFERENCES alerts(id),
                    status TEXT NOT NULL DEFAULT 'open',
                    risk_score REAL NOT NULL,
                    assignee TEXT,
                    freeze_target INTEGER NOT NULL DEFAULT 0,
                    report_ref TEXT,
                    version INTEGER NOT NULL DEFAULT 1,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS case_notes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id INTEGER NOT NULL REFERENCES cases(id),
                    actor TEXT NOT NULL,
                    note TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS entity_merges (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_id INTEGER NOT NULL,
                    target_id INTEGER NOT NULL,
                    actor TEXT NOT NULL,
                    details TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS timeline (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id INTEGER REFERENCES cases(id),
                    entity_id INTEGER REFERENCES entities(id),
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    details TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS watchlist_versions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entry_id INTEGER NOT NULL REFERENCES watchlist(id),
                    list_name TEXT NOT NULL,
                    name TEXT NOT NULL,
                    normalized_name TEXT NOT NULL,
                    countries TEXT NOT NULL DEFAULT '[]',
                    version INTEGER NOT NULL,
                    active INTEGER NOT NULL,
                    change_type TEXT NOT NULL,
                    changed_by TEXT NOT NULL,
                    effective_at TEXT NOT NULL,
                    UNIQUE(entry_id, version)
                );
                CREATE TABLE IF NOT EXISTS screening_archives (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    transaction_id INTEGER NOT NULL REFERENCES transactions(id),
                    watchlist_entry_id INTEGER REFERENCES watchlist(id),
                    watchlist_version_id INTEGER REFERENCES watchlist_versions(id),
                    list_name TEXT,
                    entry_name TEXT,
                    entry_version INTEGER,
                    entry_active INTEGER,
                    countries TEXT NOT NULL DEFAULT '[]',
                    normalized_name TEXT,
                    score REAL NOT NULL,
                    kind TEXT NOT NULL DEFAULT 'initial',
                    review_id INTEGER,
                    screened_by TEXT NOT NULL,
                    screened_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS watchlist_reviews (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    transaction_id INTEGER NOT NULL REFERENCES transactions(id),
                    watchlist_entry_id INTEGER NOT NULL REFERENCES watchlist(id),
                    from_version INTEGER NOT NULL,
                    to_version INTEGER NOT NULL,
                    trigger_change TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    conclusion TEXT,
                    handled_by TEXT,
                    handled_at TEXT,
                    note TEXT,
                    rescreen_archive_id INTEGER REFERENCES screening_archives(id),
                    created_at TEXT NOT NULL,
                    UNIQUE(transaction_id, watchlist_entry_id, to_version)
                );
                CREATE INDEX IF NOT EXISTS idx_wv_entry ON watchlist_versions(entry_id, version);
                CREATE INDEX IF NOT EXISTS idx_sa_txn ON screening_archives(transaction_id);
                CREATE INDEX IF NOT EXISTS idx_sa_entry ON screening_archives(watchlist_entry_id);
                CREATE INDEX IF NOT EXISTS idx_wr_status ON watchlist_reviews(status, id);
                CREATE INDEX IF NOT EXISTS idx_txn_entity ON transactions(entity_id, created_at);
                CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status, risk_score DESC);
                """
            )

    def _audit(self, conn: sqlite3.Connection, actor: str, action: str, details: dict[str, Any],
               entity_id: int | None = None, case_id: int | None = None) -> None:
        conn.execute(
            "INSERT INTO timeline(case_id,entity_id,actor,action,details,created_at) VALUES(?,?,?,?,?,?)",
            (case_id, entity_id, actor, action, json.dumps(details, ensure_ascii=False, sort_keys=True), utcnow()),
        )

    def _resolve_entity(self, conn: sqlite3.Connection, entity_id: int) -> sqlite3.Row:
        seen = set()
        current = entity_id
        while True:
            if current in seen:
                raise DomainError("实体合并关系存在循环", 409)
            seen.add(current)
            row = conn.execute("SELECT * FROM entities WHERE id=?", (current,)).fetchone()
            if not row:
                raise DomainError("实体不存在", 404)
            if row["merged_into"] is None:
                return row
            current = row["merged_into"]

    def create_entity(self, actor: str, role: str, entity_type: str, canonical_name: str,
                      aliases: list[str] | None = None) -> dict[str, Any]:
        actor = clean_actor(actor)
        require_role(role, {"analyst", "investigator", "supervisor"}, "创建实体")
        entity_type = entity_type.strip().lower()
        canonical_name = canonical_name.strip()
        if entity_type not in {"person", "organization"} or not canonical_name:
            raise DomainError("实体类型或名称无效")
        normalized = normalize_name(canonical_name)
        clean_aliases = sorted({a.strip() for a in (aliases or []) if a and a.strip()}, key=str.casefold)
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            existing_entities = conn.execute(
                "SELECT canonical_name,aliases FROM entities WHERE merged_into IS NULL"
            ).fetchall()
            for row in existing_entities:
                known_names = [row["canonical_name"]] + json.loads(row["aliases"])
                if any(normalize_name(item) == normalized for item in known_names):
                    raise DomainError("实体名称或别名已存在，应使用已有实体或执行合并", 409)
            try:
                cur = conn.execute(
                    """INSERT INTO entities(entity_type,canonical_name,normalized_name,aliases,created_by,created_at,updated_at)
                       VALUES(?,?,?,?,?,?,?)""",
                    (entity_type, canonical_name, normalized, json.dumps(clean_aliases, ensure_ascii=False), actor, utcnow(), utcnow()),
                )
            except sqlite3.IntegrityError as exc:
                raise DomainError("实体已存在", 409) from exc
            self._audit(conn, actor, "entity.created", {"name": canonical_name}, cur.lastrowid)
            return dict(conn.execute("SELECT * FROM entities WHERE id=?", (cur.lastrowid,)).fetchone())

    def add_alias(self, actor: str, role: str, entity_id: int, alias: str,
                  expected_version: int) -> dict[str, Any]:
        actor = clean_actor(actor)
        require_role(role, {"analyst", "investigator", "supervisor"}, "维护实体别名")
        alias = alias.strip()
        if not alias:
            raise DomainError("别名不能为空")
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            entity = self._resolve_entity(conn, entity_id)
            if entity["merged_into"] is not None:
                raise DomainError("请在主实体上维护别名", 409)
            if entity["version"] != int(expected_version):
                raise DomainError("实体已变化，请刷新后重试", 409)
            aliases = json.loads(entity["aliases"])
            normalized = normalize_name(alias)
            conflict = conn.execute(
                "SELECT id,canonical_name,aliases FROM entities WHERE merged_into IS NULL AND id<>?",
                (entity["id"],),
            ).fetchall()
            for row in conflict:
                names = [row["canonical_name"]] + json.loads(row["aliases"])
                if any(normalize_name(name) == normalized for name in names):
                    raise DomainError("别名已属于其他实体，应先执行实体合并", 409)
            if alias not in aliases:
                aliases.append(alias)
                aliases.sort(key=str.casefold)
            conn.execute(
                "UPDATE entities SET aliases=?,version=version+1,updated_at=? WHERE id=? AND version=?",
                (json.dumps(aliases, ensure_ascii=False), utcnow(), entity["id"], expected_version),
            )
            self._audit(conn, actor, "entity.alias_added", {"alias": alias}, entity["id"])
            return dict(conn.execute("SELECT * FROM entities WHERE id=?", (entity["id"],)).fetchone())

    def create_customer(self, actor: str, role: str, entity_id: int, customer_no: str,
                        country: str, occupation: str = "", allowlisted: bool = False,
                        risk_score: float = 0.0) -> dict[str, Any]:
        actor = clean_actor(actor)
        require_role(role, {"analyst", "supervisor"}, "建立客户档案")
        try:
            risk_score = float(risk_score)
        except (TypeError, ValueError) as exc:
            raise DomainError("风险评分必须是数值") from exc
        if not customer_no.strip() or len(country.strip()) != 2 or not 0 <= risk_score <= 1:
            raise DomainError("客户编号、国家代码或风险评分无效")
        with self.connect() as conn:
            entity = self._resolve_entity(conn, entity_id)
            try:
                cur = conn.execute(
                    """INSERT INTO customers(entity_id,customer_no,country,occupation,allowlisted,risk_score,created_at)
                       VALUES(?,?,?,?,?,?,?)""",
                    (entity["id"], customer_no.strip(), country.strip().upper(), occupation.strip(), int(bool(allowlisted)), risk_score, utcnow()),
                )
            except sqlite3.IntegrityError as exc:
                raise DomainError("客户编号已存在", 409) from exc
            self._audit(conn, actor, "customer.created", {"customer_no": customer_no.strip()}, entity["id"])
            return dict(conn.execute("SELECT * FROM customers WHERE id=?", (cur.lastrowid,)).fetchone())

    def add_or_update_watchlist(self, actor: str, role: str, list_name: str, name: str,
                                countries: list[str] | None = None,
                                active: bool = True, expected_version: int | None = None,
                                entry_id: int | None = None) -> dict[str, Any]:
        actor = clean_actor(actor)
        require_role(role, {"supervisor"}, "维护制裁名单")
        list_name, name = list_name.strip(), name.strip()
        normalized = normalize_name(name)
        countries_json = json.dumps(sorted({c.strip().upper() for c in (countries or []) if c.strip()}), ensure_ascii=False)
        if not list_name or not normalized:
            raise DomainError("名单名称和实体名称不能为空")
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            history = WatchlistHistory(conn)
            row = None
            if entry_id is not None:
                row = conn.execute("SELECT * FROM watchlist WHERE id=?", (int(entry_id),)).fetchone()
                if not row:
                    raise DomainError("名单条目不存在", 404)
            else:
                row = conn.execute(
                    "SELECT * FROM watchlist WHERE list_name=? AND normalized_name=?", (list_name, normalized)
                ).fetchone()
            now = utcnow()
            if row:
                if expected_version is not None and row["version"] != int(expected_version):
                    raise DomainError("名单条目已变化，请刷新后重试", 409)
                was_active, new_active = bool(row["active"]), bool(active)
                corrected = name != row["name"] or countries_json != row["countries"]
                if not corrected and was_active == new_active:
                    return {"entry": dict(row), "history_version_id": None, "enqueued_reviews": 0, "changed": False}
                change_type = (
                    WatchlistHistory.DEACTIVATED if was_active and not new_active else
                    WatchlistHistory.REACTIVATED if not was_active and new_active else
                    WatchlistHistory.CORRECTED
                )
                try:
                    conn.execute(
                        "UPDATE watchlist SET list_name=?,name=?,normalized_name=?,countries=?,active=?,version=version+1,updated_by=?,updated_at=? WHERE id=?",
                        (list_name, name, normalized, countries_json, int(new_active), actor, now, row["id"]),
                    )
                except sqlite3.IntegrityError as exc:
                    raise DomainError("同一名单下已存在该名称的条目", 409) from exc
                updated = conn.execute("SELECT * FROM watchlist WHERE id=?", (row["id"],)).fetchone()
                history_version_id = history.record(updated, change_type, actor, now)
                enqueued = ListReviewQueue(conn).enqueue_affected(updated["id"], updated["version"], change_type, now)
                self._audit(conn, actor, "watchlist.updated",
                            {"list_name": list_name, "name": name, "active": new_active,
                             "entry_id": updated["id"], "version": updated["version"],
                             "change_type": change_type, "affected_transactions": enqueued})
                return {"entry": dict(updated), "history_version_id": history_version_id,
                        "enqueued_reviews": enqueued, "changed": True}
            try:
                cur = conn.execute(
                    "INSERT INTO watchlist(list_name,name,normalized_name,countries,active,updated_by,updated_at) VALUES(?,?,?,?,?,?,?)",
                    (list_name, name, normalized, countries_json, int(bool(active)), actor, now),
                )
            except sqlite3.IntegrityError as exc:
                raise DomainError("名单条目已存在", 409) from exc
            entry = conn.execute("SELECT * FROM watchlist WHERE id=?", (cur.lastrowid,)).fetchone()
            history_version_id = history.record(entry, WatchlistHistory.CREATED, actor, now)
            self._audit(conn, actor, "watchlist.added", {"list_name": list_name, "name": name, "entry_id": entry["id"]})
            return {"entry": dict(entry), "history_version_id": history_version_id,
                    "enqueued_reviews": 0, "changed": True}

    def _match_entry(self, conn: sqlite3.Connection, counterparty_name: str,
                     country: str) -> tuple[float, sqlite3.Row | None]:
        entries = conn.execute("SELECT * FROM watchlist WHERE active=1").fetchall()
        best_score, best = 0.0, None
        for row in entries:
            countries = json.loads(row["countries"])
            if countries and country.upper() not in countries:
                continue
            score = name_similarity(counterparty_name, row["name"])
            if score > best_score:
                best_score, best = score, row
        if best and best_score >= 0.9:
            return 0.95, best
        return best_score, None

    def ingest_transaction(self, actor: str, role: str, txn_ref: str, customer_id: int,
                           amount: float, currency: str, counterparty_name: str,
                           counterparty_country: str) -> dict[str, Any]:
        actor = clean_actor(actor)
        require_role(role, {"analyst", "investigator"}, "录入交易")
        try:
            amount = float(amount)
        except (TypeError, ValueError) as exc:
            raise DomainError("交易金额必须是数值") from exc
        if not txn_ref.strip() or amount <= 0 or len(currency.strip()) != 3 or len(counterparty_country.strip()) != 2:
            raise DomainError("交易编号、金额、币种或国家代码无效")
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            customer = conn.execute("SELECT * FROM customers WHERE id=?", (customer_id,)).fetchone()
            if not customer:
                raise DomainError("客户不存在", 404)
            entity = self._resolve_entity(conn, customer["entity_id"])
            country = counterparty_country.strip().upper()
            screened_at = utcnow()
            match_score, matched_entry = self._match_entry(conn, counterparty_name.strip(), country)
            match_reason = "sanctions_match:%s:%s" % (matched_entry["list_name"], matched_entry["name"]) if matched_entry else None
            base_risk = customer["risk_score"]
            reason = "normal"
            if match_reason:
                risk, reason = max(match_score, base_risk), match_reason
            elif country in HIGH_RISK_COUNTRIES:
                risk, reason = max(0.75, base_risk), "high_risk_country:" + country
            elif amount >= 100000:
                risk, reason = max(0.6, base_risk), "large_value_transaction"
            elif amount >= 50000:
                risk, reason = max(0.35, base_risk), "enhanced_review"
            else:
                risk = base_risk
            if entity["frozen"]:
                status = "blocked"
                reason = "frozen_entity"
                risk = 1.0
            elif match_reason:
                status = "escalated"
            elif risk >= 0.5:
                status = "review"
            else:
                status = "allowed"
            if customer["allowlisted"] and risk < 0.8 and amount <= 200000:
                status, risk, reason = "allowed", min(risk, 0.1), "allowlist_false_positive_reduction"
            try:
                cur = conn.execute(
                    """INSERT INTO transactions(txn_ref,customer_id,entity_id,amount,currency,counterparty_name,
                       counterparty_country,status,risk_score,reason,created_by,created_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (txn_ref.strip(), customer["id"], entity["id"], amount, currency.strip().upper(),
                     counterparty_name.strip(), country, status, risk, reason, actor, utcnow()),
                )
            except sqlite3.IntegrityError as exc:
                raise DomainError("交易编号已存在", 409) from exc
            screen_archive = None
            if matched_entry is not None:
                screen_archive = ScreeningArchive(conn).record_initial(
                    cur.lastrowid, matched_entry, match_score, actor, screened_at
                )
            alert = None
            if status in {"review", "escalated", "blocked"}:
                fingerprint = "%s|%s|%s" % (entity["id"], reason.split(":")[0], normalize_name(counterparty_name))
                existing = conn.execute("SELECT * FROM alerts WHERE fingerprint=?", (fingerprint,)).fetchone()
                if existing:
                    conn.execute(
                        "UPDATE alerts SET occurrences=occurrences+1,last_seen=?,risk_score=MAX(risk_score,?),transaction_id=? WHERE id=?",
                        (utcnow(), risk, cur.lastrowid, existing["id"]),
                    )
                    alert_id = existing["id"]
                else:
                    alert_cur = conn.execute(
                        """INSERT INTO alerts(fingerprint,entity_id,transaction_id,reason,risk_score,first_seen,last_seen)
                           VALUES(?,?,?,?,?,?,?)""",
                        (fingerprint, entity["id"], cur.lastrowid, reason, risk, utcnow(), utcnow()),
                    )
                    alert_id = alert_cur.lastrowid
                alert = dict(conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone())
            if entity["frozen"]:
                conn.execute("UPDATE transactions SET status='blocked' WHERE entity_id=? AND status='review'", (entity["id"],))
            self._audit(conn, actor, "transaction.ingested", {"txn_ref": txn_ref, "status": status, "reason": reason}, entity["id"])
            transaction = dict(conn.execute("SELECT * FROM transactions WHERE id=?", (cur.lastrowid,)).fetchone())
            return {"transaction": transaction, "alert": alert,
                    "screen_archive": screen_archive, "resolved_entity_id": entity["id"]}

    def triage_alert(self, actor: str, role: str, alert_id: int, decision: str,
                    assignee: str | None = None, case_no: str | None = None,
                    reason: str = "") -> dict[str, Any]:
        actor = clean_actor(actor)
        require_role(role, {"investigator", "supervisor"}, "处置可疑线索")
        if decision not in {"dismiss", "escalate"}:
            raise DomainError("线索处置决定无效")
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            alert = conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
            if not alert:
                raise DomainError("线索不存在", 404)
            if alert["status"] not in {"new", "triaged"}:
                raise DomainError("线索已处置", 409)
            if decision == "dismiss":
                if not reason.strip():
                    raise DomainError("误报关闭必须填写理由", 409)
                if alert["risk_score"] >= 0.9:
                    raise DomainError("制裁命中线索不能直接关闭", 409)
                conn.execute("UPDATE alerts SET status='dismissed',dismissed_reason=? WHERE id=?", (reason.strip(), alert_id))
                self._audit(conn, actor, "alert.dismissed", {"alert_id": alert_id, "reason": reason.strip()}, alert["entity_id"])
                return {"alert": dict(conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()), "case": None}
            number = (case_no or "CASE-%06d" % alert_id).strip()
            try:
                cur = conn.execute(
                    """INSERT INTO cases(case_no,entity_id,alert_id,status,risk_score,assignee,created_by,created_at,updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?)""",
                    (number, alert["entity_id"], alert_id, "investigating", alert["risk_score"], (assignee or actor).strip(), actor, utcnow(), utcnow()),
                )
            except sqlite3.IntegrityError as exc:
                raise DomainError("案件编号已存在", 409) from exc
            conn.execute("UPDATE alerts SET status='case_created',case_id=? WHERE id=?", (cur.lastrowid, alert_id))
            self._audit(conn, actor, "case.created", {"case_no": number, "alert_id": alert_id}, alert["entity_id"], cur.lastrowid)
            return {
                "alert": dict(conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()),
                "case": dict(conn.execute("SELECT * FROM cases WHERE id=?", (cur.lastrowid,)).fetchone()),
            }

    def _case_access(self, actor: str, role: str, case: sqlite3.Row) -> None:
        if role in {"supervisor", "director", "auditor"}:
            return
        if role == "investigator" and case["assignee"] == actor:
            return
        raise DomainError("案件仅限被指派的调查人员或授权角色访问", 403)

    def update_case(self, actor: str, role: str, case_id: int, note: str,
                    expected_version: int, status: str | None = None,
                    assignee: str | None = None) -> dict[str, Any]:
        actor = clean_actor(actor)
        require_role(role, {"investigator", "supervisor"}, "更新案件")
        if not note.strip():
            raise DomainError("调查记录不能为空")
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            case = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
            if not case:
                raise DomainError("案件不存在", 404)
            self._case_access(actor, role, case)
            if case["version"] != int(expected_version):
                raise DomainError("案件已变化，请刷新后重试", 409)
            if case["status"] in {"closed", "report_filed"} and role != "supervisor":
                raise DomainError("已结束案件不能再更新", 409)
            new_status = status or case["status"]
            if new_status not in {"open", "investigating", "escalated", "closed", "report_filed"}:
                raise DomainError("案件状态无效")
            if role == "investigator" and new_status in {"closed", "report_filed"}:
                raise DomainError("调查员不能自行结束案件", 403)
            conn.execute("INSERT INTO case_notes(case_id,actor,note,created_at) VALUES(?,?,?,?)", (case_id, actor, note.strip(), utcnow()))
            conn.execute(
                "UPDATE cases SET status=?,assignee=COALESCE(?,assignee),version=version+1,updated_at=? WHERE id=? AND version=?",
                (new_status, assignee.strip() if assignee else None, utcnow(), case_id, expected_version),
            )
            self._audit(conn, actor, "case.updated", {"status": new_status, "note": note.strip()}, case["entity_id"], case_id)
            return dict(conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone())

    def freeze_entity(self, actor: str, role: str, entity_id: int, reason: str,
                      expected_version: int, case_id: int | None = None) -> dict[str, Any]:
        actor = clean_actor(actor)
        require_role(role, {"supervisor", "director"}, "冻结实体")
        if not reason.strip():
            raise DomainError("冻结原因不能为空")
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            entity = self._resolve_entity(conn, entity_id)
            if entity["version"] != int(expected_version):
                raise DomainError("实体已变化，请刷新后重试", 409)
            conn.execute("UPDATE entities SET frozen=1,risk_level='high',version=version+1,updated_at=? WHERE id=?", (utcnow(), entity["id"]))
            conn.execute("UPDATE transactions SET status='blocked' WHERE entity_id=? AND status IN ('review','allowed')", (entity["id"],))
            if case_id is not None:
                case = conn.execute("SELECT * FROM cases WHERE id=? AND entity_id=?", (case_id, entity["id"])).fetchone()
                if not case:
                    raise DomainError("案件与实体不匹配", 409)
                conn.execute(
                    "UPDATE cases SET freeze_target=1,status=CASE WHEN status='investigating' THEN 'escalated' ELSE status END,version=version+1,updated_at=? WHERE id=?",
                    (utcnow(), case_id),
                )
            self._audit(conn, actor, "entity.frozen", {"reason": reason.strip()}, entity["id"], case_id)
            return dict(conn.execute("SELECT * FROM entities WHERE id=?", (entity["id"],)).fetchone())

    def unfreeze_entity(self, actor: str, role: str, entity_id: int, reason: str,
                        expected_version: int) -> dict[str, Any]:
        actor = clean_actor(actor)
        require_role(role, {"director"}, "解除冻结")
        if not reason.strip():
            raise DomainError("解冻原因不能为空")
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            entity = self._resolve_entity(conn, entity_id)
            if entity["version"] != int(expected_version):
                raise DomainError("实体已变化，请刷新后重试", 409)
            conn.execute("UPDATE entities SET frozen=0,risk_level='medium',version=version+1,updated_at=? WHERE id=?", (utcnow(), entity["id"]))
            self._audit(conn, actor, "entity.unfrozen", {"reason": reason.strip()}, entity["id"])
            return dict(conn.execute("SELECT * FROM entities WHERE id=?", (entity["id"],)).fetchone())

    def merge_entities(self, actor: str, role: str, source_id: int, target_id: int,
                       source_version: int, target_version: int) -> dict[str, Any]:
        actor = clean_actor(actor)
        require_role(role, {"supervisor"}, "合并实体")
        if source_id == target_id:
            raise DomainError("不能合并同一实体")
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            source = self._resolve_entity(conn, source_id)
            target = self._resolve_entity(conn, target_id)
            if source["version"] != int(source_version) or target["version"] != int(target_version):
                raise DomainError("实体已变化，请刷新后重试", 409)
            if source["id"] == target["id"]:
                raise DomainError("实体已经合并到目标", 409)
            source_aliases = json.loads(source["aliases"])
            target_aliases = json.loads(target["aliases"])
            aliases = sorted(set(target_aliases + source_aliases + [source["canonical_name"]]), key=str.casefold)
            now = utcnow()
            conn.execute(
                """UPDATE entities SET aliases=?,frozen=MAX(frozen,?),risk_level=?,version=version+1,updated_at=?
                   WHERE id=?""",
                (json.dumps(aliases, ensure_ascii=False), source["frozen"],
                 "high" if source["frozen"] or target["frozen"] else max(source["risk_level"], target["risk_level"], key=lambda x: {"low": 0, "medium": 1, "high": 2}.get(x, 0)),
                 now, target["id"]),
            )
            conn.execute("UPDATE entities SET merged_into=?,version=version+1,updated_at=? WHERE id=?", (target["id"], now, source["id"]))
            conn.execute("UPDATE customers SET entity_id=?,version=version+1 WHERE entity_id=? AND merged_into IS NULL", (target["id"], source["id"]))
            conn.execute("UPDATE transactions SET entity_id=? WHERE entity_id=?", (target["id"], source["id"]))
            conn.execute("UPDATE alerts SET entity_id=? WHERE entity_id=?", (target["id"], source["id"]))
            conn.execute("UPDATE cases SET entity_id=?,version=version+1,updated_at=? WHERE entity_id=?", (target["id"], now, source["id"]))
            details = {"source": source["canonical_name"], "target": target["canonical_name"], "aliases": aliases}
            conn.execute(
                "INSERT INTO entity_merges(source_id,target_id,actor,details,created_at) VALUES(?,?,?,?,?)",
                (source["id"], target["id"], actor, json.dumps(details, ensure_ascii=False), now),
            )
            self._audit(conn, actor, "entity.merged", details, target["id"])
            return {"source": dict(conn.execute("SELECT * FROM entities WHERE id=?", (source["id"],)).fetchone()),
                    "target": dict(conn.execute("SELECT * FROM entities WHERE id=?", (target["id"],)).fetchone())}

    def file_report(self, actor: str, role: str, case_id: int, report_ref: str,
                    expected_version: int) -> dict[str, Any]:
        actor = clean_actor(actor)
        require_role(role, {"supervisor"}, "提交监管报告")
        if not report_ref.strip():
            raise DomainError("监管报告编号不能为空")
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            case = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
            if not case:
                raise DomainError("案件不存在", 404)
            if case["version"] != int(expected_version):
                raise DomainError("案件已变化，请刷新后重试", 409)
            if case["status"] not in {"investigating", "escalated"}:
                raise DomainError("当前案件状态不能提交监管报告", 409)
            if case["risk_score"] < 0.5:
                raise DomainError("低风险案件不需要监管报告", 409)
            conn.execute(
                "UPDATE cases SET status='report_filed',report_ref=?,version=version+1,updated_at=? WHERE id=?",
                (report_ref.strip(), utcnow(), case_id),
            )
            self._audit(conn, actor, "case.report_filed", {"report_ref": report_ref.strip()}, case["entity_id"], case_id)
            return dict(conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone())

    def get_case(self, actor: str, role: str, case_id: int) -> dict[str, Any]:
        actor = clean_actor(actor)
        if role not in SENSITIVE_ROLES:
            raise DomainError("角色无权查看案件", 403)
        with self.connect() as conn:
            case = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
            if not case:
                raise DomainError("案件不存在", 404)
            self._case_access(actor, role, case)
            notes = [dict(r) for r in conn.execute("SELECT * FROM case_notes WHERE case_id=? ORDER BY id", (case_id,)).fetchall()]
            txn_rows = conn.execute(
                """SELECT DISTINCT t.* FROM transactions t
                   LEFT JOIN alerts a ON a.transaction_id=t.id
                   WHERE a.case_id=? OR (t.entity_id=? AND EXISTS(
                       SELECT 1 FROM screening_archives sa WHERE sa.transaction_id=t.id))
                   ORDER BY t.id""",
                (case_id, case["entity_id"]),
            ).fetchall()
            transactions = [dict(r) for r in txn_rows]
            txn_ids = {t["id"] for t in txn_rows}
            archives = ScreeningArchive(conn).for_transactions(txn_ids)
            reviews = ListReviewQueue(conn).for_transactions(txn_ids)
            for transaction in transactions:
                transaction["screening_archives"] = archives.get(transaction["id"], [])
                transaction["watchlist_reviews"] = reviews.get(transaction["id"], [])
            return {"case": dict(case), "notes": notes, "transactions": transactions}

    def get_watchlist_history(self, actor: str, role: str, entry_id: int) -> dict[str, Any]:
        actor = clean_actor(actor)
        if role not in SENSITIVE_ROLES:
            raise DomainError("角色无权查看名单历史", 403)
        with self.connect() as conn:
            entry = conn.execute("SELECT * FROM watchlist WHERE id=?", (entry_id,)).fetchone()
            if not entry:
                raise DomainError("名单条目不存在", 404)
            return {"entry": dict(entry), "versions": WatchlistHistory(conn).versions(entry_id)}

    def get_transaction_trace(self, actor: str, role: str, transaction_id: int) -> dict[str, Any]:
        actor = clean_actor(actor)
        if role not in SENSITIVE_ROLES:
            raise DomainError("角色无权查看筛查存档", 403)
        with self.connect() as conn:
            transaction = conn.execute("SELECT * FROM transactions WHERE id=?", (transaction_id,)).fetchone()
            if not transaction:
                raise DomainError("交易不存在", 404)
            payload = dict(transaction)
            payload["screening_archives"] = ScreeningArchive(conn).for_transactions({transaction_id}).get(transaction_id, [])
            payload["watchlist_reviews"] = ListReviewQueue(conn).for_transactions({transaction_id}).get(transaction_id, [])
            return payload

    def complete_list_review(self, actor: str, role: str, review_id: int, conclusion: str,
                             note: str = "") -> dict[str, Any]:
        actor = clean_actor(actor)
        require_role(role, {"investigator", "supervisor"}, "复核名单变化")
        if conclusion not in {"confirmed", "false_positive", "escalated"}:
            raise DomainError("复核结论无效（confirmed/false_positive/escalated）")
        note = (note or "").strip()
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            review = conn.execute("SELECT * FROM watchlist_reviews WHERE id=?", (review_id,)).fetchone()
            if not review:
                raise DomainError("待复核记录不存在", 404)
            if review["status"] != ListReviewQueue.PENDING:
                raise DomainError("该版本已复核，同一版本不重复处理", 409)
            transaction = conn.execute("SELECT * FROM transactions WHERE id=?", (review["transaction_id"],)).fetchone()
            now = utcnow()
            current_entry = conn.execute("SELECT * FROM watchlist WHERE id=?", (review["watchlist_entry_id"],)).fetchone()
            score, matched = (0.0, None)
            if current_entry and current_entry["active"]:
                score, matched = self._match_entry(
                    conn, transaction["counterparty_name"], transaction["counterparty_country"]
                )
                if matched is None or matched["id"] != current_entry["id"]:
                    matched, score = None, score
            rescreen = ScreeningArchive(conn).record_rescreen(
                transaction["id"], matched if matched is not None else current_entry,
                score if matched is not None else 0.0, review["id"], actor, now
            )
            alert = None
            if conclusion == "escalated":
                fingerprint = "listreview|%s|%s|%s" % (
                    transaction["entity_id"], review["watchlist_entry_id"], review["to_version"]
                )
                existing = conn.execute("SELECT * FROM alerts WHERE fingerprint=?", (fingerprint,)).fetchone()
                if existing:
                    alert_id = existing["id"]
                else:
                    alert_cur = conn.execute(
                        """INSERT INTO alerts(fingerprint,entity_id,transaction_id,reason,risk_score,first_seen,last_seen,status)
                           VALUES(?,?,?,?,?,?,?,?)""",
                        (fingerprint, transaction["entity_id"], transaction["id"],
                         "watchlist_review:%s:%s" % (current_entry["list_name"] if current_entry else "unknown", review["to_version"]),
                         0.9, now, now, "new"),
                    )
                    alert_id = alert_cur.lastrowid
                alert = dict(conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone())
            conn.execute(
                """UPDATE watchlist_reviews SET status='reviewed',conclusion=?,handled_by=?,handled_at=?,
                   note=?,rescreen_archive_id=? WHERE id=?""",
                (conclusion, actor, now, note, rescreen["id"], review_id),
            )
            self._audit(conn, actor, "watchlist.reviewed",
                        {"review_id": review_id, "transaction_id": transaction["id"],
                         "conclusion": conclusion, "rescreen_hit": matched is not None},
                        transaction["entity_id"])
            return {"review": dict(conn.execute("SELECT * FROM watchlist_reviews WHERE id=?", (review_id,)).fetchone()),
                    "rescreen": rescreen, "alert": alert}

    def state(self, actor: str = "", role: str = "viewer") -> dict[str, Any]:
        if role not in SENSITIVE_ROLES:
            return {"entities": [], "transactions": [], "alerts": [], "cases": [], "timeline": [],
                    "watchlist": [], "watchlist_reviews": [], "pending_review_txn_ids": [],
                    "access_limited": True}
        with self.connect() as conn:
            if role == "investigator":
                cases = [dict(r) for r in conn.execute("SELECT * FROM cases WHERE assignee=? ORDER BY id DESC", (actor,)).fetchall()]
            else:
                cases = [dict(r) for r in conn.execute("SELECT * FROM cases ORDER BY id DESC").fetchall()]
            entities = [dict(r) for r in conn.execute("SELECT * FROM entities ORDER BY id DESC LIMIT 100").fetchall()]
            transactions = [dict(r) for r in conn.execute("SELECT * FROM transactions ORDER BY id DESC LIMIT 100").fetchall()]
            case_ids = [c["id"] for c in cases]
            if role == "investigator" and case_ids:
                marks = ",".join("?" for _ in case_ids)
                alerts = [dict(r) for r in conn.execute("SELECT * FROM alerts WHERE case_id IN (%s) ORDER BY id DESC LIMIT 100" % marks, case_ids).fetchall()]
            elif role == "investigator":
                alerts = []
            else:
                alerts = [dict(r) for r in conn.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 100").fetchall()]
            timeline = [dict(r) for r in conn.execute("SELECT * FROM timeline ORDER BY id DESC LIMIT 200").fetchall()]
            watchlist = [dict(r) for r in conn.execute("SELECT * FROM watchlist ORDER BY id DESC").fetchall()]
            watchlist_reviews = ListReviewQueue(conn).list_all()
            pending_ids = sorted(ListReviewQueue(conn).pending_transaction_ids())
            # 给近期交易标记是否存在待复核
            pending_lookup = set(pending_ids)
            for txn in transactions:
                txn["pending_list_review"] = txn["id"] in pending_lookup
        return {"entities": entities, "transactions": transactions, "alerts": alerts, "cases": cases,
                "timeline": timeline, "watchlist": watchlist, "watchlist_reviews": watchlist_reviews,
                "pending_review_txn_ids": pending_ids, "access_limited": False}

    def seed_demo(self) -> dict[str, Any]:
        with self.connect() as conn:
            if conn.execute("SELECT COUNT(*) AS c FROM entities").fetchone()["c"]:
                return {"seeded": False, "reason": "已有数据"}
        entity = self.create_entity("analyst-demo", "analyst", "organization", "海岳贸易有限公司", ["海岳贸易"])
        customer = self.create_customer("analyst-demo", "analyst", entity["id"], "CUST-0001", "CN", "贸易", False, 0.2)
        self.add_or_update_watchlist("sup-demo", "supervisor", "OFAC", "海岳贸易有限公司", ["CN"])
        result = self.ingest_transaction("analyst-demo", "analyst", "TXN-DEMO-0001", customer["id"], 150000, "USD", "海岳贸易有限公司", "CN")
        return {"seeded": True, "entity_id": entity["id"], "customer_id": customer["id"], "alert_id": result["alert"]["id"] if result["alert"] else None}


class ApiHandler(BaseHTTPRequestHandler):
    service: FinancialCrimeService

    def _send(self, status: int, payload: Any) -> None:
        body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _headers(self) -> tuple[str, str]:
        return self.headers.get("X-User", ""), self.headers.get("X-Role", "viewer")

    def _json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length > 2_000_000:
            raise DomainError("请求体过大", 413)
        if not length:
            return {}
        try:
            value = json.loads(self.rfile.read(length).decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise DomainError("请求体不是有效 JSON") from exc
        if not isinstance(value, dict):
            raise DomainError("JSON 请求体必须是对象")
        return value

    def do_GET(self) -> None:
        try:
            path = urlparse(self.path).path
            if path in {"/", "/index.html"}:
                body = (ROOT / "static" / "index.html").read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if path in {"/app.js", "/static/app.js"}:
                body = (ROOT / "static" / "app.js").read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "application/javascript; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            actor, role = self._headers()
            if path == "/health":
                self._send(200, {"status": "ok", "service": "financial-crime"})
            elif path == "/api/state":
                self._send(200, self.service.state(actor, role))
            elif path.startswith("/api/watchlist/") and path.endswith("/history"):
                self._send(200, self.service.get_watchlist_history(actor, role, int(path.split("/")[3])))
            elif path.startswith("/api/transactions/"):
                self._send(200, self.service.get_transaction_trace(actor, role, int(path.split("/")[3])))
            elif path.startswith("/api/cases/"):
                self._send(200, self.service.get_case(actor, role, int(path.split("/")[3])))
            else:
                self._send(404, {"error": "接口不存在"})
        except DomainError as exc:
            self._send(exc.status, {"error": str(exc)})
        except (ValueError, IndexError) as exc:
            self._send(400, {"error": str(exc)})

    def do_POST(self) -> None:
        try:
            path, data, (actor, role) = urlparse(self.path).path, self._json(), self._headers()
            if path == "/api/entities":
                result = self.service.create_entity(actor, role, **data)
            elif path == "/api/entities/alias":
                result = self.service.add_alias(actor, role, **data)
            elif path == "/api/customers":
                result = self.service.create_customer(actor, role, **data)
            elif path == "/api/watchlist":
                result = self.service.add_or_update_watchlist(actor, role, **data)
            elif path == "/api/transactions":
                result = self.service.ingest_transaction(actor, role, **data)
            elif path == "/api/alerts/triage":
                result = self.service.triage_alert(actor, role, **data)
            elif path == "/api/cases/update":
                result = self.service.update_case(actor, role, **data)
            elif path == "/api/entities/freeze":
                result = self.service.freeze_entity(actor, role, **data)
            elif path == "/api/entities/unfreeze":
                result = self.service.unfreeze_entity(actor, role, **data)
            elif path == "/api/entities/merge":
                result = self.service.merge_entities(actor, role, **data)
            elif path == "/api/cases/report":
                result = self.service.file_report(actor, role, **data)
            elif path == "/api/watchlist/review":
                result = self.service.complete_list_review(actor, role, **data)
            else:
                raise DomainError("接口不存在", 404)
            self._send(201, result)
        except DomainError as exc:
            self._send(exc.status, {"error": str(exc)})
        except (KeyError, TypeError, ValueError) as exc:
            self._send(400, {"error": "请求参数错误: %s" % exc})
        except Exception as exc:
            self._send(500, {"error": "服务器内部错误", "detail": str(exc)})

    def log_message(self, fmt: str, *args: Any) -> None:
        return


def serve(service: FinancialCrimeService, host: str, port: int) -> None:
    ApiHandler.service = service
    server = ThreadingHTTPServer((host, port), ApiHandler)
    print("Financial crime service listening on http://%s:%s" % (host, port))
    server.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser(description="金融犯罪调查与制裁筛查服务")
    parser.add_argument("--db", default=str(DEFAULT_DB))
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8208)
    parser.add_argument("--init", action="store_true")
    parser.add_argument("--seed", action="store_true")
    args = parser.parse_args()
    service = FinancialCrimeService(args.db)
    if args.init:
        print(json.dumps(service.seed_demo() if args.seed else {"initialized": True, "db": args.db}, ensure_ascii=False))
        return
    serve(service, args.host, args.port)


if __name__ == "__main__":
    main()
