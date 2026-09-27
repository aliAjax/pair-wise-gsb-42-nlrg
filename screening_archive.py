"""筛查存档与名单变更待复核（与名单历史、页面分开实现）。

- `screening_archive`：每次筛查命中时，把命中的名单条目版本快照一并存档；
  即使条目后来被更正/停用，也能还原当时采用的名单版本。
- `watchlist_reviews`：名单条目产生新版本后，所有命中过旧版本的交易自动进入
  待复核；(screening_archive_id, to_version) 唯一约束保证同一版本只生成一次。
  复核处理后保留处理人、结论、说明与时间；记录持久化在 SQLite，重启仍可追查。
"""
from __future__ import annotations

import json
import sqlite3
from typing import Any

from core import DomainError, name_similarity, normalize_name, utcnow
from watchlist_history import WatchlistStore

STATUS_PENDING = "pending"
STATUS_DONE = "done"


class ScreeningStore:
    def __init__(self, watchlist_store: WatchlistStore):
        self.watchlist = watchlist_store

    def init_schema(self, conn: sqlite3.Connection) -> None:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS screening_archive (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                transaction_id INTEGER NOT NULL REFERENCES transactions(id),
                entity_id INTEGER NOT NULL,
                watchlist_entry_id INTEGER NOT NULL,
                entry_version INTEGER NOT NULL,
                list_name TEXT NOT NULL,
                matched_name TEXT NOT NULL,
                countries TEXT NOT NULL DEFAULT '[]',
                entry_active INTEGER NOT NULL,
                change_type TEXT NOT NULL,
                entry_effective_at TEXT NOT NULL,
                match_score REAL NOT NULL,
                screened_at TEXT NOT NULL,
                UNIQUE(transaction_id, watchlist_entry_id, entry_version)
            );
            CREATE TABLE IF NOT EXISTS watchlist_reviews (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                screening_archive_id INTEGER NOT NULL REFERENCES screening_archive(id),
                transaction_id INTEGER NOT NULL REFERENCES transactions(id),
                watchlist_entry_id INTEGER NOT NULL,
                from_version INTEGER NOT NULL,
                to_version INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                reason TEXT NOT NULL DEFAULT '',
                reviewed_by TEXT,
                conclusion TEXT,
                created_at TEXT NOT NULL,
                reviewed_at TEXT,
                UNIQUE(screening_archive_id, to_version)
            );
            CREATE INDEX IF NOT EXISTS idx_sa_txn ON screening_archive(transaction_id);
            CREATE INDEX IF NOT EXISTS idx_wr_status ON watchlist_reviews(status, id);
            CREATE INDEX IF NOT EXISTS idx_wr_txn ON watchlist_reviews(transaction_id);
            """
        )

    # -- 筛查与存档 ---------------------------------------------------------

    def screen(self, conn: sqlite3.Connection, counterparty_name: str, country: str
               ) -> tuple[float, str | None, sqlite3.Row | None]:
        """在当前生效名单中筛查，返回 (分数, 命中原因, 命中条目行)。"""
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
            return 0.95, "sanctions_match:%s:%s" % (best["list_name"], best["name"]), best
        return best_score, None, None

    def archive_hit(self, conn: sqlite3.Connection, transaction_id: int, entity_id: int,
                    entry: sqlite3.Row, score: float, screened_at: str) -> dict[str, Any]:
        """把命中的条目版本快照存档。同一交易/条目/版本只存一份。"""
        version_snap = self.watchlist.get_version(conn, entry["id"], entry["version"])
        if version_snap is None:  # 理论上不会发生：当前态必然有对应版本快照
            raise DomainError("名单条目版本快照缺失", 500)
        conn.execute(
            """INSERT INTO screening_archive(transaction_id,entity_id,watchlist_entry_id,entry_version,
                  list_name,matched_name,countries,entry_active,change_type,entry_effective_at,
                  match_score,screened_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(transaction_id, watchlist_entry_id, entry_version) DO NOTHING""",
            (transaction_id, entity_id, entry["id"], entry["version"], entry["list_name"],
             entry["name"], entry["countries"], entry["active"], version_snap["change_type"],
             version_snap["effective_at"], score, screened_at),
        )
        row = conn.execute(
            "SELECT * FROM screening_archive WHERE transaction_id=? AND watchlist_entry_id=? AND entry_version=?",
            (transaction_id, entry["id"], entry["version"]),
        ).fetchone()
        return dict(row)

    def enqueue_reviews_for_change(self, conn: sqlite3.Connection, entry_id: int,
                                   previous_version: int, new_version: int) -> int:
        """名单条目产生新版本后，受影响的命中交易自动待复核。

        命中版本早于新版本的存档都需要按最新版复核；唯一约束
        (screening_archive_id, to_version) 保证同一版本只生成一次，重复触发安全。
        返回本次新生成的复核任务数。
        """
        if new_version <= previous_version:
            return 0
        cur = conn.execute(
            """INSERT INTO watchlist_reviews(screening_archive_id,transaction_id,watchlist_entry_id,
                  from_version,to_version,reason,created_at)
               SELECT sa.id, sa.transaction_id, sa.watchlist_entry_id, sa.entry_version,
                      ?, 'watchlist_changed', ?
               FROM screening_archive sa
               WHERE sa.watchlist_entry_id=? AND sa.entry_version < ?
               ON CONFLICT(screening_archive_id, to_version) DO NOTHING""",
            (new_version, utcnow(), entry_id, new_version),
        )
        return cur.rowcount

    # -- 复核处理 -----------------------------------------------------------

    def resolve_review(self, conn: sqlite3.Connection, review_id: int, actor: str,
                       conclusion: str, note: str = "") -> dict[str, Any]:
        from core import REVIEW_CONCLUSIONS

        conclusion = (conclusion or "").strip()
        if conclusion not in REVIEW_CONCLUSIONS:
            raise DomainError("复核结论无效")
        row = conn.execute("SELECT * FROM watchlist_reviews WHERE id=?", (review_id,)).fetchone()
        if row is None:
            raise DomainError("复核任务不存在", 404)
        if row["status"] != STATUS_PENDING:
            raise DomainError("该复核任务已处理", 409)
        conn.execute(
            """UPDATE watchlist_reviews SET status=?,reviewed_by=?,conclusion=?,reason=?,reviewed_at=?
               WHERE id=? AND status='pending'""",
            (STATUS_DONE, actor, conclusion, note.strip(), utcnow(), review_id),
        )
        return dict(conn.execute("SELECT * FROM watchlist_reviews WHERE id=?", (review_id,)).fetchone())

    # -- 读取 ---------------------------------------------------------------

    def list_reviews(self, conn: sqlite3.Connection, status: str | None = None) -> list[dict[str, Any]]:
        sql = (
            """SELECT wr.*, t.txn_ref, t.status AS txn_status, t.reason AS txn_reason
               FROM watchlist_reviews wr
               JOIN transactions t ON t.id=wr.transaction_id"""
        )
        params: tuple[Any, ...] = ()
        if status in {STATUS_PENDING, STATUS_DONE}:
            sql += " WHERE wr.status=?"
            params = (status,)
        sql += " ORDER BY wr.id DESC"
        return [dict(r) for r in conn.execute(sql, params).fetchall()]

    def archives_for_entity(self, conn: sqlite3.Connection, entity_id: int) -> list[dict[str, Any]]:
        """案件相关交易采用过的名单版本：存档 + 各版本的复核处理情况。"""
        archives = [dict(r) for r in conn.execute(
            "SELECT * FROM screening_archive WHERE entity_id=? ORDER BY id", (entity_id,)
        ).fetchall()]
        for archive in archives:
            archive["reviews"] = [dict(r) for r in conn.execute(
                "SELECT * FROM watchlist_reviews WHERE screening_archive_id=? ORDER BY id",
                (archive["id"],),
            ).fetchall()]
        return archives
