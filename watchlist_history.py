"""制裁名单与名单版本历史（与筛查存档、页面分开实现）。

- `watchlist`：当前生效条目，`active=0` 表示已停用。
- `watchlist_versions`：只追加（append-only）的版本快照，更正与停用都保留旧版，
  每条快照带 `effective_at` 生效时间，筛查命中的是哪个版本可凭 (entry_id, version) 追溯。
"""
from __future__ import annotations

import json
import sqlite3
from typing import Any

from core import DomainError, normalize_name, utcnow

CHANGE_CREATED = "created"
CHANGE_CORRECTED = "corrected"
CHANGE_DEACTIVATED = "deactivated"


class WatchlistStore:
    def init_schema(self, conn: sqlite3.Connection) -> None:
        conn.executescript(
            """
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
            CREATE TABLE IF NOT EXISTS watchlist_versions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                entry_id INTEGER NOT NULL,
                version INTEGER NOT NULL,
                list_name TEXT NOT NULL,
                name TEXT NOT NULL,
                normalized_name TEXT NOT NULL,
                countries TEXT NOT NULL DEFAULT '[]',
                active INTEGER NOT NULL,
                change_type TEXT NOT NULL,
                effective_at TEXT NOT NULL,
                changed_by TEXT NOT NULL,
                UNIQUE(entry_id, version)
            );
            CREATE INDEX IF NOT EXISTS idx_wv_entry ON watchlist_versions(entry_id, version);
            """
        )

    # -- 写入 ---------------------------------------------------------------

    def upsert(self, conn: sqlite3.Connection, actor: str, list_name: str, name: str,
               countries: list[str] | None = None, active: bool = True,
               expected_version: int | None = None, entry_id: int | None = None) -> dict[str, Any]:
        """新增条目，或在同一条目上做版本化更正/停用。

        没有任何字段变化时拒绝生成新版本；每次真实变更都追加一份不可变快照。
        """
        list_name, name = list_name.strip(), name.strip()
        normalized = normalize_name(name)
        countries_clean = sorted({c.strip().upper() for c in (countries or []) if c.strip()})
        countries_json = json.dumps(countries_clean, ensure_ascii=False)
        if not list_name or not normalized:
            raise DomainError("名单名称和实体名称不能为空")

        row = self._find_entry(conn, entry_id, list_name, normalized)
        now = utcnow()

        if row is None:
            cur = conn.execute(
                """INSERT INTO watchlist(list_name,name,normalized_name,countries,version,active,updated_by,updated_at)
                   VALUES(?,?,?,?,1,?,?,?)""",
                (list_name, name, normalized, countries_json, 1, actor, now),
            )
            entry_id, version = cur.lastrowid, 1
            self._snapshot(conn, entry_id, version, list_name, name, normalized,
                           countries_json, True, CHANGE_CREATED, actor, now)
            return self.current_entry(conn, entry_id)

        entry_id = row["id"]
        if expected_version is not None and row["version"] != int(expected_version):
            raise DomainError("名单条目已变化，请刷新后重试", 409)
        active_flag = int(bool(active))
        same = (
            row["name"] == name
            and row["countries"] == countries_json
            and row["active"] == active_flag
        )
        if same:
            raise DomainError("名单内容没有变化，不生成新版本", 400)
        # 改名后若与同一名单内其他条目冲突，由唯一约束兜底
        if normalized != row["normalized_name"]:
            clash = conn.execute(
                "SELECT id FROM watchlist WHERE id<>? AND list_name=? AND normalized_name=?",
                (entry_id, list_name, normalized),
            ).fetchone()
            if clash:
                raise DomainError("同一名单下已存在该名称条目", 409)
        change_type = CHANGE_DEACTIVATED if row["active"] == 1 and active_flag == 0 else CHANGE_CORRECTED
        version = row["version"] + 1
        conn.execute(
            """UPDATE watchlist SET list_name=?,name=?,normalized_name=?,countries=?,active=?,
                  version=?,updated_by=?,updated_at=? WHERE id=?""",
            (list_name, name, normalized, countries_json, active_flag, version, actor, now, entry_id),
        )
        self._snapshot(conn, entry_id, version, list_name, name, normalized,
                       countries_json, bool(active_flag), change_type, actor, now)
        return self.current_entry(conn, entry_id)

    def _find_entry(self, conn: sqlite3.Connection, entry_id: int | None,
                    list_name: str, normalized: str) -> sqlite3.Row | None:
        if entry_id is not None:
            return conn.execute("SELECT * FROM watchlist WHERE id=?", (int(entry_id),)).fetchone()
        return conn.execute(
            "SELECT * FROM watchlist WHERE list_name=? AND normalized_name=?",
            (list_name, normalized),
        ).fetchone()

    def _snapshot(self, conn: sqlite3.Connection, entry_id: int, version: int, list_name: str,
                  name: str, normalized: str, countries_json: str, active: bool,
                  change_type: str, actor: str, effective_at: str) -> None:
        conn.execute(
            """INSERT INTO watchlist_versions(entry_id,version,list_name,name,normalized_name,
                  countries,active,change_type,effective_at,changed_by)
               VALUES(?,?,?,?,?,?,?,?,?,?)""",
            (entry_id, version, list_name, name, normalized, countries_json,
             int(bool(active)), change_type, effective_at, actor),
        )

    # -- 读取 ---------------------------------------------------------------

    def current_entry(self, conn: sqlite3.Connection, entry_id: int) -> dict[str, Any]:
        row = conn.execute("SELECT * FROM watchlist WHERE id=?", (entry_id,)).fetchone()
        if row is None:
            raise DomainError("名单条目不存在", 404)
        return dict(row)

    def get_version(self, conn: sqlite3.Connection, entry_id: int, version: int) -> dict[str, Any] | None:
        row = conn.execute(
            "SELECT * FROM watchlist_versions WHERE entry_id=? AND version=?",
            (entry_id, version),
        ).fetchone()
        return dict(row) if row else None

    def versions_of(self, conn: sqlite3.Connection, entry_id: int) -> list[dict[str, Any]]:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM watchlist_versions WHERE entry_id=? ORDER BY version", (entry_id,)
        ).fetchall()]

    def history_view(self, conn: sqlite3.Connection) -> list[dict[str, Any]]:
        """名单历史回看：每个条目当前态 + 全部旧版（按版本升序）。"""
        entries = [dict(r) for r in conn.execute(
            "SELECT * FROM watchlist ORDER BY list_name, id"
        ).fetchall()]
        versions = [dict(r) for r in conn.execute(
            "SELECT * FROM watchlist_versions ORDER BY entry_id, version"
        ).fetchall()]
        grouped: dict[int, list[dict[str, Any]]] = {}
        for snap in versions:
            grouped.setdefault(snap["entry_id"], []).append(snap)
        result = []
        for entry in entries:
            item = dict(entry)
            item["versions"] = grouped.get(entry["id"], [])
            result.append(item)
        return result
