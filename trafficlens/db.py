"""SQLite: задачи анализа, индикаторы компрометации, состояние источников."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    source TEXT NOT NULL,            -- upload | capture | cli
    filename TEXT NOT NULL,
    pcap_path TEXT NOT NULL,
    size INTEGER DEFAULT 0,
    created REAL NOT NULL,
    started REAL,
    finished REAL,
    status TEXT NOT NULL,            -- queued | running | done | error
    stage TEXT DEFAULT '',
    error TEXT DEFAULT '',
    summary TEXT DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS jobs_status ON jobs(status);
CREATE TABLE IF NOT EXISTS iocs (
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    source TEXT NOT NULL,
    info TEXT DEFAULT '',
    tags TEXT DEFAULT '',
    confidence INTEGER DEFAULT 0,
    port INTEGER,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    PRIMARY KEY (type, value, source)
);
CREATE INDEX IF NOT EXISTS iocs_value ON iocs(value);
CREATE TABLE IF NOT EXISTS feeds (
    name TEXT PRIMARY KEY,
    updated REAL,
    ok INTEGER,
    count INTEGER DEFAULT 0,
    message TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS marks (
    job_id TEXT NOT NULL,
    kind TEXT NOT NULL,        -- ioc | alert | file | beacon | upload | cleartext | unusual | tls | dns
    key TEXT NOT NULL,         -- стабильный идентификатор находки (см. markup.py)
    status TEXT NOT NULL,      -- confirmed | false_positive | ignored
    note TEXT DEFAULT '',
    updated REAL NOT NULL,
    PRIMARY KEY (job_id, kind, key)
);
CREATE TABLE IF NOT EXISTS allowlist (
    kind TEXT NOT NULL,
    key TEXT NOT NULL,
    note TEXT DEFAULT '',
    added REAL NOT NULL,
    PRIMARY KEY (kind, key)
);
"""

_local = threading.local()


class DB:
    def __init__(self, path: Path):
        self.path = str(path)
        with self.conn() as c:
            c.executescript(SCHEMA)

    @contextmanager
    def conn(self):
        c = sqlite3.connect(self.path, timeout=60)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA synchronous=NORMAL")
        try:
            yield c
            c.commit()
        finally:
            c.close()

    # ---------- jobs ----------
    def add_job(self, job_id: str, source: str, filename: str, pcap_path: str, size: int, status: str = "queued") -> None:
        with self.conn() as c:
            c.execute(
                "INSERT INTO jobs(id, source, filename, pcap_path, size, created, status, started) VALUES (?,?,?,?,?,?,?,?)",
                (job_id, source, filename, pcap_path, size, time.time(), status, time.time() if status == "running" else None),
            )

    def job(self, job_id: str) -> dict | None:
        with self.conn() as c:
            r = c.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        return _job(r) if r else None

    def jobs(self, limit: int = 200) -> list[dict]:
        with self.conn() as c:
            rows = c.execute("SELECT * FROM jobs ORDER BY created DESC LIMIT ?", (limit,)).fetchall()
        return [_job(r) for r in rows]

    def claim_next(self) -> dict | None:
        with self.conn() as c:
            c.execute("BEGIN IMMEDIATE")
            r = c.execute("SELECT * FROM jobs WHERE status='queued' ORDER BY created LIMIT 1").fetchone()
            if not r:
                return None
            c.execute("UPDATE jobs SET status='running', started=?, stage='', error='' WHERE id=?", (time.time(), r["id"]))
        return self.job(r["id"])

    def update_job(self, job_id: str, **fields) -> None:
        if "summary" in fields and not isinstance(fields["summary"], str):
            fields["summary"] = json.dumps(fields["summary"], ensure_ascii=False)
        sets = ", ".join(f"{k}=?" for k in fields)
        with self.conn() as c:
            c.execute(f"UPDATE jobs SET {sets} WHERE id=?", (*fields.values(), job_id))

    def delete_job(self, job_id: str) -> None:
        with self.conn() as c:
            c.execute("DELETE FROM jobs WHERE id=?", (job_id,))
            c.execute("DELETE FROM marks WHERE job_id=?", (job_id,))

    def reset_running(self) -> None:
        with self.conn() as c:
            c.execute("UPDATE jobs SET status='queued', stage='' WHERE status='running'")

    # ---------- feeds ----------
    def set_feed(self, name: str, ok: bool, count: int, message: str = "") -> None:
        with self.conn() as c:
            c.execute(
                "INSERT INTO feeds(name, updated, ok, count, message) VALUES (?,?,?,?,?) "
                "ON CONFLICT(name) DO UPDATE SET updated=excluded.updated, ok=excluded.ok, count=excluded.count, message=excluded.message",
                (name, time.time(), int(ok), count, message[:500]),
            )

    def feeds(self) -> dict[str, dict]:
        with self.conn() as c:
            return {r["name"]: dict(r) for r in c.execute("SELECT * FROM feeds")}

    # ---------- разметка аналитика ----------
    def set_mark(self, job_id: str, kind: str, key: str, status: str, note: str = "") -> None:
        with self.conn() as c:
            if status == "new":  # «новая» = без разметки, строку удаляем
                c.execute("DELETE FROM marks WHERE job_id=? AND kind=? AND key=?", (job_id, kind, key))
            else:
                c.execute(
                    "INSERT INTO marks(job_id, kind, key, status, note, updated) VALUES (?,?,?,?,?,?) "
                    "ON CONFLICT(job_id, kind, key) DO UPDATE SET status=excluded.status, note=excluded.note, updated=excluded.updated",
                    (job_id, kind, key, status, note[:300], time.time()),
                )

    def marks_for(self, job_id: str) -> dict[tuple[str, str], dict]:
        with self.conn() as c:
            return {(r["kind"], r["key"]): {"status": r["status"], "note": r["note"]}
                    for r in c.execute("SELECT kind, key, status, note FROM marks WHERE job_id=?", (job_id,))}

    def marks_count(self, job_id: str) -> int:
        with self.conn() as c:
            return c.execute("SELECT COUNT(*) FROM marks WHERE job_id=?", (job_id,)).fetchone()[0]

    # ---------- allowlist (глобальный, для всех задач) ----------
    def allow_add(self, kind: str, key: str, note: str = "") -> None:
        with self.conn() as c:
            c.execute(
                "INSERT INTO allowlist(kind, key, note, added) VALUES (?,?,?,?) "
                "ON CONFLICT(kind, key) DO UPDATE SET note=excluded.note",
                (kind, key, note[:300], time.time()),
            )

    def allow_del(self, kind: str, key: str) -> None:
        with self.conn() as c:
            c.execute("DELETE FROM allowlist WHERE kind=? AND key=?", (kind, key))

    def allowlist(self) -> dict[tuple[str, str], str]:
        with self.conn() as c:
            return {(r["kind"], r["key"]): r["note"] for r in c.execute("SELECT kind, key, note FROM allowlist")}


def _job(r: sqlite3.Row) -> dict:
    d = dict(r)
    try:
        d["summary"] = json.loads(d.get("summary") or "{}")
    except ValueError:
        d["summary"] = {}
    return d
