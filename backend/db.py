"""SQLite persistence for anonymous scam reports, sliding-window rate limits, and 7-day trends."""

from __future__ import annotations

import os
import sqlite3
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import TypedDict

DEFAULT_DB_PATH = str(Path(__file__).resolve().parent / "kashf.db")
SECONDS_IN_DAY = 86400
DEDUP_WINDOW_SECONDS = SECONDS_IN_DAY
TRENDING_DAYS = 7

VALID_CATEGORIES = {
    "phishing_bank",
    "fake_prize",
    "fake_delivery",
    "investment_fraud",
    "otp_theft",
    "fake_job",
    "other",
}


class TrendingItem(TypedDict):
    category: str
    count: int
    avg_score: int
    daily: list[int]


def get_db_path() -> str:
    """Return active SQLite database path from KASHF_DB_PATH env var or writable default path."""
    override = os.environ.get("KASHF_DB_PATH")
    if override:
        return override
    default_path = Path(DEFAULT_DB_PATH)
    parent_writable = os.access(default_path.parent, os.W_OK)
    file_writable = (not default_path.exists()) or os.access(default_path, os.W_OK)
    if parent_writable and file_writable:
        return DEFAULT_DB_PATH
    return str(Path(tempfile.gettempdir()) / "kashf.db")


def get_connection(db_path: str | None = None) -> sqlite3.Connection:
    """Open a configured SQLite connection with WAL mode and foreign keys enabled."""
    conn = sqlite3.connect(db_path or get_db_path(), timeout=15.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


@contextmanager
def open_db(db_path: str | None = None) -> Iterator[sqlite3.Connection]:
    """Yield an open SQLite connection and always close it cleanly on exit (safe on Windows WAL)."""
    conn = get_connection(db_path)
    try:
        yield conn
    finally:
        conn.close()


@contextmanager
def db_transaction(db_path: str | None = None) -> Iterator[sqlite3.Connection]:
    """Run an immediate write transaction, rolling back on errors and always closing the handle."""
    conn = get_connection(db_path)
    try:
        conn.execute("BEGIN IMMEDIATE")
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(db_path: str | None = None) -> None:
    """Create core tables and indexes if they do not exist."""
    with open_db(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fingerprint TEXT NOT NULL,
                category TEXT NOT NULL,
                score INTEGER NOT NULL,
                ts REAL NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_reports_ts ON reports(ts)")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS rate_limits (
                key TEXT NOT NULL,
                ts REAL NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_rate_limits_key_ts ON rate_limits(key, ts)")
        conn.commit()


def check_rate_limit(
    key: str,
    max_requests: int = 30,
    window_seconds: float = 60.0,
    now: float | None = None,
    db_path: str | None = None,
) -> bool:
    """Sliding-window persistent rate limiter in SQLite. Returns True if request is allowed."""
    init_db(db_path)
    clean_key = (key or "unknown").strip()[:128] or "unknown"
    ts_now = now if now is not None else time.time()
    cutoff = ts_now - window_seconds

    with db_transaction(db_path) as conn:
        conn.execute(
            "DELETE FROM rate_limits WHERE key = ? AND ts < ?",
            (clean_key, cutoff),
        )
        row = conn.execute(
            "SELECT COUNT(*) AS cnt FROM rate_limits WHERE key = ? AND ts >= ?",
            (clean_key, cutoff),
        ).fetchone()
        count = int(row["cnt"]) if row else 0
        if count >= max_requests:
            return False

        conn.execute(
            "INSERT INTO rate_limits (key, ts) VALUES (?, ?)",
            (clean_key, ts_now),
        )
        conn.execute(
            "DELETE FROM rate_limits WHERE ts < ?",
            (ts_now - (window_seconds * 2.0),),
        )
        return True


def save_report(
    category: str,
    score: int,
    fingerprint: str,
    now: float | None = None,
    db_path: str | None = None,
) -> dict[str, bool]:
    """Save an anonymous report; deduplicate identical fingerprints within 24 hours."""
    init_db(db_path)
    ts_now = now if now is not None else time.time()
    clean_category = category if category in VALID_CATEGORIES else "other"
    clean_score = max(0, min(100, int(score)))
    clean_fp = (fingerprint or "").strip().lower()[:16]
    if not clean_fp:
        raise ValueError("fingerprint is required")

    cutoff = ts_now - DEDUP_WINDOW_SECONDS
    with db_transaction(db_path) as conn:
        existing = conn.execute(
            "SELECT id FROM reports WHERE fingerprint = ? AND ts >= ? LIMIT 1",
            (clean_fp, cutoff),
        ).fetchone()

        if existing is not None:
            return {"ok": True, "deduplicated": True}

        conn.execute(
            "INSERT INTO reports (fingerprint, category, score, ts) VALUES (?, ?, ?, ?)",
            (clean_fp, clean_category, clean_score, ts_now),
        )
    return {"ok": True, "deduplicated": False}


def _aggregate_trending_rows(rows: list[sqlite3.Row], ts_now: float) -> list[TrendingItem]:
    counts: dict[str, int] = {}
    score_sums: dict[str, int] = {}
    daily_buckets: dict[str, list[int]] = {}

    for row in rows:
        cat = str(row["category"])
        if cat not in counts:
            counts[cat] = 0
            score_sums[cat] = 0
            daily_buckets[cat] = [0] * TRENDING_DAYS

        counts[cat] += 1
        score_sums[cat] += int(row["score"])
        days_ago = int((ts_now - float(row["ts"])) // SECONDS_IN_DAY)
        bucket = max(0, min(TRENDING_DAYS - 1, (TRENDING_DAYS - 1) - days_ago))
        daily_buckets[cat][bucket] += 1

    results: list[TrendingItem] = [
        {
            "category": cat,
            "count": count,
            "avg_score": round(score_sums[cat] / count) if count > 0 else 0,
            "daily": daily_buckets[cat],
        }
        for cat, count in counts.items()
    ]
    results.sort(key=lambda item: item["count"], reverse=True)
    return results


def get_trending(
    now: float | None = None,
    db_path: str | None = None,
) -> list[TrendingItem]:
    """Return last-7-days report counts and daily sparkline buckets per category."""
    init_db(db_path)
    ts_now = now if now is not None else time.time()
    window_start = ts_now - (TRENDING_DAYS * SECONDS_IN_DAY)

    with open_db(db_path) as conn:
        rows = conn.execute(
            "SELECT category, score, ts FROM reports WHERE ts >= ? ORDER BY ts ASC",
            (window_start,),
        ).fetchall()

    return _aggregate_trending_rows(rows, ts_now)


def get_community_stats(
    now: float | None = None,
    db_path: str | None = None,
) -> dict[str, object]:
    """Return high-level 7-day community statistics without exposing message contents."""
    items = get_trending(now=now, db_path=db_path)
    total_reports = sum(item["count"] for item in items)
    if total_reports == 0:
        return {
            "total_reports": 0,
            "active_categories": 0,
            "avg_score": 0,
            "top_category": None,
        }

    weighted_sum = sum(item["count"] * item["avg_score"] for item in items)
    return {
        "total_reports": total_reports,
        "active_categories": len(items),
        "avg_score": round(weighted_sum / total_reports),
        "top_category": items[0]["category"],
    }
