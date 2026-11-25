"""SQLite-backed Tamper-Evident SHA-256 Local Hash Chain for academic research certificates."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from typing import Any

from db import db_transaction, get_community_stats, init_db, open_db

GENESIS_PREV_HASH = "0" * 64
DEFAULT_INSTITUTION = "الجامعة التكنولوجية / University of Technology"


def _init_ledger_table(db_path: str | None = None) -> None:
    """Create the certificate hash-chain table if it does not yet exist."""
    init_db(db_path)
    with open_db(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ledger_blocks (
                block_index INTEGER PRIMARY KEY AUTOINCREMENT,
                cert_id TEXT UNIQUE NOT NULL,
                title TEXT NOT NULL,
                author TEXT NOT NULL,
                institution TEXT NOT NULL,
                originality_score INTEGER NOT NULL,
                doc_hash TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                block_hash TEXT NOT NULL,
                ts REAL NOT NULL
            )
            """
        )
        conn.commit()


def _compute_block_hash(
    cert_id: str,
    title: str,
    author: str,
    institution: str,
    originality_score: int,
    doc_hash: str,
    prev_hash: str,
    ts: float,
) -> str:
    """Compute canonical SHA-256 digest linking block fields to the previous block hash."""
    payload = json.dumps(
        {
            "cert_id": cert_id,
            "title": title,
            "author": author,
            "institution": institution,
            "originality_score": originality_score,
            "doc_hash": doc_hash,
            "prev_hash": prev_hash,
            "ts": round(ts, 6),
        },
        sort_keys=True,
        ensure_ascii=False,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def issue_certificate(
    title: str,
    author: str,
    institution: str,
    text: str,
    originality_score: int,
    db_path: str | None = None,
) -> dict[str, Any]:
    """Append a tamper-evident authenticity certificate block to the SQLite hash chain."""
    _init_ledger_table(db_path)
    clean_title = (title or "").strip()[:160]
    clean_author = (author or "").strip()[:100]
    clean_inst = (institution or "").strip()[:120] or DEFAULT_INSTITUTION
    clean_score = max(0, min(100, int(originality_score)))
    if not clean_title or not clean_author:
        raise ValueError("Title and author are required")

    doc_hash = hashlib.sha256((text or "").strip().encode("utf-8")).hexdigest()
    ts = time.time()

    with db_transaction(db_path) as conn:
        # Read latest block inside BEGIN IMMEDIATE so concurrent writers cannot fork prev_hash.
        last_row = conn.execute(
            "SELECT block_index, block_hash FROM ledger_blocks ORDER BY block_index DESC LIMIT 1"
        ).fetchone()
        prev_hash = str(last_row["block_hash"]) if last_row else GENESIS_PREV_HASH
        next_num = (int(last_row["block_index"]) + 1) if last_row else 1
        cert_id = f"ACAD-{next_num:04d}-{doc_hash[:6].upper()}"

        block_hash = _compute_block_hash(
            cert_id,
            clean_title,
            clean_author,
            clean_inst,
            clean_score,
            doc_hash,
            prev_hash,
            ts,
        )

        conn.execute(
            """
            INSERT INTO ledger_blocks
            (cert_id, title, author, institution, originality_score, doc_hash, prev_hash, block_hash, ts)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                cert_id,
                clean_title,
                clean_author,
                clean_inst,
                clean_score,
                doc_hash,
                prev_hash,
                block_hash,
                ts,
            ),
        )
        inserted = conn.execute(
            "SELECT * FROM ledger_blocks WHERE cert_id = ?",
            (cert_id,),
        ).fetchone()

    return _row_to_dict(inserted)


def verify_certificate(query: str, db_path: str | None = None) -> dict[str, Any]:
    """Verify a certificate by cert_id or block_hash and confirm cryptographic chain validity."""
    _init_ledger_table(db_path)
    q = (query or "").strip()
    if not q:
        return {"found": False, "chain_valid": verify_chain_integrity(db_path)}

    with open_db(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM ledger_blocks WHERE UPPER(cert_id) = UPPER(?) OR block_hash = ? OR doc_hash = ? LIMIT 1",
            (q, q.lower(), q.lower()),
        ).fetchone()

    if row is None:
        return {"found": False, "chain_valid": verify_chain_integrity(db_path)}

    cert = _row_to_dict(row)
    expected_hash = _compute_block_hash(
        cert["cert_id"],
        cert["title"],
        cert["author"],
        cert["institution"],
        cert["originality_score"],
        cert["doc_hash"],
        cert["prev_hash"],
        cert["ts"],
    )
    return {
        "found": True,
        "hash_valid": expected_hash == cert["block_hash"],
        "chain_valid": verify_chain_integrity(db_path),
        "certificate": cert,
    }


def verify_chain_integrity(db_path: str | None = None) -> bool:
    """Walk all blocks and ensure prev_hash links and SHA-256 digests are unbroken."""
    _init_ledger_table(db_path)
    with open_db(db_path) as conn:
        rows = conn.execute("SELECT * FROM ledger_blocks ORDER BY block_index ASC").fetchall()

    expected_prev = GENESIS_PREV_HASH
    for row in rows:
        cert = _row_to_dict(row)
        if cert["prev_hash"] != expected_prev:
            return False
        recomputed = _compute_block_hash(
            cert["cert_id"],
            cert["title"],
            cert["author"],
            cert["institution"],
            cert["originality_score"],
            cert["doc_hash"],
            cert["prev_hash"],
            cert["ts"],
        )
        if recomputed != cert["block_hash"]:
            return False
        expected_prev = cert["block_hash"]
    return True


def list_certificates(limit: int = 10, db_path: str | None = None) -> list[dict[str, Any]]:
    """Return the most recently issued certificates."""
    _init_ledger_table(db_path)
    with open_db(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM ledger_blocks ORDER BY block_index DESC LIMIT ?",
            (max(1, min(50, limit)),),
        ).fetchall()
    return [_row_to_dict(r) for r in rows]


def get_dashboard_summary(db_path: str | None = None) -> dict[str, Any]:
    """Return combined AcadShield executive metrics from SQLite."""
    _init_ledger_table(db_path)
    cyber_stats = get_community_stats(db_path=db_path)
    with open_db(db_path) as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS cnt, AVG(originality_score) AS avg_orig FROM ledger_blocks"
        ).fetchone()
    cert_count = int(row["cnt"]) if row else 0
    avg_orig = round(float(row["avg_orig"])) if row and row["avg_orig"] is not None else 0

    return {
        "cyber_reports": cyber_stats.get("total_reports", 0),
        "cyber_avg_risk": cyber_stats.get("avg_score", 0),
        "top_threat_category": cyber_stats.get("top_category"),
        "certificates_issued": cert_count,
        "avg_originality": avg_orig,
        "chain_valid": verify_chain_integrity(db_path),
        "recent_certificates": list_certificates(limit=6, db_path=db_path),
    }


def _row_to_dict(row: sqlite3.Row | None) -> dict[str, Any]:
    if row is None:
        return {}
    return {
        "block_index": int(row["block_index"]),
        "cert_id": str(row["cert_id"]),
        "title": str(row["title"]),
        "author": str(row["author"]),
        "institution": str(row["institution"]),
        "originality_score": int(row["originality_score"]),
        "doc_hash": str(row["doc_hash"]),
        "prev_hash": str(row["prev_hash"]),
        "block_hash": str(row["block_hash"]),
        "ts": float(row["ts"]),
    }
