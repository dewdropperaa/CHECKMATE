"""Lightweight affiliate click tracking using SQLite.

Stores click events with vulnerability context for analytics and A/B testing.
"""
import os
import sqlite3
from datetime import datetime
from typing import Dict, List, Optional

DB_PATH = os.path.join(os.path.dirname(__file__), "affiliate_analytics.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS affiliate_clicks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    affiliate_key TEXT NOT NULL,
    vulnerability_type TEXT,
    target_url TEXT,
    user_agent TEXT,
    ip_address TEXT,
    device TEXT,
    campaign TEXT,
    conversion_amount REAL,
    meta JSON
);

CREATE INDEX IF NOT EXISTS idx_affiliate_key ON affiliate_clicks(affiliate_key);
CREATE INDEX IF NOT EXISTS idx_created_at ON affiliate_clicks(created_at);
"""


def _get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = _get_conn()
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()


def log_click(event: Dict[str, Optional[str]]) -> None:
    """Persist an affiliate click event."""
    init_db()
    conn = _get_conn()
    try:
        conn.execute(
            """
            INSERT INTO affiliate_clicks (
                created_at, affiliate_key, vulnerability_type, target_url,
                user_agent, ip_address, device, campaign, conversion_amount, meta
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.utcnow().isoformat(),
                event.get("affiliate_key"),
                event.get("vulnerability_type"),
                event.get("target_url"),
                event.get("user_agent"),
                event.get("ip_address"),
                event.get("device"),
                event.get("campaign"),
                event.get("conversion_amount"),
                event.get("meta"),
            ),
        )
        conn.commit()
    finally:
        conn.close()


def get_summary() -> Dict[str, any]:
    init_db()
    conn = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT affiliate_key, COUNT(*) AS clicks,
                   SUM(CASE WHEN conversion_amount IS NOT NULL THEN 1 ELSE 0 END) AS conversions,
                   SUM(conversion_amount) AS revenue
            FROM affiliate_clicks
            GROUP BY affiliate_key
            ORDER BY clicks DESC
            """
        )
        rows = cur.fetchall()
        leaderboard = [dict(row) for row in rows]

        cur.execute("SELECT COUNT(*) AS total_clicks FROM affiliate_clicks")
        total_clicks = cur.fetchone()["total_clicks"]

        cur.execute(
            """
            SELECT vulnerability_type, COUNT(*) as clicks
            FROM affiliate_clicks
            GROUP BY vulnerability_type
            ORDER BY clicks DESC
            """
        )
        vuln_perf = [dict(row) for row in cur.fetchall()]

        return {
            "total_clicks": total_clicks,
            "affiliates": leaderboard,
            "vulnerability_performance": vuln_perf,
        }
    finally:
        conn.close()
