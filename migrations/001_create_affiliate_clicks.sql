-- Migration: create affiliate_clicks table
-- Mirrors schema used by analytics/affiliate_tracking.py

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
