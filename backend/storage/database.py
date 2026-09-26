import sqlite3
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from backend.config import DB_PATH

logger = logging.getLogger("sentinel.storage")

def get_db_connection():
    """Returns a SQLite connection with row factory enabled."""
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes SQLite tables for Sentinel storage."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Audit Trail Table (SHA-256 Hash Chaining)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_trail (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        event_type TEXT NOT NULL,
        model_id TEXT NOT NULL,
        details_json TEXT NOT NULL,
        prev_hash TEXT NOT NULL,
        current_hash TEXT NOT NULL
    )
    """)

    # 2. Incidents Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        model_id TEXT NOT NULL,
        incident_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        drift_score_psi REAL,
        trust_score_at_event REAL,
        english_alert TEXT NOT NULL,
        hindi_alert TEXT NOT NULL,
        shap_summary TEXT,
        leak_correlated INTEGER DEFAULT 0,
        leak_details TEXT,
        action_taken TEXT NOT NULL
    )
    """)

    # 3. Transactions / Predictions Log
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        model_id TEXT NOT NULL,
        input_features_json TEXT NOT NULL,
        raw_prediction INTEGER NOT NULL,
        confidence REAL NOT NULL,
        throttled_decision TEXT NOT NULL,
        honeypot_triggered INTEGER DEFAULT 0,
        drift_flag INTEGER DEFAULT 0
    )
    """)

    # 4. Trust History Time Series
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS trust_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        model_id TEXT NOT NULL,
        trust_score REAL NOT NULL,
        psi_score REAL NOT NULL,
        anomaly_rate REAL NOT NULL,
        status TEXT NOT NULL,
        throttling_level TEXT NOT NULL
    )
    """)

    # 5. Simulated Leaked Credentials / Dark Web Threat Intel
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS threat_intel_leaks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        leak_source TEXT NOT NULL,
        target_system TEXT NOT NULL,
        compromised_indicators_json TEXT NOT NULL,
        severity TEXT NOT NULL
    )
    """)

    conn.commit()

    # Seed threat intel if empty
    cursor.execute("SELECT COUNT(*) FROM threat_intel_leaks")
    if cursor.fetchone()[0] == 0:
        seed_threat_intel(conn)

    conn.close()
    logger.info("Database initialized successfully at %s", DB_PATH)

def seed_threat_intel(conn):
    cursor = conn.cursor()
    samples = [
        (
            datetime.now(timezone.utc).isoformat(),
            "DarkWeb Breach - ShadowForum Dump v4",
            "model_fraud",
            json.dumps(["FOREIGN_IP_CLUSTER_RU_88", "DEVICE_FINGERPRINT_EMULATOR_X9", "BIN_401288_COMPROMISED"]),
            "HIGH"
        ),
        (
            datetime.now(timezone.utc).isoformat(),
            "Pastebin Dump - Synthesized KYC PII",
            "model_kyc",
            json.dumps(["SYNTHETIC_INCOME_TEMPLATES_V2", "FORGED_UTILITY_PROVIDER_DELTA", "BUREAU_ID_MASK_RANGE_7"]),
            "CRITICAL"
        )
    ]
    cursor.executemany("""
    INSERT INTO threat_intel_leaks (timestamp, leak_source, target_system, compromised_indicators_json, severity)
    VALUES (?, ?, ?, ?, ?)
    """, samples)
    conn.commit()

if __name__ == "__main__":
    init_db()
