import hashlib
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Tuple

BASE_DIR = Path(__file__).resolve().parent.parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from backend.storage.database import get_db_connection

logger = logging.getLogger("sentinel.audit_chain")

GENESIS_HASH = "0" * 64

def calculate_hash(prev_hash: str, timestamp: str, event_type: str, model_id: str, details_json: str) -> str:
    """Computes SHA-256 hash for an audit log entry."""
    payload = f"{prev_hash}|{timestamp}|{event_type}|{model_id}|{details_json}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()

def record_audit_event(event_type: str, model_id: str, details: Dict[str, Any]) -> str:
    """
    Appends a new immutable event to the SHA-256 hash-chain audit log.
    Returns the newly generated hash.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    # Get the latest entry's hash
    cursor.execute("SELECT current_hash FROM audit_trail ORDER BY id DESC LIMIT 1")
    row = cursor.fetchone()
    prev_hash = row["current_hash"] if row else GENESIS_HASH

    timestamp = datetime.now(timezone.utc).isoformat()
    details_json = json.dumps(details, sort_keys=True)
    current_hash = calculate_hash(prev_hash, timestamp, event_type, model_id, details_json)

    cursor.execute("""
    INSERT INTO audit_trail (timestamp, event_type, model_id, details_json, prev_hash, current_hash)
    VALUES (?, ?, ?, ?, ?, ?)
    """, (timestamp, event_type, model_id, details_json, prev_hash, current_hash))

    conn.commit()
    conn.close()

    logger.info("Recorded audit event '%s' for model '%s'. Hash: %s", event_type, model_id, current_hash[:16])
    return current_hash

def get_audit_trail(limit: int = 50) -> List[Dict[str, Any]]:
    """Fetches recent audit log entries."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT id, timestamp, event_type, model_id, details_json, prev_hash, current_hash
    FROM audit_trail
    ORDER BY id DESC
    LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()

    results = []
    for r in rows:
        results.append({
            "id": r["id"],
            "timestamp": r["timestamp"],
            "event_type": r["event_type"],
            "model_id": r["model_id"],
            "details": json.loads(r["details_json"]),
            "prev_hash": r["prev_hash"],
            "current_hash": r["current_hash"]
        })
    return results

def verify_chain_integrity() -> Tuple[bool, str, int]:
    """
    Verifies the cryptographic integrity of the entire audit chain.
    Returns (is_valid, message, total_blocks_checked).
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT id, timestamp, event_type, model_id, details_json, prev_hash, current_hash
    FROM audit_trail
    ORDER BY id ASC
    """)
    rows = cursor.fetchall()
    conn.close()

    if not rows:
        return True, "Audit chain is empty. Genesis state valid.", 0

    expected_prev_hash = GENESIS_HASH
    for idx, row in enumerate(rows):
        # 1. Check prev_hash link
        if row["prev_hash"] != expected_prev_hash:
            return False, f"Broken link at block #{row['id']}: expected prev_hash '{expected_prev_hash}', got '{row['prev_hash']}'", idx

        # 2. Recompute current hash
        recomputed = calculate_hash(
            row["prev_hash"],
            row["timestamp"],
            row["event_type"],
            row["model_id"],
            row["details_json"]
        )

        if recomputed != row["current_hash"]:
            return False, f"Data tampering detected in block #{row['id']}! Recomputed '{recomputed[:12]}...' != Stored '{row['current_hash'][:12]}...'", idx

        expected_prev_hash = row["current_hash"]

    return True, f"All {len(rows)} audit blocks verified with 100% cryptographic SHA-256 integrity.", len(rows)
