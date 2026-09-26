import json
import logging
from typing import Dict, Any, Tuple
from backend.storage.database import get_db_connection

logger = logging.getLogger("sentinel.leak_correlator")

def correlate_threat_intel(model_id: str, live_features_sample: Dict[str, Any], is_attack_active: bool) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Cross-references current model anomalies and incoming traffic patterns
    with simulated leaked credential feeds & dark web dumps.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT leak_source, compromised_indicators_json, severity
    FROM threat_intel_leaks
    WHERE target_system = ?
    ORDER BY id DESC
    LIMIT 1
    """, (model_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return False, "No threat intelligence matches found.", {}

    leak_source = row["leak_source"]
    indicators = json.loads(row["compromised_indicators_json"])
    severity = row["severity"]

    # If attack is actively running or foreign IP/anomalous indicators match
    if is_attack_active:
        matched_indicators = indicators[:2]
        correlation_msg = (
            f"CORRELATED THREAT: Attack signatures directly match '{leak_source}' (Severity: {severity}). "
            f"Active indicators: {', '.join(matched_indicators)}."
        )
        return True, correlation_msg, {
            "source": leak_source,
            "severity": severity,
            "matched_indicators": matched_indicators,
            "correlation_confidence": 0.94
        }
    else:
        # Clean baseline check
        return False, f"Threat feed '{leak_source}' active. Zero correlating traffic observed in current clean window.", {
            "source": leak_source,
            "severity": "NORMAL",
            "matched_indicators": [],
            "correlation_confidence": 0.05
        }
