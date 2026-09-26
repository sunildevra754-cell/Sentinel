import math
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Tuple
from backend.storage.database import get_db_connection
from backend.config import (
    TRUST_THRESHOLD_HEALTHY,
    TRUST_THRESHOLD_WARNING,
    TRUST_THRESHOLD_QUARANTINE
)

logger = logging.getLogger("sentinel.trust_score")

class TrustScoreEngine:
    def __init__(self, model_id: str):
        self.model_id = model_id
        self.current_score = 98.5
        self.status = "HEALTHY"
        self.throttling_level = "NONE"
        self.auto_approval_threshold = 0.50

    def compute_trust_score(
        self,
        composite_psi: float,
        max_psi: float,
        anomaly_rate: float,
        honeypot_hit_count: int,
        is_attack_active: bool,
        is_rolled_back: bool
    ) -> Tuple[float, str, str, float]:
        """
        Calculates the real-time Model Trust Score (0-100), status, throttling level,
        and required auto-approval confidence threshold.
        """
        if is_rolled_back:
            # If successfully restored to safe checkpoint, score rapidly heals
            self.current_score = min(99.0, self.current_score + 15.0)
            self.status = "ROLLED_BACK_SAFE"
            self.throttling_level = "RECOVERED_STANDARD"
            self.auto_approval_threshold = 0.50
            return round(self.current_score, 1), self.status, self.throttling_level, self.auto_approval_threshold

        # Base score starting at 100
        score = 100.0

        # 1. Drift Penalty (based on max PSI and composite PSI)
        # Normal PSI < 0.10: 0 to 5 penalty
        # Moderate PSI 0.10 - 0.25: 10 to 30 penalty
        # Severe PSI > 0.25: 35 to 65 penalty
        if max_psi < 0.10:
            drift_penalty = max_psi * 30.0  # max ~3.0
        elif max_psi < 0.25:
            drift_penalty = 10.0 + (max_psi - 0.10) / 0.15 * 25.0  # 10 to 35
        else:
            drift_penalty = 35.0 + min(40.0, (max_psi - 0.25) * 60.0)  # 35 to 75

        # 2. Anomaly Rate Penalty (normal anomaly rate ~ 0.05-0.10)
        excess_anomalies = max(0.0, anomaly_rate - 0.12)
        anomaly_penalty = min(25.0, excess_anomalies * 50.0)

        # 3. Honeypot Penalty (direct probing penalty)
        honeypot_penalty = min(35.0, honeypot_hit_count * 20.0)

        # 4. Attack Active Multiplier
        attack_penalty = 15.0 if is_attack_active else 0.0

        # Calculate total score
        total_penalty = drift_penalty + anomaly_penalty + honeypot_penalty + attack_penalty
        score = max(5.0, min(100.0, 100.0 - total_penalty))

        # Smooth changes (exponential moving average)
        alpha = 0.45 if is_attack_active else 0.25
        self.current_score = round(alpha * score + (1.0 - alpha) * self.current_score, 1)

        # Determine Graduated Response & Throttling
        if self.current_score >= TRUST_THRESHOLD_HEALTHY:
            self.status = "HEALTHY"
            self.throttling_level = "NONE"
            self.auto_approval_threshold = 0.50
        elif self.current_score >= 65.0:
            self.status = "WARNING_THROTTLED"
            self.throttling_level = "MODERATE_THROTTLING"
            self.auto_approval_threshold = 0.75  # Require 75% confidence to auto-approve
        elif self.current_score >= TRUST_THRESHOLD_QUARANTINE:
            self.status = "WARNING_THROTTLED"
            self.throttling_level = "STRICT_THROTTLING"
            self.auto_approval_threshold = 0.88  # Require 88% confidence; rest sent for Manual Review
        else:
            self.status = "CRITICAL_QUARANTINE_TRIGGERED"
            self.throttling_level = "FULL_QUARANTINE"
            self.auto_approval_threshold = 1.00

        # Persist to database trust_history
        self._record_history(self.current_score, composite_psi, anomaly_rate)

        return self.current_score, self.status, self.throttling_level, self.auto_approval_threshold

    def _record_history(self, score: float, psi: float, anomaly_rate: float):
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO trust_history (timestamp, model_id, trust_score, psi_score, anomaly_rate, status, throttling_level)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                datetime.now(timezone.utc).isoformat(),
                self.model_id,
                score,
                psi,
                anomaly_rate,
                self.status,
                self.throttling_level
            ))
            conn.commit()
            conn.close()
        except Exception as e:
            logger.debug("Failed recording trust history: %s", e)
