import os
import joblib
import json
import logging
from collections import deque
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
import pandas as pd
import numpy as np

from backend.config import (
    CHECKPOINTS_DIR,
    MODEL_FRAUD_ID,
    MODEL_KYC_ID,
    MODEL_METADATA,
    TRUST_THRESHOLD_QUARANTINE,
    DRIFT_WINDOW_SIZE
)
from backend.engine.drift_detector import calculate_feature_drift
from backend.engine.explainability import ModelExplainer
from backend.engine.honeypot import inspect_for_honeypots
from backend.engine.leak_correlator import correlate_threat_intel
from backend.engine.trust_score import TrustScoreEngine
from backend.engine.vernacular import translate_alert
from backend.storage.audit_chain import record_audit_event
from backend.storage.database import get_db_connection

logger = logging.getLogger("sentinel.registry")

class ManagedModel:
    def __init__(self, model_id: str):
        self.model_id = model_id
        self.meta = MODEL_METADATA[model_id]
        self.features = self.meta["features"]
        self.target = self.meta["target"]
        
        self.active_version = "v1.0.0_clean"
        self.status = "HEALTHY"
        self.is_quarantined = False
        self.is_rolled_back = False
        
        # Load Clean Baseline Checkpoint
        self.clean_model_path = CHECKPOINTS_DIR / f"{model_id}_clean_v1.joblib"
        self.baseline_csv_path = CHECKPOINTS_DIR / f"baseline_{model_id}.csv"
        
        if not self.clean_model_path.exists() or not self.baseline_csv_path.exists():
            raise FileNotFoundError(f"Model artifacts not found for {model_id}. Run train_models.py first.")
            
        self.clean_model = joblib.load(self.clean_model_path)
        self.current_model = self.clean_model
        self.baseline_df = pd.read_csv(self.baseline_csv_path)
        
        # Initialize Engines
        self.explainer = ModelExplainer(self.current_model, self.baseline_df, self.features)
        self.trust_engine = TrustScoreEngine(model_id)
        
        # Rolling Data Buffers
        self.rolling_window = deque(maxlen=DRIFT_WINDOW_SIZE)
        self.recent_transactions = deque(maxlen=30)
        self.recent_anomalies = deque(maxlen=50)
        self.honeypot_triggers = deque(maxlen=20)
        
        self.last_drift_result: Dict[str, Any] = {
            "composite_psi": 0.01,
            "max_psi": 0.02,
            "max_drifting_feature": self.features[0],
            "severity": "HEALTHY",
            "features": {}
        }
        self.last_explanation = "Model operating within normal baseline boundaries."
        self.last_alert_payload: Optional[Dict[str, Any]] = None

    def predict(self, input_data: Dict[str, Any], is_attack_active: bool = False, attack_intensity: float = 0.65) -> Dict[str, Any]:
        """
        Executes real-time inference with honeypot evaluation, graduated throttling,
        drift monitoring, trust calculation, and automatic failover.
        """
        # 1. Prepare feature vector
        feature_vals = {f: float(input_data.get(f, 0.0)) for f in self.features}
        df_row = pd.DataFrame([feature_vals])
        
        # Append to rolling window for statistical drift tracking
        self.rolling_window.append(feature_vals)
        
        # 2. Check Adversarial Honeypot
        is_honeypot, canary_name, canary_desc = inspect_for_honeypots(self.model_id, input_data)
        if is_honeypot:
            self.honeypot_triggers.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "canary": canary_name,
                "desc": canary_desc
            })

        # 3. Model Inference
        prob_risk = float(self.current_model.predict_proba(df_row[self.features])[:, 1][0])
        raw_pred = 1 if prob_risk >= 0.50 else 0
        
        # 4. Graduated Response (Confidence-Based Transaction Throttling)
        trust_score = self.trust_engine.current_score
        throttle_thresh = self.trust_engine.auto_approval_threshold
        
        if self.is_quarantined or self.status == "QUARANTINED":
            # Routing 100% traffic through verified clean fallback checkpoint
            clean_prob = float(self.clean_model.predict_proba(df_row[self.features])[:, 1][0])
            raw_pred = 1 if clean_prob >= 0.50 else 0
            decision = "BLOCKED_FRAUD (Clean Checkpoint Safe Filter)" if raw_pred == 1 else "APPROVED (Clean Safe Fallback)"
            throttling_action = "QUARANTINE_FALLBACK"
        elif trust_score >= 80.0:
            decision = "BLOCKED_FRAUD" if raw_pred == 1 else "APPROVED"
            throttling_action = "STANDARD_AUTO"
        elif trust_score >= 65.0:
            # Moderate Throttling
            if prob_risk >= 0.75:
                decision = "BLOCKED_FRAUD_HIGH_CERTAINTY"
            elif prob_risk <= 0.25:
                decision = "APPROVED_HIGH_CERTAINTY"
            else:
                decision = "MANUAL_REVIEW_FLAGGED (Throttled: Moderate Risk Uncertainty)"
            throttling_action = "MODERATE_THROTTLE"
        else:
            # Strict Throttling
            if prob_risk >= 0.88:
                decision = "BLOCKED_FRAUD_STRICT"
            elif prob_risk <= 0.12:
                decision = "APPROVED_STRICT"
            else:
                decision = "STEP_UP_IDENTITY_CHALLENGE (Throttled: High Certainty Needed)"
            throttling_action = "STRICT_THROTTLE"

        # Track model integrity anomalies (extreme OOD feature outliers or honeypot probe hits)
        is_ood = False
        for feat in self.features:
            val = feature_vals[feat]
            mean = float(self.baseline_df[feat].mean())
            std = max(1e-3, float(self.baseline_df[feat].std()))
            if abs(val - mean) / std > 6.5:
                is_ood = True
                break

        is_anomaly = (is_honeypot or is_ood)
        self.recent_anomalies.append(1 if is_anomaly else 0)
        anomaly_rate = sum(self.recent_anomalies) / max(1, len(self.recent_anomalies))

        # 5. Compute Feature Drift (PSI & KL Divergence)
        if len(self.rolling_window) >= 8:
            live_df = pd.DataFrame(list(self.rolling_window))
            self.last_drift_result = calculate_feature_drift(self.baseline_df, live_df, self.features)

        # 6. Update Trust Score
        honeypot_hits = len(self.honeypot_triggers)
        new_trust_score, new_status, throttling_level, _ = self.trust_engine.compute_trust_score(
            composite_psi=self.last_drift_result.get("composite_psi", 0.0),
            max_psi=self.last_drift_result.get("max_psi", 0.0),
            anomaly_rate=anomaly_rate,
            honeypot_hit_count=honeypot_hits,
            is_attack_active=is_attack_active,
            is_rolled_back=self.is_rolled_back,
            attack_intensity=attack_intensity
        )
        self.status = new_status

        # 7. Check for Auto-Quarantine & Rollback Trigger
        if new_trust_score < TRUST_THRESHOLD_QUARANTINE and not self.is_quarantined and not self.is_rolled_back:
            self._trigger_auto_quarantine(is_attack_active)

        # 8. Threat Intel / Leak Correlation
        leak_matched, leak_msg, leak_details = correlate_threat_intel(
            self.model_id, input_data, is_attack_active or is_honeypot
        )

        # 9. Individual SHAP Explanation
        instance_explanation = self.explainer.explain_instance(df_row)

        # 10. Persist transaction record
        tx_record = {
            "id": f"tx_{len(self.recent_transactions) + 1}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "model_id": self.model_id,
            "inputs": input_data,
            "risk_score": round(prob_risk, 3),
            "raw_prediction": raw_pred,
            "decision": decision,
            "throttling_action": throttling_action,
            "honeypot_triggered": is_honeypot,
            "canary_name": canary_name if is_honeypot else None,
            "leak_correlated": leak_matched,
            "leak_message": leak_msg,
            "shap_summary": instance_explanation["human_summary"],
            "trust_score": new_trust_score,
            "status": self.status
        }
        self.recent_transactions.append(tx_record)
        
        self._save_transaction_to_db(tx_record)
        return tx_record

    def _trigger_auto_quarantine(self, is_attack_active: bool):
        """Executes automatic quarantine and immediate rollback to verified clean checkpoint."""
        self.is_quarantined = True
        self.is_rolled_back = True
        self.active_version = "v1.0.0_clean_ROLLED_BACK"
        self.status = "QUARANTINED_ROLLED_BACK"
        self.current_model = self.clean_model
        
        # Clear honeypots buffer upon rollback
        self.honeypot_triggers.clear()
        
        # Threat intel correlation
        leak_matched, leak_msg, _ = correlate_threat_intel(self.model_id, {}, True)
        
        # SHAP Drift Explanation
        drift_exp = self.explainer.generate_drift_explanation(self.last_drift_result, self.meta["name"])
        
        # Bilingual Vernacular Alert
        alert_ctx = {
            "model_name": self.meta["name"],
            "feature": self.last_drift_result.get("max_drifting_feature", "features"),
            "ratio": self.last_drift_result.get("features", {}).get(self.last_drift_result.get("max_drifting_feature"), {}).get("shift_ratio", 2.5),
            "psi": self.last_drift_result.get("max_psi", 0.35),
            "score": self.trust_engine.current_score
        }
        vernacular = translate_alert("QUARANTINE_ROLLBACK", alert_ctx)
        
        # Record Incident in SQLite
        incident_id = self._save_incident_to_db(
            incident_type="AUTO_QUARANTINE_AND_ROLLBACK",
            severity="CRITICAL",
            drift_psi=self.last_drift_result.get("max_psi", 0.35),
            trust_score=self.trust_engine.current_score,
            en_alert=vernacular["english"],
            hi_alert=vernacular["hindi"],
            shap_summary=drift_exp,
            leak_correlated=1 if leak_matched else 0,
            leak_details=leak_msg,
            action="QUARANTINED_AND_ROLLED_BACK_TO_CLEAN_CHECKPOINT"
        )
        
        # Append Immutable SHA-256 Audit Chain Event
        audit_details = {
            "incident_id": incident_id,
            "event": "AUTO_QUARANTINE_ROLLBACK",
            "model_id": self.model_id,
            "trigger_trust_score": self.trust_engine.current_score,
            "max_psi": self.last_drift_result.get("max_psi", 0.0),
            "max_drifting_feature": self.last_drift_result.get("max_drifting_feature"),
            "threat_leak_correlated": leak_matched,
            "restored_checkpoint": "model_clean_v1.joblib",
            "action": "Traffic routed 100% to verified clean checkpoint."
        }
        audit_hash = record_audit_event("AUTO_QUARANTINE_AND_ROLLBACK", self.model_id, audit_details)
        
        self.last_alert_payload = {
            "id": incident_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "type": "QUARANTINE_ROLLBACK",
            "severity": "CRITICAL",
            "english": vernacular["english"],
            "hindi": vernacular["hindi"],
            "hinglish": vernacular["hinglish"],
            "voice_script": vernacular["voice_script"],
            "shap_explanation": drift_exp,
            "leak_correlated": leak_matched,
            "leak_message": leak_msg,
            "audit_hash": audit_hash
        }
        logger.warning("AUTO-QUARANTINE COMPLETED FOR %s! Switched to safe checkpoint. Audit Hash: %s",
                       self.model_id, audit_hash[:16])

    def manual_reset_to_healthy(self):
        """Resets the model state back to verified clean healthy state."""
        self.is_quarantined = False
        self.is_rolled_back = False
        self.active_version = "v1.0.0_clean"
        self.status = "HEALTHY"
        self.current_model = self.clean_model
        self.rolling_window.clear()
        self.recent_anomalies.clear()
        self.honeypot_triggers.clear()
        self.trust_engine.current_score = 98.5
        self.trust_engine.status = "HEALTHY"
        self.trust_engine.throttling_level = "NONE"
        self.trust_engine.auto_approval_threshold = 0.50
        self.last_alert_payload = None
        self.last_drift_result = {
            "composite_psi": 0.01,
            "max_psi": 0.01,
            "max_drifting_feature": self.features[0],
            "severity": "HEALTHY",
            "features": {}
        }

        audit_details = {
            "event": "MANUAL_SYSTEM_RESET_HEALTHY",
            "model_id": self.model_id,
            "action": "Operator restored model health baseline."
        }
        record_audit_event("OPERATOR_RESET_HEALTHY", self.model_id, audit_details)

    def _save_transaction_to_db(self, tx: Dict[str, Any]):
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO transactions (timestamp, model_id, input_features_json, raw_prediction, confidence, throttled_decision, honeypot_triggered, drift_flag)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                tx["timestamp"],
                tx["model_id"],
                json.dumps(tx["inputs"]),
                tx["raw_prediction"],
                tx["risk_score"],
                tx["decision"],
                1 if tx["honeypot_triggered"] else 0,
                1 if self.last_drift_result.get("severity") == "CRITICAL" else 0
            ))
            conn.commit()
            conn.close()
        except Exception as e:
            logger.debug("Transaction DB write error: %s", e)

    def _save_incident_to_db(self, incident_type, severity, drift_psi, trust_score, en_alert, hi_alert, shap_summary, leak_correlated, leak_details, action):
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO incidents (timestamp, model_id, incident_type, severity, drift_score_psi, trust_score_at_event, english_alert, hindi_alert, shap_summary, leak_correlated, leak_details, action_taken)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                datetime.now(timezone.utc).isoformat(),
                self.model_id,
                incident_type,
                severity,
                drift_psi,
                trust_score,
                en_alert,
                hi_alert,
                shap_summary,
                leak_correlated,
                leak_details,
                action
            ))
            incident_id = cursor.lastrowid
            conn.commit()
            conn.close()
            return incident_id
        except Exception as e:
            logger.error("Incident DB write error: %s", e)
            return 1

class ModelRegistry:
    def __init__(self):
        self.models: Dict[str, ManagedModel] = {}

    def initialize_models(self):
        logger.info("Initializing Sentinel Managed Models...")
        self.models[MODEL_FRAUD_ID] = ManagedModel(MODEL_FRAUD_ID)
        self.models[MODEL_KYC_ID] = ManagedModel(MODEL_KYC_ID)
        logger.info("Sentinel Model Registry ready with %d active models.", len(self.models))

    def get_model(self, model_id: str) -> Optional[ManagedModel]:
        return self.models.get(model_id)

    def get_all_models_summary(self) -> List[Dict[str, Any]]:
        """Returns organization-wide cross-model trust comparison matrix."""
        summaries = []
        for mid, model in self.models.items():
            trust = model.trust_engine.current_score
            risk_tier = "CRITICAL" if trust < 50 else ("HIGH" if trust < 65 else ("MEDIUM" if trust < 80 else "LOW"))
            summaries.append({
                "model_id": mid,
                "name": model.meta["name"],
                "domain": model.meta["domain"],
                "trust_score": trust,
                "status": model.status,
                "throttling_level": model.trust_engine.throttling_level,
                "auto_approval_threshold": model.trust_engine.auto_approval_threshold,
                "risk_tier": risk_tier,
                "is_quarantined": model.is_quarantined,
                "is_rolled_back": model.is_rolled_back,
                "composite_psi": model.last_drift_result.get("composite_psi", 0.0),
                "max_psi": model.last_drift_result.get("max_psi", 0.0),
                "max_drifting_feature": model.last_drift_result.get("max_drifting_feature"),
                "recent_transaction_count": len(model.recent_transactions),
                "active_version": model.active_version
            })
        # Rank by risk: lowest trust score first
        summaries.sort(key=lambda x: x["trust_score"])
        return summaries

# Global registry singleton
model_registry = ModelRegistry()
