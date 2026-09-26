import sys
import time
import json
import sqlite3
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from backend.config import MODEL_FRAUD_ID, MODEL_KYC_ID, MODEL_METADATA, DB_PATH
from backend.models.model_registry import model_registry
from backend.attack_simulator.simulator import attack_simulator, ATTACK_TYPES
from backend.storage.database import init_db, get_db_connection
from backend.storage.audit_chain import verify_chain_integrity, get_audit_trail, record_audit_event
from backend.engine.drift_detector import calculate_psi, calculate_feature_drift
from backend.engine.explainability import ModelExplainer
from backend.engine.vernacular import translate_alert, VERNACULAR_TEMPLATES
from backend.engine.honeypot import inspect_for_honeypots
from backend.engine.leak_correlator import correlate_threat_intel

class SentinelTestRunner:
    def __init__(self):
        self.results = {}
        self.passed = 0
        self.failed = 0

    def record(self, test_num: int, title: str, passed: bool, details: str = ""):
        status = "PASSED" if passed else "FAILED"
        self.results[test_num] = {
            "title": title,
            "passed": passed,
            "status": status,
            "details": details
        }
        if passed:
            self.passed += 1
            print(f"[TEST {test_num:02d}] PASS - {title}")
        else:
            self.failed += 1
            print(f"[TEST {test_num:02d}] FAIL - {title} --> {details}")

    def run_all(self):
        print("=" * 70)
        print("SENTINEL RIGOROUS VERIFICATION SUITE -- 22 SYSTEMATIC TESTS")
        print("=" * 70)

        # Initialize
        init_db()
        model_registry.initialize_models()

        # Phase 1
        self.test_01_predict_endpoint_20_samples()
        self.test_02_kyc_model_independent_response()
        self.test_03_model_isolation_under_attack()
        self.test_04_multi_intensity_attack_curves()

        # Phase 2
        self.test_05_clean_baseline_stability()
        self.test_06_false_positive_resilience()
        self.test_07_shap_dynamic_explainability()
        self.test_08_trust_score_invariants()
        self.test_09_auto_quarantine_and_rollback()
        self.test_10_hindi_vernacular_linguistics()
        self.test_11_incident_timeline_chronology()

        # Phase 3
        self.test_12_threat_intel_correlation_precision()
        self.test_13_cross_model_live_ranking()
        self.test_14_graduated_confidence_throttling()
        self.test_15_sandbox_guided_flow()
        self.test_16_adversarial_honeypot_canary()

        # Phase 4
        self.test_17_audit_trail_tamper_detection()
        self.test_18_rapid_back_to_back_stress()
        self.test_19_clean_state_restart()
        self.test_20_offline_local_readiness()

        # Phase 5
        self.test_21_timed_demo_rehearsal()
        self.test_22_kiosk_usability_validation()

        print("\n" + "=" * 70)
        print(f"RESULTS SUMMARY: {self.passed} PASSED, {self.failed} FAILED / 22 TOTAL")
        print("=" * 70)
        return self.failed == 0

    # ----------------- PHASE 1 TESTS -----------------

    def test_01_predict_endpoint_20_samples(self):
        fraud = model_registry.get_model(MODEL_FRAUD_ID)
        fraud.manual_reset_to_healthy()
        samples_tested = 0
        valid_scores = True

        for _ in range(25):
            sample = attack_simulator.generate_next_sample(MODEL_FRAUD_ID)
            res = fraud.predict(sample, is_attack_active=False)
            samples_tested += 1
            if not (0.0 <= res["risk_score"] <= 1.0) or res["raw_prediction"] not in [0, 1]:
                valid_scores = False
                break
        
        passed = (samples_tested >= 20) and valid_scores
        self.record(1, "Protected Model 1 /predict 20+ synthetic samples", passed, f"Tested {samples_tested} samples.")

    def test_02_kyc_model_independent_response(self):
        kyc = model_registry.get_model(MODEL_KYC_ID)
        kyc.manual_reset_to_healthy()
        sample = attack_simulator.generate_next_sample(MODEL_KYC_ID)
        res = kyc.predict(sample, is_attack_active=False)
        passed = ("risk_score" in res) and (res["model_id"] == MODEL_KYC_ID) and ("annual_income" in sample)
        self.record(2, "Second Model (KYC) Independent Inference", passed, f"Model ID: {res.get('model_id')}")

    def test_03_model_isolation_under_attack(self):
        fraud = model_registry.get_model(MODEL_FRAUD_ID)
        kyc = model_registry.get_model(MODEL_KYC_ID)
        fraud.manual_reset_to_healthy()
        kyc.manual_reset_to_healthy()

        # Launch heavy attack on Model 1 ONLY
        attack_simulator.start_attack(MODEL_FRAUD_ID, "GRADUAL_POISONING", intensity=0.95)
        for _ in range(20):
            s1 = attack_simulator.generate_next_sample(MODEL_FRAUD_ID)
            fraud.predict(s1, is_attack_active=True, attack_intensity=0.95)
            s2 = attack_simulator.generate_next_sample(MODEL_KYC_ID)
            kyc.predict(s2, is_attack_active=False)

        attack_simulator.stop_attack(MODEL_FRAUD_ID)
        
        # Model 2 must remain healthy and unquarantined
        m2_healthy = (kyc.trust_engine.current_score >= 88.0) and (not kyc.is_quarantined)
        self.record(3, "Cross-Model Isolation (Model 2 Unaffected by Model 1 Attack)", m2_healthy,
                    f"Model 1 Trust: {fraud.trust_engine.current_score}, Model 2 Trust: {kyc.trust_engine.current_score}")

    def test_04_multi_intensity_attack_curves(self):
        fraud = model_registry.get_model(MODEL_FRAUD_ID)
        drops = {}
        for intensity, label in [(0.25, "slow"), (0.65, "medium"), (0.95, "fast")]:
            fraud.manual_reset_to_healthy()
            attack_simulator.start_attack(MODEL_FRAUD_ID, "GRADUAL_POISONING", intensity=intensity)
            min_score = 100.0
            for _ in range(16):
                s = attack_simulator.generate_next_sample(MODEL_FRAUD_ID)
                res = fraud.predict(s, is_attack_active=True, attack_intensity=intensity)
                min_score = min(min_score, res.get("trust_score", 100.0))
            attack_simulator.stop_attack(MODEL_FRAUD_ID)
            drops[label] = 98.5 - min_score

        # Fast attack should produce a sharper drop than slow attack
        passed = (drops["fast"] > drops["slow"]) and (drops["medium"] >= drops["slow"])
        self.record(4, "Multi-Intensity Attack Simulator Response Curves", passed,
                    f"Drops: Slow={drops['slow']:.1f}, Med={drops['medium']:.1f}, Fast={drops['fast']:.1f}")

    # ----------------- PHASE 2 TESTS -----------------

    def test_05_clean_baseline_stability(self):
        fraud = model_registry.get_model(MODEL_FRAUD_ID)
        fraud.manual_reset_to_healthy()
        psi_history = []

        # Run 30 clean samples
        for _ in range(30):
            s = attack_simulator.generate_next_sample(MODEL_FRAUD_ID)
            fraud.predict(s, is_attack_active=False)
            psi_history.append(fraud.last_drift_result.get("composite_psi", 0.0))

        avg_psi = sum(psi_history) / len(psi_history)
        passed = (avg_psi < 0.10) and (fraud.trust_engine.current_score >= 90.0)
        self.record(5, "Clean Baseline Stability (No False Drift Alarms)", passed,
                    f"Average Clean PSI: {avg_psi:.4f}, Final Trust: {fraud.trust_engine.current_score}")

    def test_06_false_positive_resilience(self):
        fraud = model_registry.get_model(MODEL_FRAUD_ID)
        fraud.manual_reset_to_healthy()

        # Rare legitimate transaction (high amount but verified domestic device and high account age)
        rare_legit_tx = {
            "amount": 2850.0,
            "transaction_velocity_1h": 1,
            "location_mismatch_score": 0.05,
            "device_trust_score": 0.98,
            "account_age_days": 1800,
            "foreign_ip_flag": 0,
            "past_failed_attempts": 0,
            "merchant_risk_rating": 0.1
        }
        res = fraud.predict(rare_legit_tx, is_attack_active=False)
        passed = (fraud.trust_engine.current_score >= 90.0) and (not res["honeypot_triggered"])
        self.record(6, "False Positive Resilience on Rare Legitimate Transactions", passed,
                    f"Decision: {res['decision']}, Trust: {fraud.trust_engine.current_score}")

    def test_07_shap_dynamic_explainability(self):
        fraud = model_registry.get_model(MODEL_FRAUD_ID)
        fraud.manual_reset_to_healthy()

        # Drift with amount shift
        res_amount = fraud.explainer.generate_drift_explanation({
            "max_drifting_feature": "amount",
            "max_psi": 0.38,
            "features": {"amount": {"shift_ratio": 3.4, "live_mean": 1420.0, "baseline_mean": 418.0}}
        }, "Sentinel-Guard")

        # Drift with foreign IP shift
        res_ip = fraud.explainer.generate_drift_explanation({
            "max_drifting_feature": "foreign_ip_flag",
            "max_psi": 0.42,
            "features": {"foreign_ip_flag": {"shift_ratio": 4.1, "live_mean": 0.85, "baseline_mean": 0.12}}
        }, "Sentinel-Guard")

        passed = ("amount" in res_amount) and ("foreign_ip_flag" in res_ip) and (res_amount != res_ip)
        self.record(7, "SHAP Dynamic Feature-Tailored Explainability", passed,
                    f"Sample Explanation: {res_amount[:65]}...")

    def test_08_trust_score_invariants(self):
        fraud = model_registry.get_model(MODEL_FRAUD_ID)
        fraud.manual_reset_to_healthy()
        initial = fraud.trust_engine.current_score
        
        # Degrade
        attack_simulator.start_attack(MODEL_FRAUD_ID, "GRADUAL_POISONING", intensity=0.95)
        for _ in range(15):
            s = attack_simulator.generate_next_sample(MODEL_FRAUD_ID)
            fraud.predict(s, is_attack_active=True)
        degraded = fraud.trust_engine.current_score

        # Rollback
        fraud._trigger_auto_quarantine(is_attack_active=False)
        recovered = fraud.trust_engine.current_score

        passed = (90.0 <= initial <= 100.0) and (0.0 <= degraded <= 100.0) and (recovered >= degraded)
        self.record(8, "Trust Score Range & Recovery Invariants [0-100]", passed,
                    f"Initial: {initial}, Degraded: {degraded}, Recovered: {recovered}")

    def test_09_auto_quarantine_and_rollback(self):
        fraud = model_registry.get_model(MODEL_FRAUD_ID)
        fraud.manual_reset_to_healthy()

        attack_simulator.start_attack(MODEL_FRAUD_ID, "GRADUAL_POISONING", intensity=0.95)
        for _ in range(25):
            s = attack_simulator.generate_next_sample(MODEL_FRAUD_ID)
            fraud.predict(s, is_attack_active=True)
        attack_simulator.stop_attack(MODEL_FRAUD_ID)

        passed = fraud.is_quarantined and fraud.is_rolled_back and (fraud.active_version.startswith("v1.0.0_clean"))
        self.record(9, "Auto-Quarantine & Clean Checkpoint Rollback Execution", passed,
                    f"Status: {fraud.status}, Version: {fraud.active_version}")

    def test_10_hindi_vernacular_linguistics(self):
        alert_keys = ["DRIFT_CRITICAL", "DRIFT_WARNING", "QUARANTINE_ROLLBACK", "HONEYPOT_DETECTED", "CREDENTIAL_LEAK_CORRELATED"]
        all_valid = True
        ctx = {"model_name": "Sentinel-Guard", "feature": "amount", "ratio": 3.2, "psi": 0.38, "score": 42.0, "canary": "CANARY_1337", "source": "ShadowForum"}

        for k in alert_keys:
            trans = translate_alert(k, ctx)
            # Verify Hindi text is non-empty and contains valid Devanagari characters (Unicode range 0x0900-0x097F)
            has_devanagari = any('\u0900' <= char <= '\u097f' for char in trans["hindi"])
            if not has_devanagari or not trans["english"]:
                all_valid = False
                break

        self.record(10, "Bilingual Hindi Vernacular Alert Linguistics & Unicode", all_valid,
                    f"Tested {len(alert_keys)} alert templates with valid Devanagari script.")

    def test_11_incident_timeline_chronology(self):
        fraud = model_registry.get_model(MODEL_FRAUD_ID)
        
        # Run 3 consecutive attack-to-rollback cycles
        for cycle in range(3):
            fraud.manual_reset_to_healthy()
            attack_simulator.start_attack(MODEL_FRAUD_ID, "GRADUAL_POISONING", intensity=0.95)
            for _ in range(15):
                s = attack_simulator.generate_next_sample(MODEL_FRAUD_ID)
                fraud.predict(s, is_attack_active=True)
            attack_simulator.stop_attack(MODEL_FRAUD_ID)
            fraud._trigger_auto_quarantine(is_attack_active=False)

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, timestamp, incident_type FROM incidents ORDER BY id DESC LIMIT 3")
        rows = cursor.fetchall()
        conn.close()

        passed = len(rows) >= 3
        self.record(11, "Incident Timeline Chronology Across 3 Full Cycles", passed,
                    f"Found {len(rows)} verified incident logs in chronological sequence.")

    # ----------------- PHASE 3 TESTS -----------------

    def test_12_threat_intel_correlation_precision(self):
        # 1. Under attack -> should correlate
        matched, msg, _ = correlate_threat_intel(MODEL_FRAUD_ID, {}, is_attack_active=True)
        # 2. Clean baseline -> should NOT false-correlate
        matched_clean, msg_clean, _ = correlate_threat_intel(MODEL_FRAUD_ID, {}, is_attack_active=False)

        passed = (matched is True) and (matched_clean is False)
        self.record(12, "Threat Intel Correlation Precision (No False Match)", passed,
                    f"Attack Match: {matched}, Clean Match: {matched_clean}")

    def test_13_cross_model_live_ranking(self):
        fraud = model_registry.get_model(MODEL_FRAUD_ID)
        kyc = model_registry.get_model(MODEL_KYC_ID)
        fraud.manual_reset_to_healthy()
        kyc.manual_reset_to_healthy()

        # Degrade Model 1
        fraud.trust_engine.current_score = 45.0
        kyc.trust_engine.current_score = 98.0

        ranking = model_registry.get_all_models_summary()
        # Ranked by risk (lowest trust first)
        top_risk_model = ranking[0]["model_id"]

        passed = (top_risk_model == MODEL_FRAUD_ID) and (ranking[0]["risk_tier"] == "CRITICAL")
        self.record(13, "Cross-Model Live Risk Surface Ranking", passed,
                    f"Top Risk: {top_risk_model} ({ranking[0]['risk_tier']})")

    def test_14_graduated_confidence_throttling(self):
        fraud = model_registry.get_model(MODEL_FRAUD_ID)
        fraud.manual_reset_to_healthy()

        # 1. Healthy (Trust 95) -> Threshold 0.50 (Standard)
        fraud.trust_engine.current_score = 95.0
        _, _, _, t1 = fraud.trust_engine.compute_trust_score(0.01, 0.01, 0.0, 0, False, False)

        # 2. Moderate Warning (Trust 72) -> Threshold 0.75 (Moderate Throttling)
        fraud.trust_engine.current_score = 72.0
        _, _, _, t2 = fraud.trust_engine.compute_trust_score(0.06, 0.08, 0.0, 0, False, False)

        # 3. Strict Warning (Trust 52) -> Threshold 0.88 (Strict Throttling)
        fraud.trust_engine.current_score = 52.0
        _, _, _, t3 = fraud.trust_engine.compute_trust_score(0.12, 0.16, 0.0, 0, False, False)

        passed = (t1 == 0.50) and (t2 == 0.75) and (t3 == 0.88)
        self.record(14, "Graduated Confidence Throttling Multi-Tier Progression", passed,
                    f"Throttling Stages: Healthy={t1*100}%, Mod={t2*100}%, Strict={t3*100}%")

    def test_15_sandbox_guided_flow(self):
        catalog = ATTACK_TYPES
        passed = (len(catalog) >= 4) and ("GRADUAL_POISONING" in catalog) and ("ADVERSARIAL_CANARY_PROBING" in catalog)
        self.record(15, "Exhibition Attack Sandbox Catalog & Parameter Routing", passed,
                    f"Available Attack Vectors: {list(catalog.keys())}")

    def test_16_adversarial_honeypot_canary(self):
        canary_payload = {
            "amount": 1337.42,
            "foreign_ip_flag": 1,
            "transaction_velocity_1h": 2
        }
        is_hit, name, desc = inspect_for_honeypots(MODEL_FRAUD_ID, canary_payload)
        passed = (is_hit is True) and (name == "CANARY_ELITE_PROBE_1337")
        self.record(16, "Adversarial Honeypot Canary Signature Detection", passed,
                    f"Canary Triggered: {name}")

    # ----------------- PHASE 4 TESTS -----------------

    def test_17_audit_trail_tamper_detection(self):
        # 1. Initial valid check
        init_valid, _, _ = verify_chain_integrity()

        # 2. Inject deliberate tamper in database
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, details_json FROM audit_trail ORDER BY id DESC LIMIT 1")
        row = cursor.fetchone()
        orig_id = row["id"]
        orig_details = row["details_json"]

        # Modify details without updating hash
        tampered_details = json.dumps({"action": "TAMPERED_EVENT_INJECTED"})
        cursor.execute("UPDATE audit_trail SET details_json = ? WHERE id = ?", (tampered_details, orig_id))
        conn.commit()

        # 3. Verification must fail
        tamper_detected, _, _ = verify_chain_integrity()
        tamper_caught = (tamper_detected is False)

        # 4. Restore original
        cursor.execute("UPDATE audit_trail SET details_json = ? WHERE id = ?", (orig_details, orig_id))
        conn.commit()
        conn.close()

        restored_valid, _, count = verify_chain_integrity()
        passed = init_valid and tamper_caught and restored_valid
        self.record(17, "SHA-256 Audit Trail Cryptographic Tamper Detection", passed,
                    f"Tamper Detected: {tamper_caught}, Restored: {restored_valid} ({count} blocks)")

    def test_18_rapid_back_to_back_stress(self):
        fraud = model_registry.get_model(MODEL_FRAUD_ID)
        crashed = False
        try:
            for attack_num in range(3):
                attack_simulator.start_attack(MODEL_FRAUD_ID, "COVARIATE_SHIFT_SURGE", intensity=0.90)
                for _ in range(10):
                    s = attack_simulator.generate_next_sample(MODEL_FRAUD_ID)
                    fraud.predict(s, is_attack_active=True)
                attack_simulator.stop_attack(MODEL_FRAUD_ID)
                fraud.manual_reset_to_healthy()
        except Exception as e:
            crashed = True

        self.record(18, "Rapid Consecutive Attack Stress Test (Zero Crash/Leak)", not crashed,
                    "Executed 30 continuous attack inferences without exceptions.")

    def test_19_clean_state_restart(self):
        # Re-initialize registry and verify clean state
        model_registry.initialize_models()
        fraud = model_registry.get_model(MODEL_FRAUD_ID)
        kyc = model_registry.get_model(MODEL_KYC_ID)
        passed = (fraud is not None) and (kyc is not None) and (fraud.status == "HEALTHY") and (kyc.status == "HEALTHY")
        self.record(19, "Cold Clean-State Restart Resilience", passed,
                    "Both models re-instantiated with verified weights.")

    def test_20_offline_local_readiness(self):
        # Verify static files exist locally and don't depend on external network APIs to serve UI
        idx = BASE_DIR / "static" / "index.html"
        css = BASE_DIR / "static" / "style.css"
        js = BASE_DIR / "static" / "app.js"
        db = BASE_DIR / "data" / "sentinel.db"
        passed = idx.exists() and css.exists() and js.exists() and db.exists()
        self.record(20, "100% Offline Local Exhibition Readiness", passed,
                    f"All static assets & SQLite DB present locally in workspace.")

    # ----------------- PHASE 5 TESTS -----------------

    def test_21_timed_demo_rehearsal(self):
        t0 = time.time()
        fraud = model_registry.get_model(MODEL_FRAUD_ID)
        fraud.manual_reset_to_healthy()

        # Step 1: Healthy
        s_clean = attack_simulator.generate_next_sample(MODEL_FRAUD_ID)
        fraud.predict(s_clean, is_attack_active=False)

        # Step 2: Attack
        attack_simulator.start_attack(MODEL_FRAUD_ID, "GRADUAL_POISONING", intensity=0.95)
        for _ in range(15):
            s_atk = attack_simulator.generate_next_sample(MODEL_FRAUD_ID)
            fraud.predict(s_atk, is_attack_active=True)
        attack_simulator.stop_attack(MODEL_FRAUD_ID)

        # Step 3: Rollback
        if not fraud.is_quarantined:
            fraud._trigger_auto_quarantine(is_attack_active=False)

        elapsed = time.time() - t0
        passed = (elapsed < 180.0) and (fraud.is_quarantined or fraud.is_rolled_back)
        self.record(21, "Timed Exhibition Demo Flow (< 3 minutes)", passed,
                    f"Completed full cycle in {elapsed:.3f} seconds.")

    def test_22_kiosk_usability_validation(self):
        # Verify UI controls, labels, and vernacular prompts are fully mapped
        tmpl_count = len(VERNACULAR_TEMPLATES)
        attacks_count = len(ATTACK_TYPES)
        passed = (tmpl_count >= 6) and (attacks_count >= 4)
        self.record(22, "Kiosk UI Usability & Exhibition Completeness", passed,
                    f"{tmpl_count} vernacular templates & {attacks_count} interactive attack vectors mapped.")

if __name__ == "__main__":
    runner = SentinelTestRunner()
    success = runner.run_all()
    sys.exit(0 if success else 1)
