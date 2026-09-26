import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import unittest
from backend.models.model_registry import model_registry
from backend.config import MODEL_FRAUD_ID, MODEL_KYC_ID
from backend.attack_simulator.simulator import attack_simulator
from backend.storage.audit_chain import verify_chain_integrity, get_audit_trail
from backend.engine.vernacular import translate_alert

class TestSentinelE2E(unittest.TestCase):
    def setUp(self):
        model_registry.initialize_models()

    def test_01_models_initialized(self):
        fraud = model_registry.get_model(MODEL_FRAUD_ID)
        kyc = model_registry.get_model(MODEL_KYC_ID)
        self.assertIsNotNone(fraud)
        self.assertIsNotNone(kyc)
        self.assertEqual(fraud.status, "HEALTHY")
        self.assertGreaterEqual(fraud.trust_engine.current_score, 90.0)

    def test_02_clean_prediction_flow(self):
        fraud = model_registry.get_model(MODEL_FRAUD_ID)
        sample = attack_simulator.generate_next_sample(MODEL_FRAUD_ID)
        result = fraud.predict(sample, is_attack_active=False)
        self.assertIn("risk_score", result)
        self.assertIn("decision", result)
        self.assertIn("shap_summary", result)
        self.assertEqual(result["throttling_action"], "STANDARD_AUTO")

    def test_03_honeypot_canary_detection(self):
        fraud = model_registry.get_model(MODEL_FRAUD_ID)
        canary_sample = {
            "amount": 1337.42,
            "transaction_velocity_1h": 8,
            "location_mismatch_score": 0.8,
            "device_trust_score": 0.2,
            "account_age_days": 100,
            "foreign_ip_flag": 1,
            "past_failed_attempts": 3,
            "merchant_risk_rating": 0.7
        }
        res = fraud.predict(canary_sample, is_attack_active=True)
        self.assertTrue(res["honeypot_triggered"])
        self.assertEqual(res["canary_name"], "CANARY_ELITE_PROBE_1337")

    def test_04_attack_drift_throttling_and_auto_rollback(self):
        fraud = model_registry.get_model(MODEL_FRAUD_ID)
        fraud.manual_reset_to_healthy()
        
        # Start attack
        attack_simulator.start_attack(MODEL_FRAUD_ID, "GRADUAL_POISONING", intensity=0.95)
        
        # Inject 25 poisoned transactions
        for _ in range(25):
            sample = attack_simulator.generate_next_sample(MODEL_FRAUD_ID)
            res = fraud.predict(sample, is_attack_active=True)

        # During the attack stream, the model detects drift and automatically triggers quarantine & rollback
        self.assertTrue(fraud.is_quarantined or fraud.is_rolled_back)
        self.assertIn("ROLLED_BACK", fraud.status)
        self.assertIsNotNone(fraud.last_alert_payload)
        self.assertIn("सुरक्षा", fraud.last_alert_payload["hindi"])
        
        # Cleanup
        attack_simulator.stop_attack(MODEL_FRAUD_ID)
        fraud.manual_reset_to_healthy()

    def test_05_vernacular_translation(self):
        ctx = {"model_name": "Sentinel-Guard", "feature": "amount", "ratio": 3.2, "psi": 0.38, "score": 42.0}
        alert = translate_alert("DRIFT_CRITICAL", ctx)
        self.assertIn("Critical drift detected", alert["english"])
        self.assertIn("गंभीर विचलन चेतावनी", alert["hindi"])
        self.assertIn("Gambhir drift", alert["hinglish"])

    def test_06_immutable_audit_chain_integrity(self):
        is_valid, msg, count = verify_chain_integrity()
        self.assertTrue(is_valid)
        self.assertGreater(count, 0)
        trail = get_audit_trail(limit=5)
        self.assertGreater(len(trail), 0)
        self.assertEqual(len(trail[0]["current_hash"]), 64)

if __name__ == "__main__":
    unittest.main()
