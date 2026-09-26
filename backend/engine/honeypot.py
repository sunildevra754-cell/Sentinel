from typing import Dict, Any, Tuple
import logging

logger = logging.getLogger("sentinel.honeypot")

# Seeded Canary / Bait Signatures (Deliberately planted bait vectors)
HONEYPOT_RULES = {
    "model_fraud": [
        {
            "name": "CANARY_ELITE_PROBE_1337",
            "description": "Probe pattern with canary amount $1337.42 and foreign IP flag",
            "check": lambda d: abs(float(d.get("amount", 0)) - 1337.42) < 0.05 and int(d.get("foreign_ip_flag", 0)) == 1
        },
        {
            "name": "CANARY_DEVICE_FINGERPRINT_PROBE",
            "description": "Bait device trust fingerprint 0.007 with account age 777 days",
            "check": lambda d: abs(float(d.get("device_trust_score", 0)) - 0.007) < 0.002 and int(d.get("account_age_days", 0)) == 777
        },
        {
            "name": "CANARY_MERCHANT_BOUNDARY_SWEEP",
            "description": "Boundary sweep probe with merchant rating 0.999 and 4 failed attempts",
            "check": lambda d: float(d.get("merchant_risk_rating", 0)) >= 0.998 and int(d.get("past_failed_attempts", 0)) >= 4
        }
    ],
    "model_kyc": [
        {
            "name": "CANARY_SYNTHETIC_PII_777k",
            "description": "Seeded synthetic income template $777,777 with inquiry surge 11",
            "check": lambda d: abs(float(d.get("annual_income", 0)) - 777777) < 1.0 and int(d.get("inquiry_velocity_6m", 0)) >= 11
        },
        {
            "name": "CANARY_IDENTITY_PROBE_PI",
            "description": "Bait credit score 314 with document score 0.133",
            "check": lambda d: int(d.get("credit_bureau_score", 0)) == 314 and abs(float(d.get("id_document_match_score", 0)) - 0.133) < 0.005
        },
        {
            "name": "CANARY_DTI_OVERFLOW_SCAN",
            "description": "Probing DTI boundary 0.999 with unverified utility bill",
            "check": lambda d: float(d.get("debt_to_income_ratio", 0)) >= 0.998 and int(d.get("utility_bill_verified", 0)) == 0
        }
    ]
}

def inspect_for_honeypots(model_id: str, features: Dict[str, Any]) -> Tuple[bool, str, str]:
    """
    Evaluates incoming payload against honeypot bait patterns.
    Returns (is_honeypot, canary_name, description).
    """
    rules = HONEYPOT_RULES.get(model_id, [])
    for rule in rules:
        try:
            if rule["check"](features):
                logger.warning("HONEYPOT TRIGGERED! Model: %s, Canary: %s", model_id, rule["name"])
                return True, rule["name"], rule["description"]
        except Exception as e:
            logger.error("Honeypot evaluation error on %s: %s", rule["name"], e)

    return False, "", ""
