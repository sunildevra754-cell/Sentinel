import os
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
CHECKPOINTS_DIR = DATA_DIR / "checkpoints"
DB_PATH = DATA_DIR / "sentinel.db"

# Ensure runtime directories exist
DATA_DIR.mkdir(exist_ok=True, parents=True)
CHECKPOINTS_DIR.mkdir(exist_ok=True, parents=True)

# Trust Score & Drift Thresholds
TRUST_THRESHOLD_HEALTHY = 80.0
TRUST_THRESHOLD_WARNING = 50.0  # Between 50 and 80 -> Warning / Throttled
TRUST_THRESHOLD_QUARANTINE = 50.0  # < 50 -> Auto-Quarantine & Rollback

PSI_THRESHOLD_MODERATE = 0.10
PSI_THRESHOLD_SEVERE = 0.25
KL_THRESHOLD_ALERT = 0.30

# Rolling Window Size for Real-Time Drift Analysis
DRIFT_WINDOW_SIZE = 60

# Model IDs
MODEL_FRAUD_ID = "model_fraud"
MODEL_KYC_ID = "model_kyc"

MODEL_METADATA = {
    MODEL_FRAUD_ID: {
        "name": "Sentinel-Guard: Payment Fraud Engine",
        "domain": "Financial Transactions & E-Commerce",
        "description": "Real-time binary classifier assessing transaction risk, velocity, and device patterns.",
        "features": [
            "amount",
            "transaction_velocity_1h",
            "location_mismatch_score",
            "device_trust_score",
            "account_age_days",
            "foreign_ip_flag",
            "past_failed_attempts",
            "merchant_risk_rating"
        ],
        "target": "is_fraud"  # 1 = Fraud, 0 = Legitimate
    },
    MODEL_KYC_ID: {
        "name": "Sentinel-Risk: KYC & Credit Underwriting",
        "domain": "Lending & Identity Verification",
        "description": "Evaluates applicant creditworthiness, income verification stability, and identity signals.",
        "features": [
            "annual_income",
            "debt_to_income_ratio",
            "credit_bureau_score",
            "employment_years",
            "id_document_match_score",
            "utility_bill_verified",
            "previous_defaults_count",
            "inquiry_velocity_6m"
        ],
        "target": "is_high_risk"  # 1 = Deny/High Risk, 0 = Approve
    }
}
