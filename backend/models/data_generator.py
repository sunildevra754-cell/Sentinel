import numpy as np
import pandas as pd
from typing import Dict, Any, Tuple
from backend.config import MODEL_FRAUD_ID, MODEL_KYC_ID

try:
    from faker import Faker
    fake = Faker()
    Faker.seed(42)
except Exception:
    class FallbackFake:
        def hexify(self, text="^^^^^^"):
            import uuid
            return uuid.uuid4().hex[:len(text)]
        def ipv4_public(self):
            import random
            return f"{random.randint(11, 199)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"
        def md5(self):
            import uuid
            return uuid.uuid4().hex
        def sha256(self):
            import hashlib, uuid
            return hashlib.sha256(uuid.uuid4().bytes).hexdigest()
    fake = FallbackFake()

np.random.seed(42)

def generate_fraud_dataset(n_samples: int = 4000) -> pd.DataFrame:
    """Generates realistic synthetic transaction dataset for Payment Fraud detection."""
    # Features
    amount = np.random.lognormal(mean=4.2, sigma=1.1, size=n_samples)
    amount = np.clip(amount, 5.0, 5000.0).round(2)
    
    transaction_velocity_1h = np.random.poisson(lam=1.8, size=n_samples) + 1
    transaction_velocity_1h = np.clip(transaction_velocity_1h, 1, 15)
    
    location_mismatch_score = np.random.beta(a=1.5, b=5.0, size=n_samples).round(3)
    device_trust_score = np.random.beta(a=6.0, b=1.5, size=n_samples).round(3)
    
    account_age_days = np.random.exponential(scale=400, size=n_samples).astype(int) + 5
    account_age_days = np.clip(account_age_days, 1, 3650)
    
    foreign_ip_flag = (np.random.rand(n_samples) < 0.12).astype(int)
    past_failed_attempts = np.random.choice([0, 1, 2, 3, 4], size=n_samples, p=[0.75, 0.15, 0.06, 0.03, 0.01])
    merchant_risk_rating = np.random.beta(a=2.0, b=4.0, size=n_samples).round(3)
    
    # Ground truth fraud logic with realistic probabilistic noise
    is_fraud_cond = (
        ((amount > 500) & (foreign_ip_flag == 1)) |
        ((transaction_velocity_1h > 4) & (device_trust_score < 0.45)) |
        ((location_mismatch_score > 0.65) & (past_failed_attempts >= 1)) |
        ((merchant_risk_rating > 0.65) & (account_age_days < 60))
    )
    # 85% deterministic + 15% random noise
    is_fraud = np.where(is_fraud_cond, (np.random.rand(n_samples) < 0.88).astype(int), (np.random.rand(n_samples) < 0.03).astype(int))
    
    df = pd.DataFrame({
        "amount": amount,
        "transaction_velocity_1h": transaction_velocity_1h,
        "location_mismatch_score": location_mismatch_score,
        "device_trust_score": device_trust_score,
        "account_age_days": account_age_days,
        "foreign_ip_flag": foreign_ip_flag,
        "past_failed_attempts": past_failed_attempts,
        "merchant_risk_rating": merchant_risk_rating,
        "is_fraud": is_fraud
    })
    return df

def generate_kyc_dataset(n_samples: int = 4000) -> pd.DataFrame:
    """Generates realistic synthetic applicant dataset for KYC & Credit Underwriting."""
    annual_income = np.random.lognormal(mean=11.1, sigma=0.55, size=n_samples)
    annual_income = np.clip(annual_income, 18000, 350000).round(-2)
    
    debt_to_income_ratio = np.random.beta(a=2.5, b=4.5, size=n_samples).round(3)
    debt_to_income_ratio = np.clip(debt_to_income_ratio, 0.05, 0.85)
    
    credit_bureau_score = np.random.normal(loc=680, scale=80, size=n_samples).astype(int)
    credit_bureau_score = np.clip(credit_bureau_score, 300, 850)
    
    employment_years = np.random.exponential(scale=6.0, size=n_samples).round(1)
    employment_years = np.clip(employment_years, 0.0, 35.0)
    
    id_document_match_score = np.random.beta(a=7.0, b=1.2, size=n_samples).round(3)
    utility_bill_verified = (np.random.rand(n_samples) < 0.82).astype(int)
    previous_defaults_count = np.random.choice([0, 1, 2, 3], size=n_samples, p=[0.82, 0.12, 0.04, 0.02])
    inquiry_velocity_6m = np.random.poisson(lam=1.5, size=n_samples)
    inquiry_velocity_6m = np.clip(inquiry_velocity_6m, 0, 10)
    
    risk_prob = (
        0.03 +
        0.40 * (credit_bureau_score < 580) +
        0.30 * (debt_to_income_ratio > 0.48) +
        0.25 * (id_document_match_score < 0.65) * (utility_bill_verified == 0) +
        0.35 * (previous_defaults_count >= 2) +
        0.15 * (inquiry_velocity_6m > 5)
    )
    risk_prob = np.clip(risk_prob, 0.01, 0.95)
    is_high_risk = (np.random.rand(n_samples) < risk_prob).astype(int)
    
    df = pd.DataFrame({
        "annual_income": annual_income,
        "debt_to_income_ratio": debt_to_income_ratio,
        "credit_bureau_score": credit_bureau_score,
        "employment_years": employment_years,
        "id_document_match_score": id_document_match_score,
        "utility_bill_verified": utility_bill_verified,
        "previous_defaults_count": previous_defaults_count,
        "inquiry_velocity_6m": inquiry_velocity_6m,
        "is_high_risk": is_high_risk
    })
    return df

def generate_live_sample(model_id: str, is_attack: bool = False, attack_intensity: float = 0.5) -> Dict[str, Any]:
    """Generates a single incoming real-time feature payload (normal or poisoned)."""
    if model_id == MODEL_FRAUD_ID:
        if not is_attack:
            # Normal clean traffic distribution
            amount = float(np.random.lognormal(mean=4.2, sigma=1.0))
            amount = round(min(max(amount, 10.0), 3000.0), 2)
            velocity = int(np.random.poisson(lam=1.5) + 1)
            loc_mismatch = round(float(np.random.beta(1.5, 5.0)), 3)
            device_trust = round(float(np.random.beta(6.0, 1.5)), 3)
            account_age = int(np.random.exponential(400) + 10)
            foreign_ip = 1 if np.random.rand() < 0.10 else 0
            failed_attempts = int(np.random.choice([0, 1, 2], p=[0.85, 0.12, 0.03]))
            merchant_risk = round(float(np.random.beta(2.0, 4.0)), 3)
        else:
            # Poisoned / Anomaly pattern: High velocity, forged device, sudden foreign IP drift
            # Attackers attempting to bypass high amounts with poisoned device features
            shift = attack_intensity
            amount = float(np.random.uniform(900.0, 4500.0)) * (1.0 + 0.3 * shift)
            amount = round(amount, 2)
            velocity = int(np.random.randint(6, 14))
            loc_mismatch = round(min(0.98, float(np.random.uniform(0.65, 0.99))), 3)
            # Attackers try spoofing device trust to slip through
            device_trust = round(max(0.05, float(np.random.uniform(0.1, 0.4))), 3)
            account_age = int(np.random.randint(1, 45))
            foreign_ip = 1 if np.random.rand() < (0.6 + 0.3 * shift) else 0
            failed_attempts = int(np.random.randint(2, 5))
            merchant_risk = round(float(np.random.uniform(0.6, 0.95)), 3)
            
        return {
            "amount": amount,
            "transaction_velocity_1h": velocity,
            "location_mismatch_score": loc_mismatch,
            "device_trust_score": device_trust,
            "account_age_days": account_age,
            "foreign_ip_flag": foreign_ip,
            "past_failed_attempts": failed_attempts,
            "merchant_risk_rating": merchant_risk,
            "user_id": f"usr_{fake.hexify(text='^^^^^^')}",
            "ip_address": fake.ipv4_public(),
            "device_fingerprint": f"fp_{fake.md5()[:8]}"
        }
    else:
        # MODEL_KYC_ID
        if not is_attack:
            income = float(np.random.lognormal(11.1, 0.55))
            income = round(min(max(income, 22000), 280000), -2)
            dti = round(float(np.random.beta(2.5, 4.5)), 3)
            credit_score = int(np.clip(np.random.normal(680, 75), 450, 850))
            emp_years = round(float(np.random.exponential(6.0)), 1)
            doc_score = round(float(np.random.beta(7.0, 1.2)), 3)
            utility_ok = 1 if np.random.rand() < 0.85 else 0
            defaults = int(np.random.choice([0, 1], p=[0.88, 0.12]))
            inquiries = int(np.random.poisson(1.2))
        else:
            shift = attack_intensity
            # Forged synthetic KYC profiles with exaggerated income & manipulated bureau velocity
            income = float(np.random.uniform(180000, 420000))
            dti = round(float(np.random.uniform(0.55, 0.88)), 3)
            credit_score = int(np.random.randint(510, 640))
            emp_years = round(float(np.random.uniform(0.2, 2.0)), 1)
            doc_score = round(float(np.random.uniform(0.35, 0.65)), 3)
            utility_ok = 1 if np.random.rand() < 0.25 else 0
            defaults = int(np.random.randint(1, 4))
            inquiries = int(np.random.randint(6, 12))
            
        return {
            "annual_income": income,
            "debt_to_income_ratio": dti,
            "credit_bureau_score": credit_score,
            "employment_years": emp_years,
            "id_document_match_score": doc_score,
            "utility_bill_verified": utility_ok,
            "previous_defaults_count": defaults,
            "inquiry_velocity_6m": inquiries,
            "applicant_id": f"app_{fake.hexify(text='^^^^^^')}",
            "national_id_hash": fake.sha256()[:12]
        }
