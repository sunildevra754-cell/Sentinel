import os
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import joblib
import json
import logging
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, roc_auc_score

from backend.config import (
    CHECKPOINTS_DIR,
    MODEL_FRAUD_ID,
    MODEL_KYC_ID,
    MODEL_METADATA
)
from backend.models.data_generator import generate_fraud_dataset, generate_kyc_dataset
from backend.storage.audit_chain import record_audit_event
from backend.storage.database import init_db

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("sentinel.train")

def compute_baseline_stats(df: pd.DataFrame, features: list) -> dict:
    """Computes quantile deciles and statistical summary for PSI comparison."""
    stats = {}
    for feat in features:
        vals = df[feat].values
        # Compute 10 decile boundaries
        quantiles = np.percentile(vals, np.linspace(0, 100, 11))
        # Remove duplicate bin edges if any
        quantiles = np.unique(quantiles)
        stats[feat] = {
            "mean": float(np.mean(vals)),
            "std": float(np.std(vals)),
            "min": float(np.min(vals)),
            "max": float(np.max(vals)),
            "bins": [float(q) for q in quantiles]
        }
    return stats

def train_and_checkpoint_model(model_id: str, df: pd.DataFrame, target_col: str):
    """Trains a classifier, generates baseline stats, and stores a verified clean checkpoint."""
    features = MODEL_METADATA[model_id]["features"]
    X = df[features]
    y = df[target_col]

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=8,
        min_samples_split=6,
        random_state=42,
        n_jobs=-1
    )
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    y_prob = clf.predict_proba(X_test)[:, 1]

    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, zero_division=0))
    rec = float(recall_score(y_test, y_pred, zero_division=0))
    auc = float(roc_auc_score(y_test, y_prob))

    logger.info("Model '%s' Training Complete. Accuracy: %.4f, Precision: %.4f, Recall: %.4f, AUC: %.4f",
                model_id, acc, prec, rec, auc)

    # Save Baseline Data
    baseline_csv_path = CHECKPOINTS_DIR / f"baseline_{model_id}.csv"
    df.to_csv(baseline_csv_path, index=False)

    # Save Baseline Distribution Stats
    baseline_stats = compute_baseline_stats(df, features)
    stats_path = CHECKPOINTS_DIR / f"baseline_stats_{model_id}.json"
    with open(stats_path, "w") as f:
        json.dump(baseline_stats, f, indent=2)

    # Save Clean Checkpoint Model
    model_checkpoint_path = CHECKPOINTS_DIR / f"{model_id}_clean_v1.joblib"
    joblib.dump(clf, model_checkpoint_path)

    # Record to SHA-256 Audit Trail
    audit_details = {
        "action": "MODEL_CLEAN_CHECKPOINT_CREATED",
        "version": "v1.0.0_clean",
        "checkpoint_file": str(model_checkpoint_path.name),
        "dataset_samples": len(df),
        "metrics": {
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "roc_auc": round(auc, 4)
        },
        "features": features
    }
    hash_val = record_audit_event("CHECKPOINT_VERIFIED", model_id, audit_details)
    logger.info("Checkpoint recorded in audit chain. Hash: %s", hash_val)

    return {
        "model_id": model_id,
        "checkpoint_path": str(model_checkpoint_path),
        "metrics": audit_details["metrics"]
    }

def train_all_models():
    """Initializes DB and trains both initial clean protected models."""
    init_db()
    
    logger.info("Generating dataset and training Model 1: %s...", MODEL_FRAUD_ID)
    df_fraud = generate_fraud_dataset(n_samples=5000)
    res_fraud = train_and_checkpoint_model(MODEL_FRAUD_ID, df_fraud, "is_fraud")

    logger.info("Generating dataset and training Model 2: %s...", MODEL_KYC_ID)
    df_kyc = generate_kyc_dataset(n_samples=5000)
    res_kyc = train_and_checkpoint_model(MODEL_KYC_ID, df_kyc, "is_high_risk")

    logger.info("All baseline models successfully trained and verified.")
    return {"fraud": res_fraud, "kyc": res_kyc}

if __name__ == "__main__":
    train_all_models()
