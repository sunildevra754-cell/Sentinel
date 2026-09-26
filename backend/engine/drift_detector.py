import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Any
import logging

logger = logging.getLogger("sentinel.drift")

def calculate_psi(expected: np.ndarray, actual: np.ndarray, bins: List[float] = None, num_bins: int = 10) -> float:
    """
    Calculates Population Stability Index (PSI) between baseline (expected)
    and live rolling window (actual).
    PSI = sum((Actual_% - Expected_%) * ln(Actual_% / Expected_%))
    """
    eps = 1e-3  # Laplace smoothing

    if len(expected) == 0 or len(actual) == 0:
        return 0.0

    if bins is None or len(bins) < 2:
        # Generate quantile-based bins from expected
        quantiles = np.linspace(0, 100, num_bins + 1)
        bins = np.percentile(expected, quantiles)
        bins = np.unique(bins)
        if len(bins) < 2:
            bins = np.linspace(min(expected.min(), actual.min()) - 1,
                               max(expected.max(), actual.max()) + 1, num_bins + 1)

    bins = list(bins)
    bins[0] = min(bins[0], float(actual.min()), float(expected.min())) - 1e-3
    bins[-1] = max(bins[-1], float(actual.max()), float(expected.max())) + 1e-3

    # Bin the data
    expected_counts, _ = np.histogram(expected, bins=bins)
    actual_counts, _ = np.histogram(actual, bins=bins)

    # Convert to percentages with smoothing
    expected_pct = (expected_counts + eps) / (len(expected) + eps * len(expected_counts))
    actual_pct = (actual_counts + eps) / (len(actual) + eps * len(actual_counts))

    # Calculate PSI
    psi_vector = (actual_pct - expected_pct) * np.log(actual_pct / expected_pct)
    psi_val = float(np.sum(psi_vector))
    return max(0.0, psi_val)

def calculate_kl_divergence(p: np.ndarray, q: np.ndarray, num_bins: int = 10) -> float:
    """
    Computes Kullback-Leibler Divergence KL(P || Q) between two empirical samples.
    """
    eps = 1e-4
    min_val = min(p.min(), q.min()) - 1e-3
    max_val = max(p.max(), q.max()) + 1e-3
    bins = np.linspace(min_val, max_val, num_bins + 1)

    p_counts, _ = np.histogram(p, bins=bins)
    q_counts, _ = np.histogram(q, bins=bins)

    p_prob = (p_counts + eps) / (len(p) + eps * len(p_counts))
    q_prob = (q_counts + eps) / (len(q) + eps * len(q_counts))

    kl_val = float(np.sum(p_prob * np.log(p_prob / q_prob)))
    return max(0.0, kl_val)

def calculate_feature_drift(baseline_df: pd.DataFrame, live_df: pd.DataFrame, features: List[str]) -> Dict[str, Any]:
    """
    Analyzes drift for each feature between baseline and current live window.
    Returns per-feature PSI, KL divergence, shift multiplier, and composite PSI score.
    """
    feature_results = {}
    psi_values = []
    kl_values = []

    for feat in features:
        if feat not in baseline_df.columns or feat not in live_df.columns:
            continue

        exp = baseline_df[feat].dropna().values
        act = live_df[feat].dropna().values
        exp_mean = float(np.mean(exp))
        act_mean = float(np.mean(act)) if len(act) > 0 else exp_mean
        shift_ratio = round((act_mean + 1e-5) / (exp_mean + 1e-5), 2)

        if len(act) < 15:
            feature_results[feat] = {
                "psi": 0.01,
                "kl": 0.01,
                "baseline_mean": round(exp_mean, 2),
                "live_mean": round(act_mean, 2),
                "shift_ratio": 1.0,
                "status": "NO_DRIFT"
            }
            psi_values.append(0.01)
            kl_values.append(0.01)
            continue

        psi = calculate_psi(exp, act)
        kl = calculate_kl_divergence(act, exp)

        exp_mean = float(np.mean(exp))
        act_mean = float(np.mean(act))
        shift_ratio = round((act_mean + 1e-5) / (exp_mean + 1e-5), 2)

        status = "NO_DRIFT"
        if psi >= 0.25:
            status = "SEVERE_DRIFT"
        elif psi >= 0.10:
            status = "MODERATE_DRIFT"

        feature_results[feat] = {
            "psi": round(psi, 4),
            "kl": round(kl, 4),
            "baseline_mean": round(exp_mean, 2),
            "live_mean": round(act_mean, 2),
            "shift_ratio": shift_ratio,
            "status": status
        }
        psi_values.append(psi)
        kl_values.append(kl)

    composite_psi = float(np.mean(psi_values)) if psi_values else 0.0
    max_psi_feature = max(feature_results.items(), key=lambda x: x[1]["psi"])[0] if feature_results else None
    max_psi_val = feature_results[max_psi_feature]["psi"] if max_psi_feature else 0.0

    severity = "HEALTHY"
    if max_psi_val >= 0.25 or composite_psi >= 0.20:
        severity = "CRITICAL"
    elif max_psi_val >= 0.10 or composite_psi >= 0.08:
        severity = "WARNING"

    return {
        "composite_psi": round(composite_psi, 4),
        "max_psi": round(max_psi_val, 4),
        "max_drifting_feature": max_psi_feature,
        "severity": severity,
        "features": feature_results
    }
