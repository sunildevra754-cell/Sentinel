import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Any
import logging

logger = logging.getLogger("sentinel.drift")

def calculate_psi(expected: np.ndarray, actual: np.ndarray, bins: List[float] = None, num_bins: int = 4) -> float:
    """
    Calculates Population Stability Index (PSI) between baseline (expected)
    and live rolling window (actual) using finite-sample bias correction.
    Handles discrete categorical variables directly and continuous variables via quantile quartiles.
    PSI = max(0.0, sum((Actual_% - Expected_%) * ln(Actual_% / Expected_%)) - (k - 1) / N)
    """
    eps = 0.02  # Bayesian Laplace prior for small sample multinomials

    if len(expected) == 0 or len(actual) == 0:
        return 0.0

    unique_exp = np.unique(expected)
    # If discrete variable (e.g. binary flag, count <= 6 unique values)
    if len(unique_exp) <= 6:
        categories = np.unique(np.concatenate([unique_exp, np.unique(actual)]))
        exp_counts = np.array([np.sum(expected == cat) for cat in categories], dtype=float)
        act_counts = np.array([np.sum(actual == cat) for cat in categories], dtype=float)

        expected_pct = (exp_counts + eps) / (len(expected) + eps * len(categories))
        actual_pct = (act_counts + eps) / (len(actual) + eps * len(categories))

        raw_psi = float(np.sum((actual_pct - expected_pct) * np.log(actual_pct / expected_pct)))
        bias = (len(categories) - 1.0) / max(1.0, float(len(actual)))
        return max(0.0, raw_psi - bias)

    # Continuous variable: 4 quantile bins
    quantiles = np.linspace(0, 100, num_bins + 1)
    bin_edges = np.percentile(expected, quantiles)
    bin_edges = np.unique(bin_edges)
    if len(bin_edges) < 2:
        bin_edges = np.linspace(min(expected.min(), actual.min()) - 1,
                                max(expected.max(), actual.max()) + 1, num_bins + 1)

    bin_edges = list(bin_edges)
    bin_edges[0] = min(bin_edges[0], float(actual.min()), float(expected.min())) - 1e-3
    bin_edges[-1] = max(bin_edges[-1], float(actual.max()), float(expected.max())) + 1e-3

    expected_counts, _ = np.histogram(expected, bins=bin_edges)
    actual_counts, _ = np.histogram(actual, bins=bin_edges)

    expected_pct = (expected_counts + eps) / (len(expected) + eps * len(expected_counts))
    actual_pct = (actual_counts + eps) / (len(actual) + eps * len(actual_counts))

    raw_psi = float(np.sum((actual_pct - expected_pct) * np.log(actual_pct / expected_pct)))
    k_bins = len(expected_counts)
    bias = (k_bins - 1.0) / max(1.0, float(len(actual)))
    return max(0.0, raw_psi - bias)

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

        if len(act) < 8:
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

        status = "NO_DRIFT"
        if psi >= 0.25:
            status = "SEVERE_DRIFT"
        elif psi >= 0.12:
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
    elif max_psi_val >= 0.12 or composite_psi >= 0.08:
        severity = "WARNING"

    return {
        "composite_psi": round(composite_psi, 4),
        "max_psi": round(max_psi_val, 4),
        "max_drifting_feature": max_psi_feature,
        "severity": severity,
        "features": feature_results
    }
