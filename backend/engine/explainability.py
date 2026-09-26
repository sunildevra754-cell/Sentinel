import numpy as np
import pandas as pd
import logging
from typing import Dict, Any, List
import shap

logger = logging.getLogger("sentinel.explainability")

class ModelExplainer:
    def __init__(self, model, baseline_sample: pd.DataFrame, feature_names: List[str]):
        self.model = model
        self.feature_names = feature_names
        self.baseline_sample = baseline_sample[feature_names]
        
        # Initialize SHAP TreeExplainer if possible
        try:
            self.explainer = shap.TreeExplainer(self.model, data=self.baseline_sample.iloc[:100])
            self.shap_type = "tree"
        except Exception as e:
            logger.warning("TreeExplainer failed (%s). Falling back to Exact/Linear explainer.", e)
            try:
                self.explainer = shap.Explainer(self.model.predict_proba, self.baseline_sample.iloc[:50])
                self.shap_type = "kernel"
            except Exception as ex:
                logger.error("SHAP initialization fallback: %s", ex)
                self.explainer = None
                self.shap_type = "heuristic"

    def explain_instance(self, instance_df: pd.DataFrame) -> Dict[str, Any]:
        """
        Explains an individual prediction with feature attributions and human-readable text.
        """
        df_feats = instance_df[self.feature_names]
        contributions = {}

        if self.explainer is not None:
            try:
                shap_values = self.explainer(df_feats)
                # If binary classifier output shape is (1, num_features, 2) or (1, num_features)
                if len(shap_values.values.shape) == 3:
                    vals = shap_values.values[0, :, 1]  # positive class
                else:
                    vals = shap_values.values[0, :]
                    
                for idx, feat in enumerate(self.feature_names):
                    contributions[feat] = round(float(vals[idx]), 4)
            except Exception as e:
                logger.debug("SHAP explanation error: %s. Using heuristic feature importance.", e)
                contributions = self._heuristic_contributions(df_feats)
        else:
            contributions = self._heuristic_contributions(df_feats)

        # Sort features by absolute contribution
        sorted_feats = sorted(contributions.items(), key=lambda x: abs(x[1]), reverse=True)
        top_positive = [f"{k} (+{v:.2f})" for k, v in sorted_feats if v > 0][:3]
        top_negative = [f"{k} ({v:.2f})" for k, v in sorted_feats if v < 0][:3]

        # Generate human-readable explanation
        if sorted_feats:
            top_name, top_val = sorted_feats[0]
            action = "increasing risk significantly" if top_val > 0 else "lowering risk score"
            human_sentence = f"Feature '{top_name}' was the strongest driver ({top_val:+.2f}), {action}."
        else:
            human_sentence = "All features contributed nominally within normal baseline boundaries."

        return {
            "contributions": contributions,
            "top_risk_drivers": top_positive,
            "top_mitigating_drivers": top_negative,
            "human_summary": human_sentence
        }

    def _heuristic_contributions(self, df_feats: pd.DataFrame) -> Dict[str, float]:
        """Fallback normalized heuristic feature importance if SHAP is unavailable."""
        contributions = {}
        if hasattr(self.model, "feature_importances_"):
            importances = self.model.feature_importances_
            row = df_feats.iloc[0]
            for idx, feat in enumerate(self.feature_names):
                val = row[feat]
                mean = self.baseline_sample[feat].mean()
                std = max(self.baseline_sample[feat].std(), 1e-3)
                z_score = (val - mean) / std
                contributions[feat] = round(float(importances[idx] * z_score), 4)
        return contributions

    def generate_drift_explanation(self, drift_results: Dict[str, Any], model_name: str) -> str:
        """
        Converts feature drift and PSI metrics into plain-language, executive-ready explanation.
        """
        max_feat = drift_results.get("max_drifting_feature")
        max_psi = drift_results.get("max_psi", 0.0)
        feat_data = drift_results.get("features", {}).get(max_feat, {})
        shift_ratio = feat_data.get("shift_ratio", 1.0)
        live_mean = feat_data.get("live_mean", 0.0)
        baseline_mean = feat_data.get("baseline_mean", 0.0)

        if max_psi >= 0.25:
            explanation = (
                f"CRITICAL DRIFT ALERT on [{model_name}]: Feature '{max_feat}' has shifted {shift_ratio}x "
                f"(Live Avg: {live_mean} vs Baseline Avg: {baseline_mean}, PSI: {max_psi}). "
                f"The model's decision boundary is being actively warped, matching a gradual data-poisoning attack pattern."
            )
        elif max_psi >= 0.10:
            explanation = (
                f"MODERATE DRIFT WARNING on [{model_name}]: Feature '{max_feat}' is exhibiting distribution divergence "
                f"(PSI: {max_psi}, shift: {shift_ratio}x). Model confidence throttling is being tightened."
            )
        else:
            explanation = f"Model [{model_name}] input distribution is consistent with verified baseline (Composite PSI: {drift_results.get('composite_psi', 0.0)})."

        return explanation
