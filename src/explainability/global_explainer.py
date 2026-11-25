"""Global explainability using SHAP for Random Forest phishing classifier."""
import os
import joblib
import pandas as pd
import numpy as np
import shap
import matplotlib.pyplot as plt


class PhishingGlobalExplainer:
    """Wrapper around shap.TreeExplainer for tree-based ensemble models."""

    def __init__(self, model):
        self.model = model
        self.explainer = shap.TreeExplainer(model)

    def explain(self, X_sample: pd.DataFrame):
        """Compute SHAP values for class 1 (Phishing)."""
        shap_values = self.explainer.shap_values(X_sample)
        # Handle binary classification output formats in SHAP:
        # Some versions return list [class 0, class 1], others return 3D array (samples, features, classes)
        if isinstance(shap_values, list):
            sv = shap_values[1]
        elif len(shap_values.shape) == 3:
            sv = shap_values[:, :, 1]
        else:
            sv = shap_values
        return sv


def plot_shap_importance(shap_vals, feature_names, output_path: str, top_n: int = 15):
    """Plot global feature importance based on mean absolute SHAP value."""
    mean_abs = np.mean(np.abs(shap_vals), axis=0)
    top_indices = np.argsort(mean_abs)[::-1][:top_n]
    
    top_features = [feature_names[i] for i in top_indices]
    top_scores = mean_abs[top_indices]

    plt.figure(figsize=(10, 6))
    y_pos = np.arange(len(top_features))
    plt.barh(y_pos, top_scores[::-1], color='#3498db', edgecolor='black', alpha=0.85)
    plt.yticks(y_pos, top_features[::-1], fontsize=10)
    plt.xlabel('Mean |SHAP Value| (Average Impact on Phishing Likelihood)', fontsize=11, fontweight='bold')
    plt.title(f'Top {top_n} Features by Global SHAP Importance', fontsize=13, fontweight='bold')
    plt.grid(axis='x', alpha=0.3)
    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    plt.close()


def plot_shap_summary(shap_vals, X_sample, output_path: str, max_display: int = 15):
    """Generate and save SHAP summary beeswarm plot."""
    plt.figure(figsize=(10, 7))
    shap.summary_plot(shap_vals, X_sample, max_display=max_display, show=False)
    plt.title('SHAP Summary / Beeswarm Plot (Impact on Phishing Classification)', fontsize=12, fontweight='bold', pad=15)
    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    plt.close()
