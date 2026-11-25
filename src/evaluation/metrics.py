"""Evaluation metrics and visualization generators for Phishing Detection."""
import os
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score, roc_auc_score,
    confusion_matrix, roc_curve, precision_recall_curve
)


def compute_metrics(y_true, y_pred, y_prob) -> dict:
    """Calculate comprehensive classification metrics."""
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0

    return {
        "Accuracy": float(accuracy_score(y_true, y_pred)),
        "Precision": float(precision_score(y_true, y_pred)),
        "Recall": float(recall_score(y_true, y_pred)),
        "F1-Score": float(f1_score(y_true, y_pred)),
        "ROC-AUC": float(roc_auc_score(y_true, y_prob)),
        "False Positive Rate": float(fpr),
        "False Negative Rate": float(fnr),
        "True Positives": int(tp),
        "False Positives": int(fp),
        "True Negatives": int(tn),
        "False Negatives": int(fn)
    }


def plot_confusion_matrices(models_dict: dict, output_path: str):
    """Plot normalized confusion matrices for all evaluated models side by side."""
    fig, axes = plt.subplots(1, len(models_dict), figsize=(5 * len(models_dict), 4))
    if len(models_dict) == 1:
        axes = [axes]

    for ax, (name, data) in zip(axes, models_dict.items()):
        cm = confusion_matrix(data['y_true'], data['y_pred'], normalize='true')
        sns.heatmap(cm, annot=True, fmt='.2%', cmap='Blues', cbar=False, ax=ax,
                    xticklabels=['Legit (0)', 'Phish (1)'],
                    yticklabels=['Legit (0)', 'Phish (1)'])
        ax.set_title(f"{name}\nConfusion Matrix (Normalized)", fontsize=11, fontweight='bold')
        ax.set_ylabel('True Label')
        ax.set_xlabel('Predicted Label')

    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    plt.close()


def plot_roc_curves(models_dict: dict, output_path: str):
    """Plot overlaid ROC curves with AUC annotations."""
    plt.figure(figsize=(8, 6))
    
    for name, data in models_dict.items():
        fpr, tpr, _ = roc_curve(data['y_true'], data['y_prob'])
        auc = roc_auc_score(data['y_true'], data['y_prob'])
        plt.plot(fpr, tpr, label=f"{name} (AUC = {auc:.4f})", linewidth=2)

    plt.plot([0, 1], [0, 1], 'k--', label='Random Chance (AUC = 0.5000)', alpha=0.7)
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate (FPR)', fontsize=11, fontweight='bold')
    plt.ylabel('True Positive Rate (TPR / Recall)', fontsize=11, fontweight='bold')
    plt.title('Receiver Operating Characteristic (ROC) Comparison', fontsize=13, fontweight='bold')
    plt.legend(loc='lower right', frameon=True)
    plt.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    plt.close()


def plot_pr_curves(models_dict: dict, output_path: str):
    """Plot Precision-Recall curves."""
    plt.figure(figsize=(8, 6))
    
    for name, data in models_dict.items():
        prec, rec, _ = precision_recall_curve(data['y_true'], data['y_prob'])
        plt.plot(rec, prec, label=name, linewidth=2)

    plt.xlabel('Recall', fontsize=11, fontweight='bold')
    plt.ylabel('Precision', fontsize=11, fontweight='bold')
    plt.title('Precision-Recall Curves Comparison', fontsize=13, fontweight='bold')
    plt.legend(loc='lower left', frameon=True)
    plt.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    plt.close()
