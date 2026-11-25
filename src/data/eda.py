"""Exploratory Data Analysis utilities for Phishing Detection."""
import os
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns


def load_dataset(file_path: str) -> pd.DataFrame:
    """Load the raw or processed phishing dataset."""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Dataset not found at {file_path}")
    return pd.read_csv(file_path)


def generate_class_distribution_plot(df: pd.DataFrame, output_path: str) -> None:
    """Generate and save class distribution bar and pie chart."""
    plt.figure(figsize=(10, 4))
    
    # Label mapping: -1 is Legitimate, 1 is Phishing
    counts = df['Result'].value_counts()
    labels = ['Phishing (1)', 'Legitimate (-1)']
    values = [counts.get(1, 0), counts.get(-1, 0)]
    colors = ['#e74c3c', '#2ecc71']

    plt.subplot(1, 2, 1)
    bars = plt.bar(labels, values, color=colors, edgecolor='black', alpha=0.85)
    plt.title('Class Sample Counts', fontsize=12, fontweight='bold')
    plt.ylabel('Count')
    for bar in bars:
        yval = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2.0, yval + 50, f'{yval:,}', ha='center', va='bottom', fontweight='bold')

    plt.subplot(1, 2, 2)
    plt.pie(values, labels=labels, autopct='%1.1f%%', colors=colors, startangle=140,
            wedgeprops=dict(edgecolor='black'))
    plt.title('Class Ratio Breakdown', fontsize=12, fontweight='bold')

    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    plt.close()


def generate_correlation_heatmap(df: pd.DataFrame, output_path: str) -> None:
    """Generate and save full feature correlation heatmap."""
    plt.figure(figsize=(18, 14))
    corr = df.corr()
    mask = np.triu(np.ones_like(corr, dtype=bool))
    
    sns.heatmap(
        corr,
        mask=mask,
        cmap='coolwarm',
        vmax=1.0,
        vmin=-1.0,
        center=0,
        square=True,
        linewidths=0.5,
        cbar_kws={"shrink": 0.8},
        annot=False
    )
    plt.title('UCI Phishing Websites Dataset: Feature Correlation Matrix', fontsize=16, fontweight='bold', pad=20)
    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    plt.close()


def generate_top_correlations_plot(df: pd.DataFrame, output_path: str) -> None:
    """Plot top positive and negative correlations with target 'Result'."""
    corr = df.corr()['Result'].drop('Result').sort_values(ascending=False)
    
    plt.figure(figsize=(12, 6))
    colors = ['#e74c3c' if x > 0 else '#3498db' for x in corr.values]
    bars = plt.barh(corr.index, corr.values, color=colors, edgecolor='black', alpha=0.85)
    plt.axvline(0, color='black', linestyle='--', linewidth=0.8)
    plt.title('Feature Correlation with Target (Result: 1=Phishing, -1=Legitimate)', fontsize=13, fontweight='bold')
    plt.xlabel('Pearson Correlation Coefficient')
    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    plt.close()
