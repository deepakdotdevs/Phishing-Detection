"""Helper utilities for Streamlit dashboard."""
import os
import sys

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC_DIR = os.path.join(ROOT_DIR, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)
if ROOT_DIR not in sys.path:
    sys.path.append(ROOT_DIR)

import joblib
import pandas as pd
import streamlit as st
MODELS_DIR = os.path.join(ROOT_DIR, "models")
DATA_DIR = os.path.join(ROOT_DIR, "data", "processed")


@st.cache_resource
def load_all_models():
    """Load serialized models with caching."""
    models = {}
    rf_path = os.path.join(MODELS_DIR, "random_forest.joblib")
    svm_path = os.path.join(MODELS_DIR, "svm.joblib")
    mlp_path = os.path.join(MODELS_DIR, "mlp_ann.joblib")
    robust_path = os.path.join(MODELS_DIR, "robust_random_forest.joblib")
    prep_path = os.path.join(MODELS_DIR, "preprocessor.joblib")
    shap_path = os.path.join(MODELS_DIR, "shap_explainer.joblib")

    if os.path.exists(rf_path):
        models["Random Forest"] = joblib.load(rf_path)
    if os.path.exists(svm_path):
        models["SVM (RBF)"] = joblib.load(svm_path)
    if os.path.exists(mlp_path):
        models["MLP (ANN)"] = joblib.load(mlp_path)
    if os.path.exists(robust_path):
        models["Robust Random Forest"] = joblib.load(robust_path)
    if os.path.exists(prep_path):
        models["Preprocessor"] = joblib.load(prep_path)
    if os.path.exists(shap_path):
        models["SHAP Explainer"] = joblib.load(shap_path)

    return models


@st.cache_data
def load_test_dataset():
    """Load held-out test data."""
    test_path = os.path.join(DATA_DIR, "test.csv")
    if os.path.exists(test_path):
        return pd.read_csv(test_path)
    return pd.DataFrame()


def get_curated_samples(test_df):
    """Return dictionary of curated sample cases for quick demonstration."""
    if test_df.empty:
        return {}
    
    phish_indices = test_df[test_df['target'] == 1].index.tolist()
    legit_indices = test_df[test_df['target'] == 0].index.tolist()

    return {
        "High-Confidence Phishing Sample": phish_indices[0] if phish_indices else 0,
        "Authentic Legitimate Sample": legit_indices[0] if legit_indices else 0,
        "Sophisticated Phishing Sample": phish_indices[5] if len(phish_indices) > 5 else phish_indices[0],
        "Borderline Benign Sample": legit_indices[5] if len(legit_indices) > 5 else legit_indices[0]
    }
