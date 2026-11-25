"""Automated End-to-End QA Test Suite for Phishing Detection System."""
import os
import sys
import pytest
import pandas as pd
import numpy as np
import joblib

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if os.path.join(ROOT_DIR, "src") not in sys.path:
    sys.path.insert(0, os.path.join(ROOT_DIR, "src"))

DATA_DIR = os.path.join(ROOT_DIR, "data")
MODELS_DIR = os.path.join(ROOT_DIR, "models")


def test_raw_dataset_integrity():
    """Verify raw dataset exists, has correct shape, and has zero nulls."""
    raw_path = os.path.join(DATA_DIR, "raw", "phishing_dataset.csv")
    assert os.path.exists(raw_path), "Raw dataset file missing"
    
    df = pd.read_csv(raw_path)
    assert df.shape == (11055, 31), f"Unexpected raw shape: {df.shape}"
    assert df.isnull().sum().sum() == 0, "Null values detected in raw dataset"
    assert "Result" in df.columns, "Target column 'Result' missing"


def test_processed_dataset_integrity():
    """Verify processed train and test splits exist and have correct sizes."""
    train_path = os.path.join(DATA_DIR, "processed", "train.csv")
    test_path = os.path.join(DATA_DIR, "processed", "test.csv")
    
    assert os.path.exists(train_path), "Processed train.csv missing"
    assert os.path.exists(test_path), "Processed test.csv missing"

    train_df = pd.read_csv(train_path)
    test_df = pd.read_csv(test_path)

    assert len(train_df) == 8844, f"Train length mismatch: {len(train_df)}"
    assert len(test_df) == 2211, f"Test length mismatch: {len(test_df)}"
    assert "target" in train_df.columns, "Target column missing in train split"
    assert set(train_df['target'].unique()) == {0, 1}, "Target labels must be {0, 1}"


def test_preprocessor_artifact():
    """Verify saved preprocessor transforms test instances without error."""
    prep_path = os.path.join(MODELS_DIR, "preprocessor.joblib")
    assert os.path.exists(prep_path), "preprocessor.joblib missing"
    
    preprocessor = joblib.load(prep_path)
    test_df = pd.read_csv(os.path.join(DATA_DIR, "processed", "test.csv"))
    X_test = test_df.drop(columns=['target'])
    
    transformed = preprocessor.transform(X_test)
    assert transformed.shape == X_test.shape, "Transformed shape mismatch"


def test_model_artifacts_and_predictions():
    """Verify all models load and generate deterministic predictions on test batch."""
    test_df = pd.read_csv(os.path.join(DATA_DIR, "processed", "test.csv"))
    X_test = test_df.drop(columns=['target']).head(20)
    
    models = ["random_forest.joblib", "svm.joblib", "mlp_ann.joblib", "robust_random_forest.joblib"]
    for m_name in models:
        m_path = os.path.join(MODELS_DIR, m_name)
        assert os.path.exists(m_path), f"Model {m_name} missing"
        
        model = joblib.load(m_path)
        preds = model.predict(X_test)
        probs = model.predict_proba(X_test)[:, 1]
        
        assert len(preds) == 20, f"Incorrect prediction length for {m_name}"
        assert (probs >= 0.0).all() and (probs <= 1.0).all(), f"Invalid probability bounds for {m_name}"


def test_adversarial_evasion_attacker():
    """Verify adversarial feature perturbation works and does not mutate clean data in-place."""
    from adversarial.evasion import PhishingEvasionAttacker

    test_df = pd.read_csv(os.path.join(DATA_DIR, "processed", "test.csv"))
    X_sample = test_df.drop(columns=['target']).head(5).copy()

    attacker = PhishingEvasionAttacker(attack_intensity="moderate")
    X_adv = attacker.perturb(X_sample)

    assert X_adv.shape == X_sample.shape, "Adversarial perturbation altered shape"
    assert (X_adv["SSLfinal_State"] == -1).all(), "SSLfinal_State was not perturbed to benign (-1)"


def test_shap_alert_generator():
    """Verify SHAP explainer and plain-text alert generation."""
    from explainability.alert_generator import SecurityAlertGenerator

    rf = joblib.load(os.path.join(MODELS_DIR, "random_forest.joblib"))
    expl = joblib.load(os.path.join(MODELS_DIR, "shap_explainer.joblib"))
    test_df = pd.read_csv(os.path.join(DATA_DIR, "processed", "test.csv"))
    X_sample = test_df.drop(columns=['target']).iloc[0]

    alert_gen = SecurityAlertGenerator(rf, expl, test_df.drop(columns=['target']).columns.tolist())
    exp = alert_gen.explain_instance(X_sample)

    assert "prediction" in exp, "Explanation missing prediction key"
    assert "top_risk_factors" in exp or "top_protective_factors" in exp, "Explanation missing factor keys"

    alert_txt = alert_gen.format_alert("TEST-01", exp)
    assert "SECURITY INCIDENT ALERT" in alert_txt, "Alert text formatted incorrectly"
