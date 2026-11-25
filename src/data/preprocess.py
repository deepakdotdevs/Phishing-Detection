"""Preprocessing pipeline ensuring zero data leakage."""
import os
import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.base import BaseEstimator, TransformerMixin


class PhishingPreprocessor(BaseEstimator, TransformerMixin):
    """Custom preprocessor fitting strictly on training split."""

    def __init__(self, scale_features: bool = True):
        self.scale_features = scale_features
        self.scaler = StandardScaler() if scale_features else None
        self.feature_names = None

    def fit(self, X: pd.DataFrame, y=None):
        self.feature_names = list(X.columns)
        if self.scaler:
            self.scaler.fit(X)
        return self

    def transform(self, X: pd.DataFrame) -> pd.DataFrame:
        if self.scaler:
            transformed = self.scaler.transform(X)
            return pd.DataFrame(transformed, columns=self.feature_names, index=X.index)
        return X.copy()


def prepare_data(raw_csv_path: str, test_size: float = 0.2, random_state: int = 42):
    """
    Load raw data, remap targets to {0, 1}, and perform stratified train-test split.
    Zero leakage: scaler is fit solely on the training fold.
    """
    df = pd.read_csv(raw_csv_path)
    
    # Remap target: -1 (Legitimate) -> 0, 1 (Phishing) -> 1
    # Store explicit target mapping in documentation
    X = df.drop(columns=['Result'])
    y = df['Result'].map({-1: 0, 1: 1}).astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y
    )

    preprocessor = PhishingPreprocessor(scale_features=True)
    X_train_scaled = preprocessor.fit_transform(X_train)
    X_test_scaled = preprocessor.transform(X_test)

    train_df = X_train_scaled.copy()
    train_df['target'] = y_train.values

    test_df = X_test_scaled.copy()
    test_df['target'] = y_test.values

    # Also keep unscaled for tree-based models and explainability
    train_unscaled = X_train.copy()
    train_unscaled['target'] = y_train.values

    test_unscaled = X_test.copy()
    test_unscaled['target'] = y_test.values

    return preprocessor, train_df, test_df, train_unscaled, test_unscaled
