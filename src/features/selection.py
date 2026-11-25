"""Feature selection utilities for Phishing Detection."""
import pandas as pd
import numpy as np
from sklearn.feature_selection import mutual_info_classif
from sklearn.ensemble import RandomForestClassifier


def compute_mutual_information(X: pd.DataFrame, y: pd.Series, random_state: int = 42) -> pd.Series:
    """Compute mutual information score of each feature against the target."""
    mi_scores = mutual_info_classif(X, y, random_state=random_state)
    mi_series = pd.Series(mi_scores, index=X.columns).sort_values(ascending=False)
    return mi_series


def get_top_features(X: pd.DataFrame, y: pd.Series, n_features: int = 20, random_state: int = 42) -> list:
    """Select the top n features by mutual information."""
    mi_series = compute_mutual_information(X, y, random_state=random_state)
    return mi_series.head(n_features).index.tolist()
