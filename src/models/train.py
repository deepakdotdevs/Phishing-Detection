"""Model training and serialization for Phishing Detection."""
import os
import time
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier


def train_random_forest(X_train: pd.DataFrame, y_train: pd.Series, random_state: int = 42) -> tuple:
    """Train Random Forest classifier (Primary model)."""
    start = time.time()
    rf = RandomForestClassifier(
        n_estimators=100,
        max_depth=15,
        min_samples_split=4,
        min_samples_leaf=2,
        random_state=random_state,
        n_jobs=-1
    )
    rf.fit(X_train, y_train)
    duration = time.time() - start
    return rf, duration


def train_svm(X_train_scaled: pd.DataFrame, y_train: pd.Series, random_state: int = 42) -> tuple:
    """Train Support Vector Classifier with RBF kernel and probability estimation."""
    start = time.time()
    svm = SVC(
        C=1.0,
        kernel='rbf',
        gamma='scale',
        probability=True,
        random_state=random_state
    )
    svm.fit(X_train_scaled, y_train)
    duration = time.time() - start
    return svm, duration


def train_mlp_ann(X_train_scaled: pd.DataFrame, y_train: pd.Series, random_state: int = 42) -> tuple:
    """Train Artificial Neural Network using MLPClassifier."""
    start = time.time()
    mlp = MLPClassifier(
        hidden_layer_sizes=(64, 32),
        activation='relu',
        solver='adam',
        max_iter=300,
        early_stopping=True,
        random_state=random_state
    )
    mlp.fit(X_train_scaled, y_train)
    duration = time.time() - start
    return mlp, duration


def save_model(model, filepath: str) -> None:
    """Save model to disk using joblib."""
    joblib.dump(model, filepath)
