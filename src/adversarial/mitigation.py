"""Adversarial training mitigation to harden Phishing Detection models."""
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from adversarial.evasion import PhishingEvasionAttacker


def generate_adversarial_training_data(X_train: pd.DataFrame, y_train: pd.Series, sample_fraction: float = 0.5, random_state: int = 42) -> tuple:
    """
    Augment training data with perturbed phishing samples.
    Fit and augmentation applied STRICTLY to training data to guarantee zero leakage.
    """
    phishing_indices = y_train[y_train == 1].index
    np.random.seed(random_state)
    selected_indices = np.random.choice(phishing_indices, size=int(len(phishing_indices) * sample_fraction), replace=False)
    
    X_phish_sub = X_train.loc[selected_indices].copy()
    y_phish_sub = y_train.loc[selected_indices].copy()

    # Apply moderate attacker perturbations
    attacker = PhishingEvasionAttacker(attack_intensity="moderate")
    X_adv = attacker.perturb(X_phish_sub)

    # Combine original training data with synthetic adversarial examples
    X_augmented = pd.concat([X_train, X_adv], ignore_index=True)
    y_augmented = pd.concat([y_train, y_phish_sub], ignore_index=True)

    return X_augmented, y_augmented


def train_robust_model(X_augmented: pd.DataFrame, y_augmented: pd.Series, random_state: int = 42) -> RandomForestClassifier:
    """Train hardened Random Forest model on defensively augmented dataset."""
    robust_rf = RandomForestClassifier(
        n_estimators=120,
        max_depth=16,
        min_samples_split=4,
        min_samples_leaf=2,
        random_state=random_state,
        n_jobs=-1
    )
    robust_rf.fit(X_augmented, y_augmented)
    return robust_rf
