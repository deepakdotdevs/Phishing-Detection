"""Adversarial evasion attack simulation against Phishing Detection models."""
import pandas as pd
import numpy as np


class PhishingEvasionAttacker:
    """
    Simulates feature-space adversarial manipulation by a threat actor.
    Features manipulated mimic real-world attacker adaptations:
    - Obtaining valid SSL certificate (SSLfinal_State -> -1)
    - Avoiding suspicious domain hyphens (Prefix_Suffix -> -1)
    - Hosting external assets locally (Request_URL -> -1)
    - Minimizing subdomain nesting (having_Sub_Domain -> -1)
    - Using normal port configuration (port -> -1)
    """

    MANIPULABLE_FEATURES = [
        "SSLfinal_State",
        "Prefix_Suffix",
        "Request_URL",
        "having_Sub_Domain",
        "Favicon",
        "port",
        "HTTPS_token"
    ]

    def __init__(self, attack_intensity: str = "moderate"):
        self.attack_intensity = attack_intensity

    def perturb(self, X: pd.DataFrame) -> pd.DataFrame:
        """Apply targeted adversarial perturbations to make phishing samples look benign."""
        X_adv = X.copy()
        
        if self.attack_intensity == "mild":
            # Spoof SSL and fix URL prefix
            features_to_flip = ["SSLfinal_State", "Prefix_Suffix"]
        elif self.attack_intensity == "moderate":
            # SSL, prefix, asset requests, and subdomains
            features_to_flip = ["SSLfinal_State", "Prefix_Suffix", "Request_URL", "having_Sub_Domain"]
        else: # aggressive
            features_to_flip = self.MANIPULABLE_FEATURES

        for feat in features_to_flip:
            if feat in X_adv.columns:
                # Set to -1 (the benign / legitimate indicator in UCI dataset)
                X_adv[feat] = -1

        return X_adv


def evaluate_evasion(model, X_clean: pd.DataFrame, y_clean: pd.Series, attacker: PhishingEvasionAttacker) -> dict:
    """Evaluate evasion rate strictly on True Positive phishing samples."""
    # Filter true phishing samples correctly identified by model
    clean_preds = model.predict(X_clean)
    clean_probs = model.predict_proba(X_clean)[:, 1]
    
    # Only test on actual phishing samples that the model originally detected
    tp_mask = (y_clean == 1) & (clean_preds == 1)
    X_phish_tp = X_clean[tp_mask].copy()
    original_probs = clean_probs[tp_mask]
    
    if len(X_phish_tp) == 0:
        return {"error": "No true positive phishing samples found"}

    # Perturb
    X_adv = attacker.perturb(X_phish_tp)
    adv_preds = model.predict(X_adv)
    adv_probs = model.predict_proba(X_adv)[:, 1]

    # Evasion occurred if adv_pred is 0 (classified as legitimate)
    evaded_count = int(np.sum(adv_preds == 0))
    total_tested = int(len(X_phish_tp))
    evasion_rate = float(evaded_count / total_tested)
    avg_conf_drop = float(np.mean(original_probs - adv_probs))

    return {
        "total_phishing_tested": total_tested,
        "evaded_count": evaded_count,
        "evasion_success_rate": evasion_rate,
        "avg_original_confidence": float(np.mean(original_probs)),
        "avg_adversarial_confidence": float(np.mean(adv_probs)),
        "avg_confidence_drop": avg_conf_drop,
        "original_probs": original_probs.tolist(),
        "adv_probs": adv_probs.tolist()
    }
