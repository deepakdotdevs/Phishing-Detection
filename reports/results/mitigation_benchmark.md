# Adversarial Training Defense & Mitigation Benchmark

## 1. Overview
To counter the high evasion rate observed in Issue #6, we implemented **Defensive Adversarial Augmentation & Retraining**.
- Synthesized perturbed training examples from the training split only (zero test contamination).
- Defensively hardened Random Forest was trained and exported to `models/robust_random_forest.joblib`.

## 2. Before vs. After Benchmark Table
| Metric | Baseline Model | Robust Hardened Model | Difference / Impact |
| :--- | :---: | :---: | :--- |
| **Clean Test Accuracy** | 96.47% | 95.48% | -1.00% (Negligible utility cost) |
| **Clean Test F1-Score** | 0.9686 | 0.9604 | -0.0082 |
| **Moderate Attack Evasion Rate** | **68.72%** | **0.41%** | **-68.31% drop (Robustness Gain)** |

## 3. Defense Assessment
- The adversarial retraining dropped evasion from **68.7% down to 0.4%**, demonstrating a **99.4% relative reduction in successful attacks**.
- High clean test accuracy (95.48%) is preserved, proving that adversarial hardening does not compromise normal operational utility.
