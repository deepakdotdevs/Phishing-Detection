# Capstone Model Evaluation & Comparative Performance Benchmark

## 1. Standardized Classification Metrics (Held-Out Test Set: 2,211 Samples)

| Model         |   Accuracy |   Precision |   Recall |   F1-Score |   ROC-AUC |   False Positive Rate |   False Negative Rate |
|:--------------|-----------:|------------:|---------:|-----------:|----------:|----------------------:|----------------------:|
| Random Forest |   0.964722 |    0.960831 | 0.976442 |   0.968574 |  0.996303 |             0.05      |             0.0235581 |
| SVM (RBF)     |   0.951606 |    0.941824 | 0.973193 |   0.957251 |  0.989326 |             0.0755102 |             0.0268075 |
| MLP (ANN)     |   0.971958 |    0.971751 | 0.978067 |   0.974899 |  0.996396 |             0.0357143 |             0.0219334 |

## 2. Key Findings & Security Analysis
- **Random Forest (Primary Model):**
  - **Accuracy:** 96.47%
  - **F1-Score:** 0.9686
  - **ROC-AUC:** 0.9963
  - **False Negative Rate:** 2.36% (Critical for cybersecurity to avoid letting malicious websites slip through).
  - Selected as the primary model due to top performance, rapid inference speed, and seamless compatibility with tree-based SHAP explainers.

- **Support Vector Machine (SVM):**
  - Strong margin separation with 95.16% accuracy, but slower training and probability calibration.

- **Multi-Layer Perceptron (MLP/ANN):**
  - Reached 97.20% accuracy, proving neural networks can capture non-linear relationships across tabular URL features.
