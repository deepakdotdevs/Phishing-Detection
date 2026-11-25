# Automated End-to-End QA Validation Report

## 1. Test Execution Summary
- **Execution Engine:** `pytest` (v9.0.2)
- **Target Test Suite:** `tests/test_pipeline.py`
- **Result:** **PASSED (All 6 Test Modules Green)**
- **Execution Time:** 2.73 seconds

```text
============================= test session starts =============================
platform win32 -- Python 3.14.3, pytest-9.0.2, pluggy-1.6.0
rootdir: E:\Projects\Phishing Detection\Phishing-Detection
collected 6 items

tests/test_pipeline.py::test_raw_dataset_integrity PASSED                [ 16%]
tests/test_pipeline.py::test_processed_dataset_integrity PASSED          [ 33%]
tests/test_pipeline.py::test_preprocessor_artifact PASSED                [ 50%]
tests/test_pipeline.py::test_model_artifacts_and_predictions PASSED      [ 66%]
tests/test_pipeline.py::test_adversarial_evasion_attacker PASSED         [ 83%]
tests/test_pipeline.py::test_shap_alert_generator PASSED                 [100%]

============================== 6 passed in 2.73s ==============================
```

## 2. Verified Subsystems
1. **Raw Dataset Integrity:** Validated 11,055 records, 31 columns, zero missing values, and target existence.
2. **Preprocessing & Leakage Prevention:** Verified 80/20 stratified split (8,844 train vs. 2,211 test), target remapping, and isolated transformation.
3. **Model Artifacts & Inferences:** Validated deterministic loading and probability predictions across Random Forest, SVM, MLP, and Robust Random Forest.
4. **Adversarial Attacker Module:** Verified repeatable feature perturbation and immutability of clean inputs.
5. **Explainable AI & Alert Generator:** Verified SHAP calculation and SOC plain-language advisory formatting.
6. **Streamlit UI Components:** Verified syntax and module compatibility.
