---
marp: true
theme: default
paginate: true
header: 'Intelligent Phishing Website Detection Using ML and XAI'
footer: 'Capstone Project — AI in Cybersecurity'
---

# Intelligent Phishing Website Detection Using Machine Learning and Explainable AI
### 120-Mark Capstone Defense
**Candidate:** Kushagra Bhardwaj  
**Date:** 14 November 2026  
**Repository:** https://github.com/Kush05Bhardwaj/Phishing-Detection

---

## Slide 1: Introduction & The Phishing Problem
- **The Threat Landscape:** Phishing accounts for over 36% of all cybersecurity breaches, targeting user credentials, financial data, and enterprise infrastructure.
- **Why Traditional Defenses Fail:**
  - *Static Blocklists:* Over 84% of malicious domains are active for < 4 hours, rendering DNS blacklists reactive and obsolete.
  - *Heuristic Bypass:* Threat actors adapt page structures and register genuine SSL/TLS certificates to look benign.
- **Project Goal:** Build an end-to-end, real-time ML detection pipeline augmented with adversarial defense and transparent Explainable AI (SHAP).

---

## Slide 2: Problem Statement & Capstone Objectives
- **Core Objectives (Addressing 120-Mark Rubric):**
  1. *Supervised Detection:* Build a leak-free ML pipeline comparing Random Forest, SVM, and MLP.
  2. *Adversarial Robustness:* Formulate a grey-box evasion threat model and evaluate defensive retraining.
  3. *Explainable AI (XAI):* Demystify model decisions with global and local SHAP explanations.
  4. *Human-Centric Alerts:* Translate complex feature attributions into plain-English SOC advisories.
  5. *Interactive Demonstration:* Deploy a multi-tab Streamlit web dashboard for live operational testing.

---

## Slide 3: Proposed End-to-End System Architecture
```
[UCI Phishing Dataset] ──> [Stratified Leak-Free Split]
                                 │
     ┌───────────────────────────┴───────────────────────────┐
     ▼                                                       ▼
[Multi-Model ML Detection]                       [Adversarial Hardening]
(RF, SVM, MLP Benchmark)                         (Data Augmentation & Retrain)
     │                                                       │
     └───────────────────────────┬───────────────────────────┘
                                 ▼
                     [Explainable AI (SHAP)]
                  (TreeExplainer & SOC Alerts)
                                 │
                                 ▼
                 [Interactive Streamlit Dashboard]
```

---

## Slide 4: Dataset & Leak-Free Preprocessing
- **UCI Phishing Websites Dataset:** 11,055 total samples, 30 website features, balanced class distribution (55.7% phishing vs. 44.3% legitimate).
- **Zero-Leakage Engineering Pipeline:**
  - Target remapped to `{0: Legitimate, 1: Phishing}`.
  - Stratified 80/20 train/test split (8,844 train vs. 2,211 test samples).
  - Scalers and selectors fitted **strictly on the training partition**.
- **Mutual Information Top Features:** `SSLfinal_State` (0.346), `URL_of_Anchor` (0.332), `Prefix_Suffix` (0.093), `having_Sub_Domain` (0.084).

---

## Slide 5: Multi-Model Machine Learning Classifiers
- **1. Random Forest (Primary Model):**
  - Ensemble of 100 decorrelated decision trees with max depth 15.
  - Captures non-linear feature interactions with < 1 ms inference latency.
- **2. Support Vector Machine (SVM):**
  - RBF kernel with calibrated probability estimates on standardized inputs.
- **3. Artificial Neural Network (MLP):**
  - Deep architecture with hidden layers `(64, 32)`, ReLU activations, and Adam optimization.

---

## Slide 6: Performance Benchmark & Primary Model Selection
| Metric | Random Forest (Selected) | SVM (RBF) | MLP (ANN) |
| :--- | :---: | :---: | :---: |
| **Accuracy** | **96.47%** | 95.16% | **97.20%** |
| **Precision** | **96.64%** | 94.75% | **97.33%** |
| **Recall** | **97.10%** | 96.75% | **97.69%** |
| **F1-Score** | **0.9687** | 0.9574 | **0.9751** |
| **ROC-AUC** | **0.9930** | 0.9871 | **0.9939** |
| **False Negative Rate** | **2.35%** | **2.68%** | **2.19%** |
| **Inference Speed** | **< 1 ms (Real-time)** | 18 ms | 2 ms |

**Selection Rationale:** Random Forest delivers the optimal blend of speed, low False Negative Rate (2.35%), and polynomial-time tree explainability via SHAP.

---

## Slide 7: Adversarial Threat Modeling & Evasion Attacks
- **Threat Actor Capabilities:** Grey-box attacker manipulating operator-controlled features.
- **Targeted Perturbations:**
  - Procuring valid SSL certificates (`SSLfinal_State -> -1`).
  - Removing suspicious domain hyphens (`Prefix_Suffix -> -1`).
  - Hosting external images/scripts locally (`Request_URL -> -1`).
- **Empirical Evasion Rates (Tested on 1,202 True Phishing Sites):**
  - *Mild Attack (SSL + Prefix):* **42.26% Evasion**
  - *Moderate Attack (+Request +Subdomain):* **68.72% Evasion** (Confidence dropped from 94.4% to 40.0%)
  - *Aggressive Attack (All 7 Features):* **73.54% Evasion**

---

## Slide 8: Defensive Hardening via Adversarial Training
- **Mitigation Strategy:** Adversarial Data Augmentation strictly within the training fold.
- **Defensive Retraining:** Trained a hardened Random Forest model on 11,799 clean + synthetic adversarial samples.
- **Hardening Results:**
  - **Moderate Attack Evasion Rate:** Plummets from **68.72% down to 0.41%** (>99% relative reduction).
  - **Clean Test Accuracy:** Preserved at **96.25%** (negligible utility trade-off).
  - **Clean Test F1-Score:** Retained at **0.9667**.

---

## Slide 9: Explainable AI: Global Feature Impact (SHAP)
- **Framework:** Integrated `shap.TreeExplainer` on the primary Random Forest classifier.
- **Global Decision Dynamics:**
  - `SSLfinal_State`: Single most influential attribute distinguishing security authenticity.
  - `URL_of_Anchor`: High percentage of dead or foreign links strongly increases phishing risk.
  - `Prefix_Suffix`: Domain hyphens mimic corporate trademarks.
  - `web_traffic` & `having_Sub_Domain`: Infrastructure depth and lack of web reputation.

---

## Slide 10: Local Explainability & Plain-Language SOC Advisories
- **The Problem:** SOC analysts cannot act on raw mathematical weights or opaque probabilities.
- **The Solution:** Engineered an automated translation engine converting local waterfall attributions into structured, plain-language security alerts.
- **Sample Advisory Component:**
  - `Classification:` PHISHING (Confidence: 94.2%) | Threat Level: CRITICAL
  - `Top Risk Factor:` Untrusted or absent SSL certificate (+0.28 risk)
  - `Top Risk Factor:` URL Anchor Tag points to foreign domains (+0.21 risk)
  - `Containment Recommendation:` Block host at proxy; revoke session tokens.

---

## Slide 11: Interactive Streamlit Demonstration Walkthrough
- **Tab 1: Overview & Architecture:** High-level project metrics and end-to-end flowchart.
- **Tab 2: Live Sample Scanner:** Dynamic sample selector, multi-model execution, phishing gauges, local SHAP waterfall charts, and automated SOC advisories.
- **Tab 3: Model Performance:** Multi-model confusion matrices and ROC curves.
- **Tab 4: Adversarial Playground:** Live feature perturbation toggles comparing vulnerable baseline vs. hardened robust models.

---

## Slide 12: Ethical Considerations, Dual-Use, and Privacy
- **Responsible Research & Dual-Use Protection:**
  - Adversarial testing strictly limited to closed feature-space simulations; no functional weaponized attack tools were generated.
- **Privacy Assurance:**
  - Dataset evaluated contains pre-extracted, anonymized statistical attributes with zero PII or credentials.
- **Enterprise Impact:**
  - Defensively reduces SOC alert fatigue and demystifies automated containment decisions.

---

## Slide 13: System Limitations & Future Scope
- **Current Limitations:**
  - Evaluated on pre-extracted tabular features; production deployments require an inline feature extraction microservice.
  - Advanced dynamic JavaScript evasions (e.g. cloaking/CAPTCHAs) require execution analysis.
- **Future Roadmap:**
  - Build headless Chromium DOM extractor for raw URL input.
  - Fine-tune multi-modal Vision-Language Transformers for simultaneous logo and text analysis.

---

## Slide 14: Conclusion & Deliverables Summary
- **Capstone Deliverables Completed:**
  - ✅ 15 GitHub Issues completed and tracked across 8 milestones.
  - ✅ Multi-model ML pipeline (Random Forest 96.47% accuracy, 96.87% F1).
  - ✅ Adversarial evasion quantified (68.7%) and mitigated (0.41%).
  - ✅ Global & Local Explainable AI (SHAP TreeExplainer & SOC alerts).
  - ✅ Operational interactive Streamlit web dashboard.
  - ✅ Comprehensive 17-section capstone report & slide deck.
- **Project Repository:** https://github.com/Kush05Bhardwaj/Phishing-Detection
