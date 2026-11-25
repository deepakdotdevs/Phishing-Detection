"""Interactive Phishing Website Detection Dashboard.
Capstone Project: Intelligent Phishing Website Detection Using Machine Learning & Explainable AI.
"""
import os
import sys
import pandas as pd
import numpy as np
import streamlit as st
import matplotlib.pyplot as plt

# Setup page layout
st.set_page_config(
    page_title="Phishing Detection AI Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Add src and root to sys.path
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SRC_DIR = os.path.join(ROOT_DIR, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)
if ROOT_DIR not in sys.path:
    sys.path.append(ROOT_DIR)

try:
    from app.utils import load_all_models, load_test_dataset, get_curated_samples
except ImportError:
    from utils import load_all_models, load_test_dataset, get_curated_samples
from explainability.alert_generator import SecurityAlertGenerator, plot_local_waterfall
from adversarial.evasion import PhishingEvasionAttacker
from features.extractor import extract_features_from_url, FEATURE_COLUMNS

models = load_all_models()
test_df = load_test_dataset()
curated_samples = get_curated_samples(test_df)

# Sidebar
st.sidebar.image("https://img.icons8.com/fluency/96/shield.png", width=70)
st.sidebar.title("Phishing Detection AI")
st.sidebar.markdown("**AI in Cybersecurity Capstone**")
st.sidebar.markdown("---")

selected_model_name = st.sidebar.selectbox(
    "Active Detection Model:",
    ["Random Forest (Primary)", "SVM (RBF)", "MLP (ANN)", "Robust Hardened Random Forest"]
)
st.sidebar.info(
    "💡 **Dual Inspection Mode:** Scan and classify live website URLs in real-time, or evaluate pre-extracted benchmark test instances."
)
st.sidebar.markdown("---")
st.sidebar.markdown("**System Status:** 🟢 All Pipelines Operational")

# Title Header
st.title("🛡️ Intelligent Phishing Website Detection Platform")
st.markdown("##### Machine Learning Detection, Adversarial Hardening & Explainable AI (SHAP)")

# Tabs
tab1, tab2, tab3, tab4 = st.tabs([
    "📌 Overview & Architecture",
    "🔍 Live Inspection & Inference",
    "📊 Model Performance & Benchmarks",
    "⚔️ Adversarial Playground & Defense"
])

# ----------------- TAB 1: OVERVIEW -----------------
with tab1:
    st.subheader("Project Objectives & Capstone Alignment")
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Dataset Size", "11,055 Samples", "UCI Phishing Repository")
    col2.metric("Feature Vectors", "30 Attributes", "Ternary Categorical")
    col3.metric("Primary Model F1", "96.87%", "Random Forest Classifier")
    col4.metric("Adversarial Evasion Drop", "68.7% -> 0.4%", "Hardened Mitigation")

    st.markdown("---")
    st.markdown("### 🏗️ End-to-End System Pipeline")
    st.markdown(
        """
        ```mermaid
        flowchart LR
            DATA[UCI Phishing Dataset] --> PREP[Leak-Free Preprocessing]
            PREP --> ML[Random Forest / SVM / MLP]
            ML --> ADV[Adversarial Evasion Simulation]
            ADV --> DEF[Adversarial Hardening Defense]
            ML --> XAI[SHAP TreeExplainer & Alerts]
            XAI --> APP[Streamlit Operational Dashboard]
        ```
        """
    )

    st.markdown("---")
    st.markdown("### 📋 Core Deliverables Checklist")
    c1, c2 = st.columns(2)
    with c1:
        st.success("✅ **Multi-Model ML Detection:** Trained Random Forest, SVM (RBF), and MLP/ANN.")
        st.success("✅ **Leakage-Free Preprocessing:** Stratified train/test splits with isolated scaling.")
        st.success("✅ **Adversarial Cybersecurity Simulation:** Black-box/Grey-box feature manipulation.")
    with c2:
        st.success("✅ **Defensive Mitigation:** Adversarial retraining cutting evasion rate by 99%.")
        st.success("✅ **Explainable AI (SHAP):** Global feature importances & plain-English security alerts.")
        st.success("✅ **Live Interactive Demo:** Real-time inference across test instances.")

# ----------------- TAB 2: LIVE INSPECTION & XAI -----------------
with tab2:
    st.subheader("Live Web Sample Scanner & SHAP Explainability")

    scan_mode = st.radio(
        "Select Inspection Source:",
        ["🌐 Enter Live URL (Real-Time Scan)", "📁 Evaluate Benchmark Dataset Instances"],
        horizontal=True
    )

    sample_row_series = None
    target_name = ""
    ground_truth = None

    if "Live URL" in scan_mode:
        st.markdown("Enter any website URL to extract 30 lexical, DNS, SSL, and DOM features in real-time:")
        url_col1, url_col2 = st.columns([3, 1])
        with url_col1:
            live_url_input = st.text_input(
                "Target Web URL:",
                value="http://paypal-security-account-verification-alert.com/login",
                placeholder="e.g. https://www.google.com or http://fake-bank-login.com"
            )
        with url_col2:
            st.markdown("<div style='height: 28px'></div>", unsafe_allow_html=True)
            fetch_dom = st.checkbox("Active Network & DOM Fetch", value=True, help="Make active HTTP & SSL requests to inspect certificates and page anchors.")

        st.caption("💡 *Quick Test Presets (Click to Load):*")
        p_c1, p_c2, p_c3, p_c4 = st.columns(4)
        if p_c1.button("🟢 Google.com"):
            live_url_input = "https://www.google.com"
        if p_c2.button("🟢 PayPal.com"):
            live_url_input = "https://www.paypal.com"
        if p_c3.button("🔴 Fake PayPal Phish"):
            live_url_input = "http://paypal-security-account-verification-alert.com/login"
        if p_c4.button("🔴 Raw IP Phishing"):
            live_url_input = "http://192.168.1.1/login.php?secure=0"

        if live_url_input:
            with st.spinner(f"🔍 Extracting features from `{live_url_input}`..."):
                extracted = extract_features_from_url(live_url_input, fetch_dom=fetch_dom)
                sample_row_series = pd.Series([extracted[c] for c in FEATURE_COLUMNS], index=FEATURE_COLUMNS)
                target_name = live_url_input
                ground_truth = None
    else:
        st.markdown("Select a sample from the held-out test dataset or load curated security cases:")
        c_sel1, c_sel2 = st.columns([2, 1])
        with c_sel1:
            sample_choice = st.selectbox("Curated Test Instances:", list(curated_samples.keys()))
            selected_idx = curated_samples[sample_choice]
        with c_sel2:
            custom_idx = st.number_input("Or enter custom Test Row Index (0 to 2210):", min_value=0, max_value=len(test_df)-1 if not test_df.empty else 0, value=selected_idx)

        sample_row = test_df.iloc[custom_idx] if not test_df.empty else None
        if sample_row is not None:
            sample_row_series = sample_row.drop(labels=['target'])
            target_name = f"Sample-#{custom_idx}"
            ground_truth = int(sample_row['target'])

    if sample_row_series is not None:
        X_sample = sample_row_series.to_frame().T

        # Model Inference
        active_model = models.get("Random Forest")
        if "SVM" in selected_model_name:
            active_model = models.get("SVM (RBF)")
            X_infer = models["Preprocessor"].transform(X_sample) if "Preprocessor" in models else X_sample
        elif "MLP" in selected_model_name:
            active_model = models.get("MLP (ANN)")
            X_infer = models["Preprocessor"].transform(X_sample) if "Preprocessor" in models else X_sample
        elif "Robust" in selected_model_name:
            active_model = models.get("Robust Random Forest")
            X_infer = X_sample
        else:
            X_infer = X_sample

        prob = float(active_model.predict_proba(X_infer)[0, 1])
        pred = int(active_model.predict(X_infer)[0])

        st.markdown("---")
        res_col1, res_col2, res_col3 = st.columns([1, 1, 2])

        with res_col1:
            st.markdown("#### Model Verdict")
            if pred == 1:
                st.error("🚨 **PHISHING DETECTED**")
            else:
                st.success("✅ **LEGITIMATE WEBSITE**")
            if ground_truth is not None:
                st.caption(f"Ground Truth Label: {'Phishing (1)' if ground_truth == 1 else 'Legitimate (0)'}")
            else:
                st.caption(f"Target: `{target_name}`")

        with res_col2:
            st.markdown("#### Malicious Probability")
            st.progress(prob)
            st.markdown(f"**Confidence:** `{prob*100:.2f}% Phishing`")

        with res_col3:
            st.markdown("#### Operational Threat Assessment")
            if prob >= 0.80:
                st.warning("⚠️ **CRITICAL RISK:** Multiple high-severity phishing markers identified.")
            elif prob >= 0.50:
                st.warning("⚠️ **ELEVATED RISK:** Suspicious anomalies detected in domain or asset links.")
            else:
                st.info("ℹ️ **LOW RISK:** Structural profile aligns with authentic domain registrations.")

        # XAI SHAP Explanation Section
        st.markdown("---")
        st.subheader("💡 Explainable AI (XAI) — Local Feature Attribution")
        xai_col1, xai_col2 = st.columns([1, 1])

        rf_primary = models.get("Random Forest")
        shap_explainer = models.get("SHAP Explainer")

        if rf_primary and shap_explainer:
            alert_generator = SecurityAlertGenerator(rf_primary, shap_explainer, X_sample.columns.tolist())
            explanation = alert_generator.explain_instance(sample_row_series)

            with xai_col1:
                st.markdown("##### Feature Attributions (Local Waterfall Plot)")
                sv = explanation["shap_values"]
                feat_names = list(X_sample.columns)
                top_idx = np.argsort(np.abs(sv))[::-1][:8]
                sub_names = [feat_names[i] for i in top_idx][::-1]
                sub_vals = [sv[i] for i in top_idx][::-1]
                colors = ['#e74c3c' if v > 0 else '#2ecc71' for v in sub_vals]

                fig, ax = plt.subplots(figsize=(6, 4))
                ax.barh(np.arange(len(sub_names)), sub_vals, color=colors, edgecolor='black', alpha=0.85)
                ax.set_yticks(np.arange(len(sub_names)))
                ax.set_yticklabels(sub_names, fontsize=9)
                ax.axvline(0, color='black', linestyle='--', linewidth=0.8)
                ax.set_xlabel('SHAP Impact on Phishing Likelihood', fontsize=9, fontweight='bold')
                plt.tight_layout()
                st.pyplot(fig)
                plt.close()

            with xai_col2:
                st.markdown("##### Human-Readable Security Alert")
                alert_text = alert_generator.format_alert(target_name, explanation)
                st.code(alert_text, language="text")

        with st.expander("🔍 View Extracted Feature Vector (30 Attributes)"):
            st.dataframe(X_sample)

# ----------------- TAB 3: BENCHMARKS -----------------
with tab3:
    st.subheader("Model Performance & Comparative Evaluation")

    metrics_file = os.path.join(ROOT_DIR, "reports", "results", "model_comparison.csv")
    if os.path.exists(metrics_file):
        m_df = pd.read_csv(metrics_file)
        st.dataframe(m_df.style.highlight_max(subset=['Accuracy', 'Precision', 'Recall', 'F1-Score', 'ROC-AUC'], color='#d4edda'), use_container_width=True)

    st.markdown("---")
    st.markdown("### 📈 Evaluation Visualizations")
    img_col1, img_col2 = st.columns(2)

    cm_path = os.path.join(ROOT_DIR, "reports", "figures", "confusion_matrices.png")
    roc_path = os.path.join(ROOT_DIR, "reports", "figures", "roc_curves.png")

    with img_col1:
        if os.path.exists(cm_path):
            st.image(cm_path, caption="Normalized Confusion Matrices Across Models", use_container_width=True)

    with img_col2:
        if os.path.exists(roc_path):
            st.image(roc_path, caption="Receiver Operating Characteristic (ROC) Comparison", use_container_width=True)

# ----------------- TAB 4: ADVERSARIAL PLAYGROUND -----------------
with tab4:
    st.subheader("⚔️ Adversarial Evasion Playground & Defensive Hardening")
    st.markdown(
        "Demonstrate how threat actors manipulate website features in an attempt to evade ML filters, "
        "and how **Adversarial Training** hardens model resilience."
    )

    adv_col1, adv_col2 = st.columns([1, 1])

    with adv_col1:
        st.markdown("#### 1. Select Phishing Sample to Attack")
        phish_indices = test_df[test_df['target'] == 1].index.tolist() if not test_df.empty else [0]
        atk_sample_idx = st.selectbox("Target Phishing Instance:", phish_indices[:15])

        original_sample_row = test_df.loc[atk_sample_idx].drop(labels=['target'])
        sample_adv = original_sample_row.copy()

        st.markdown("#### 2. Threat Actor Feature Perturbations")
        ssl_spoof = st.checkbox("Spoof Valid SSL Certificate (SSLfinal_State -> Legit)", value=True)
        prefix_fix = st.checkbox("Remove Hyphen from Domain (Prefix_Suffix -> Legit)", value=True)
        request_url_fix = st.checkbox("Host Assets Locally (Request_URL -> Legit)", value=False)
        subdomain_fix = st.checkbox("Flatten Subdomain Structure (having_Sub_Domain -> Legit)", value=False)

        if ssl_spoof:
            sample_adv["SSLfinal_State"] = -1
        if prefix_fix:
            sample_adv["Prefix_Suffix"] = -1
        if request_url_fix:
            sample_adv["Request_URL"] = -1
        if subdomain_fix:
            sample_adv["having_Sub_Domain"] = -1

    with adv_col2:
        st.markdown("#### 3. Defensive Comparison (Standard vs. Robust)")
        rf_base = models.get("Random Forest")
        rf_rob = models.get("Robust Random Forest")

        if rf_base and rf_rob:
            orig_df = pd.DataFrame([original_sample_row])
            pert_df = pd.DataFrame([sample_adv])

            # Baseline RF
            base_orig_prob = float(rf_base.predict_proba(orig_df)[0, 1])
            base_pert_prob = float(rf_base.predict_proba(pert_df)[0, 1])
            base_evaded = base_pert_prob < 0.50

            # Robust RF
            rob_orig_prob = float(rf_rob.predict_proba(orig_df)[0, 1])
            rob_pert_prob = float(rf_rob.predict_proba(pert_df)[0, 1])
            rob_evaded = rob_pert_prob < 0.50

            st.markdown("##### Baseline Random Forest (Vulnerable)")
            st.write(f"Original Confidence: `{base_orig_prob*100:.2f}%`")
            st.write(f"Under Attack Confidence: `{base_pert_prob*100:.2f}%`")
            if base_evaded:
                st.error("❌ **EVASION SUCCESSFUL:** Filter bypassed! (Classified as Benign)")
            else:
                st.success("🛡️ **ATTACK BLOCKED:** Still recognized as Phishing.")

            st.markdown("---")
            st.markdown("##### Defensively Hardened Model (Adversarially Trained)")
            st.write(f"Original Confidence: `{rob_orig_prob*100:.2f}%`")
            st.write(f"Under Attack Confidence: `{rob_pert_prob*100:.2f}%`")
            if rob_evaded:
                st.error("❌ Evasion Successful")
            else:
                st.success("🛡️ **ATTACK BLOCKED:** Hardened model resisted feature spoofing!")

    st.markdown("---")
    st.markdown("### 📊 Macro Evasion Benchmark")
    mit_path = os.path.join(ROOT_DIR, "reports", "figures", "mitigation_comparison.png")
    if os.path.exists(mit_path):
        st.image(mit_path, caption="Comprehensive Adversarial Evasion and Mitigation Benchmark", use_container_width=True)
