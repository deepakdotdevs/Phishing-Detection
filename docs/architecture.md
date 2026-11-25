# System Architecture: Intelligent Phishing Detection & Explainable AI

This document outlines the end-to-end architecture for the Capstone Project: **Intelligent Phishing Website Detection Using Machine Learning and Explainable AI**.

```mermaid
flowchart TD
    subgraph DataIngestion["1. Data Ingestion & Preprocessing"]
        RAW["UCI Phishing Websites Dataset (11,055 samples, 30 features)"]
        SPLIT["Stratified 80/20 Train/Test Split (random_state=42)"]
        SCALER["StandardScaler & OneHot/Label Mapping"]
        SELECT["Feature Selection (RFE / Mutual Info)"]
        RAW --> SPLIT
        SPLIT -->|Train Fold Only| SCALER --> SELECT --> TRAIN_DATA["data/processed/train.parquet"]
        SPLIT -->|Test Fold Only| TRANSFORM["Transform (No Fit)"] --> TEST_DATA["data/processed/test.parquet"]
    end

    subgraph Modeling["2. Supervised Learning & Evaluation"]
        TRAIN_DATA --> RF["Random Forest (Primary)"]
        TRAIN_DATA --> SVM["Support Vector Machine (RBF)"]
        TRAIN_DATA --> MLP["MLP Neural Network"]
        RF & SVM & MLP --> EVAL["Comparative Evaluation (Accuracy, Precision, Recall, F1, ROC-AUC)"]
        EVAL --> ARTIFACTS["Serialized Models (models/*.joblib)"]
    end

    subgraph SecurityDefense["3. Adversarial Attack & Mitigation"]
        TEST_DATA --> ATTACK["Feature Perturbation Generator"]
        ATTACK --> EVASION["Evasion Simulation & Confidence Degradation"]
        EVASION --> ADV_TRAIN["Adversarial Retraining (Data Augmentation)"]
        ADV_TRAIN --> ROBUST_RF["Robust Random Forest Model"]
    end

    subgraph XAI["4. Explainable AI (SHAP)"]
        RF --> TREE_EXPL["SHAP TreeExplainer"]
        TEST_DATA --> TREE_EXPL
        TREE_EXPL --> GLOBAL_XAI["Global Feature Importance & Beeswarm"]
        TREE_EXPL --> LOCAL_XAI["Local Waterfall Plots & Feature Attributions"]
        LOCAL_XAI --> ALERT_GEN["SOC-Readable Security Alert Engine"]
    end

    subgraph UI["5. Interactive Web Demonstration"]
        ARTIFACTS & ROBUST_RF & ALERT_GEN --> STREAMLIT["Streamlit Web Dashboard (app/streamlit_app.py)"]
        STREAMLIT --> T1["Overview & Architecture"]
        STREAMLIT --> T2["Live Inspection & Risk Scoring"]
        STREAMLIT --> T3["Model Metrics & Benchmarking"]
        STREAMLIT --> T4["Adversarial Playground & Defense"]
    end
```
