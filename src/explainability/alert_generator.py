"""Plain-English SOC security alert generator powered by local SHAP explanations."""
import pandas as pd
import numpy as np
import shap
import matplotlib.pyplot as plt

FEATURE_TRANSLATION_MAP = {
    "having_IP_Address": "IP address used instead of domain name",
    "URL_Length": "Abnormally long URL length",
    "Shortining_Service": "URL shortening service used to disguise target",
    "having_At_Symbol": "URL contains '@' symbol to obfuscate host",
    "double_slash_redirecting": "Redirecting '//' located in URL path",
    "Prefix_Suffix": "Domain contains hyphen ('-') imitating brand",
    "having_Sub_Domain": "Suspicious multi-level subdomains present",
    "SSLfinal_State": "Untrusted or absent SSL certificate",
    "Domain_registeration_length": "Domain registered for less than one year",
    "Favicon": "Favicon loaded from external untrusted host",
    "port": "Non-standard server port queried",
    "HTTPS_token": "'https' string inserted into domain name",
    "Request_URL": "High percentage of external images and objects",
    "URL_of_Anchor": "High percentage of invalid or empty hyperlink anchors",
    "Links_in_tags": "Meta/script/link tags point to external domains",
    "SFH": "Server Form Handler is empty or foreign domain",
    "Submitting_to_email": "Form submits sensitive data directly via mailto:",
    "Abnormal_URL": "Host name not matching WHOIS record",
    "Redirect": "Multiple consecutive page redirects",
    "on_mouseover": "JavaScript onMouseOver alters status bar text",
    "RightClick": "Right-click context menu disabled to prevent inspection",
    "popUpWidnow": "Pop-up window prompts for credential input",
    "Iframe": "Hidden iframe elements detected in webpage DOM",
    "age_of_domain": "Domain created very recently (immature age)",
    "DNSRecord": "No valid DNS host records found",
    "web_traffic": "Low or non-existent web traffic rank",
    "Page_Rank": "Low Google PageRank score",
    "Google_Index": "Webpage not indexed in Google Search",
    "Links_pointing_to_page": "Zero external inbound backlinks",
    "Statistical_report": "Host matches known phishing threat intelligence lists"
}


class SecurityAlertGenerator:
    """Generates structured, human-readable security advisories for SOC analysts."""

    def __init__(self, model, explainer, feature_names):
        self.model = model
        self.explainer = explainer
        self.feature_names = feature_names

    def explain_instance(self, instance_series: pd.Series) -> dict:
        """Calculate local SHAP values and structure explanation."""
        instance_df = pd.DataFrame([instance_series])
        
        prob = float(self.model.predict_proba(instance_df)[0, 1])
        pred = int(self.model.predict(instance_df)[0])

        shap_vals = self.explainer.shap_values(instance_df)
        if isinstance(shap_vals, list):
            sv = shap_vals[1][0]
            base_val = self.explainer.expected_value[1] if isinstance(self.explainer.expected_value, (list, np.ndarray)) else self.explainer.expected_value
        elif len(shap_vals.shape) == 3:
            sv = shap_vals[0, :, 1]
            base_val = self.explainer.expected_value[1] if isinstance(self.explainer.expected_value, (list, np.ndarray)) else self.explainer.expected_value
        else:
            sv = shap_vals[0]
            base_val = self.explainer.expected_value

        # Top positive risk drivers (increasing phishing likelihood)
        risk_indices = np.argsort(sv)[::-1]
        top_risk_factors = []
        for idx in risk_indices:
            if sv[idx] > 0.01:
                feat = self.feature_names[idx]
                top_risk_factors.append({
                    "feature": feat,
                    "plain_description": FEATURE_TRANSLATION_MAP.get(feat, feat),
                    "raw_value": int(instance_series[feat]),
                    "shap_contribution": float(sv[idx])
                })

        # Top protective factors (decreasing phishing likelihood)
        protective_indices = np.argsort(sv)
        top_protective_factors = []
        for idx in protective_indices:
            if sv[idx] < -0.01:
                feat = self.feature_names[idx]
                top_protective_factors.append({
                    "feature": feat,
                    "plain_description": FEATURE_TRANSLATION_MAP.get(feat, feat),
                    "raw_value": int(instance_series[feat]),
                    "shap_contribution": float(sv[idx])
                })

        return {
            "prediction": "PHISHING" if pred == 1 else "LEGITIMATE",
            "phishing_probability": prob,
            "base_value": float(base_val),
            "top_risk_factors": top_risk_factors[:4],
            "top_protective_factors": top_protective_factors[:4],
            "shap_values": sv,
            "raw_instance": instance_series
        }

    def format_alert(self, sample_id: str, explanation: dict) -> str:
        """Format an explanation into a plain-text SOC security advisory."""
        status = explanation["prediction"]
        prob = explanation["phishing_probability"] * 100
        threat_level = "CRITICAL" if prob >= 85 else ("HIGH" if prob >= 60 else ("ELEVATED" if prob >= 50 else "LOW / BENIGN"))

        lines = [
            "=" * 78,
            f"SECURITY INCIDENT ALERT: {status} DETECTION",
            "=" * 78,
            f"Target Sample Identifier : {sample_id}",
            f"Detection Classification : {status} (Model Confidence: {prob:.2f}%)",
            f"Evaluated Threat Level   : {threat_level}",
            "-" * 78,
            "KEY THREAT RISK CONTRIBUTORS (Factors Driving Malicious Assessment):"
        ]

        if explanation["top_risk_factors"]:
            for f in explanation["top_risk_factors"]:
                lines.append(f"  [+] {f['plain_description']:<52} [+{f['shap_contribution']:.3f} SHAP]")
        else:
            lines.append("  None detected.")

        lines.append("-" * 78)
        lines.append("KEY MITIGATING / PROTECTIVE CONTRIBUTORS (Factors Driving Legitimacy):")
        if explanation["top_protective_factors"]:
            for f in explanation["top_protective_factors"]:
                lines.append(f"  [-] {f['plain_description']:<52} [{f['shap_contribution']:.3f} SHAP]")
        else:
            lines.append("  None detected.")

        lines.append("-" * 78)
        if status == "PHISHING":
            lines.append("ACTIONABLE SOC RECOMMENDATION:")
            lines.append("  [!] QUARANTINE: Block web traffic to this host at the perimeter proxy.")
            lines.append("  [!] Revoke any cached user credentials entered within the session window.")
        else:
            lines.append("ACTIONABLE SOC RECOMMENDATION:")
            lines.append("  [*] ALLOW: Traffic profile conforms to trusted legitimate operational patterns.")
        lines.append("=" * 78)
        return "\n".join(lines)


def plot_local_waterfall(explanation: dict, output_path: str):
    """Generate a clean local waterfall plot using matplotlib."""
    sv = explanation["shap_values"]
    feat_names = list(explanation["raw_instance"].index)
    
    # Sort by absolute SHAP impact
    top_indices = np.argsort(np.abs(sv))[::-1][:10]
    sub_names = [feat_names[i] for i in top_indices][::-1]
    sub_vals = [sv[i] for i in top_indices][::-1]
    
    colors = ['#e74c3c' if v > 0 else '#2ecc71' for v in sub_vals]

    plt.figure(figsize=(10, 5))
    y_pos = np.arange(len(sub_names))
    plt.barh(y_pos, sub_vals, color=colors, edgecolor='black', alpha=0.85)
    plt.yticks(y_pos, sub_names, fontsize=10)
    plt.axvline(0, color='black', linestyle='--', linewidth=0.8)
    plt.xlabel('SHAP Value (Contribution to Phishing Score)', fontsize=11, fontweight='bold')
    plt.title(f'Local Feature Contributions ({explanation["prediction"]} - Prob: {explanation["phishing_probability"]*100:.1f}%)', fontsize=12, fontweight='bold')
    plt.grid(axis='x', alpha=0.3)
    plt.tight_layout()
    plt.savefig(output_path, dpi=300)
    plt.close()
