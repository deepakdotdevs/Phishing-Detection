# Plain-Language Explainable AI Security Alerts

This document records the human-readable security advisories automatically compiled from local SHAP waterfall feature attributions.

---

## 1. High-Confidence Phishing Incident
```
==============================================================================
SECURITY INCIDENT ALERT: PHISHING DETECTION
==============================================================================
Target Sample Identifier : Sample-#2 (True Phishing)
Detection Classification : PHISHING (Model Confidence: 98.95%)
Evaluated Threat Level   : CRITICAL
------------------------------------------------------------------------------
KEY THREAT RISK CONTRIBUTORS (Factors Driving Malicious Assessment):
  [+] Untrusted or absent SSL certificate                  [+0.104 SHAP]
  [+] High percentage of invalid or empty hyperlink anchors [+0.102 SHAP]
  [+] Domain contains hyphen ('-') imitating brand         [+0.093 SHAP]
  [+] Low or non-existent web traffic rank                 [+0.037 SHAP]
------------------------------------------------------------------------------
KEY MITIGATING / PROTECTIVE CONTRIBUTORS (Factors Driving Legitimacy):
  [-] No valid DNS host records found                      [-0.012 SHAP]
------------------------------------------------------------------------------
ACTIONABLE SOC RECOMMENDATION:
  [!] QUARANTINE: Block web traffic to this host at the perimeter proxy.
  [!] Revoke any cached user credentials entered within the session window.
==============================================================================
```

---

## 2. Verified Legitimate Website Audit
```
==============================================================================
SECURITY INCIDENT ALERT: LEGITIMATE DETECTION
==============================================================================
Target Sample Identifier : Sample-#0 (Legitimate Website)
Detection Classification : LEGITIMATE (Model Confidence: 0.28%)
Evaluated Threat Level   : LOW / BENIGN
------------------------------------------------------------------------------
KEY THREAT RISK CONTRIBUTORS (Factors Driving Malicious Assessment):
  [+] Meta/script/link tags point to external domains      [+0.018 SHAP]
------------------------------------------------------------------------------
KEY MITIGATING / PROTECTIVE CONTRIBUTORS (Factors Driving Legitimacy):
  [-] High percentage of invalid or empty hyperlink anchors [-0.236 SHAP]
  [-] Untrusted or absent SSL certificate                  [-0.193 SHAP]
  [-] Suspicious multi-level subdomains present            [-0.038 SHAP]
  [-] Domain contains hyphen ('-') imitating brand         [-0.028 SHAP]
------------------------------------------------------------------------------
ACTIONABLE SOC RECOMMENDATION:
  [*] ALLOW: Traffic profile conforms to trusted legitimate operational patterns.
==============================================================================
```

---

## 3. Adversarially Manipulated Evasion Sample
```
==============================================================================
SECURITY INCIDENT ALERT: PHISHING DETECTION
==============================================================================
Target Sample Identifier : Sample-#2-ADV (Perturbed Phishing)
Detection Classification : PHISHING (Model Confidence: 57.98%)
Evaluated Threat Level   : ELEVATED
------------------------------------------------------------------------------
KEY THREAT RISK CONTRIBUTORS (Factors Driving Malicious Assessment):
  [+] High percentage of invalid or empty hyperlink anchors [+0.178 SHAP]
  [+] Low or non-existent web traffic rank                 [+0.067 SHAP]
  [+] Server Form Handler is empty or foreign domain       [+0.044 SHAP]
  [+] Meta/script/link tags point to external domains      [+0.041 SHAP]
------------------------------------------------------------------------------
KEY MITIGATING / PROTECTIVE CONTRIBUTORS (Factors Driving Legitimacy):
  [-] Untrusted or absent SSL certificate                  [-0.254 SHAP]
  [-] Suspicious multi-level subdomains present            [-0.050 SHAP]
  [-] High percentage of external images and objects       [-0.045 SHAP]
  [-] Domain contains hyphen ('-') imitating brand         [-0.022 SHAP]
------------------------------------------------------------------------------
ACTIONABLE SOC RECOMMENDATION:
  [!] QUARANTINE: Block web traffic to this host at the perimeter proxy.
  [!] Revoke any cached user credentials entered within the session window.
==============================================================================
```
