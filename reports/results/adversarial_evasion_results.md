# Adversarial Evasion Attack Simulation — Security Report

## 1. Threat Model Formulation
- **Attacker Profile:** Skilled adversary seeking to bypass standard ML-based web security filters.
- **Knowledge Level:** Grey-box (knows high-leverage features like SSL certificates and URL formatting, but lacks full weights).
- **Feasible Manipulations:**
  1. *Mild:* Acquiring valid SSL certificate (`SSLfinal_State -> -1`) and eliminating hyphenated prefixes (`Prefix_Suffix -> -1`).
  2. *Moderate:* Also hosting external images/scripts locally (`Request_URL -> -1`) and flattening subdomain hierarchies (`having_Sub_Domain -> -1`).
  3. *Aggressive:* Modifying all 7 operator-controlled features.

## 2. Experimental Evasion Findings
| Attack Intensity | Features Perturbed | Phishing Samples Tested | Evaded Filter Count | Evasion Success Rate | Mean Confidence Drop |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **Mild** | SSL + Prefix | 1202 | 508 | **42.26%** | -39.7% |
| **Moderate** | SSL + Prefix + Request + Subdomain | 1202 | 826 | **68.72%** | -54.4% |
| **Aggressive** | All 7 Manipulable Features | 1202 | 884 | **73.54%** | -53.9% |

## 3. Vulnerability Insights
- Relying predominantly on surface indicators like SSL validity creates a critical single-point of failure: threat actors routinely deploy free Let's Encrypt certificates to spoof legitimacy.
- Without adversarial training or deep behavioral heuristics, 68.7% of active phishing sites can slip past the baseline model under moderate perturbation.
