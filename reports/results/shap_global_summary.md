# Global Model Explainability Analysis (SHAP TreeExplainer)

## 1. Executive Summary
Using **SHapley Additive exPlanations (SHAP)** with a tree-specific algorithm on the primary Random Forest classifier, we evaluated the cooperative game-theoretic contributions of all 30 features on phishing classification.

## 2. Top 10 Most Influential Features Globally
| Rank | Feature Name | Mean |SHAP| Score | Directional Security Impact |
| :---: | :--- | :---: | :--- |
| 1 | `SSLfinal_State` | 0.1855 | Strongest discriminator of website legitimacy |
| 2 | `URL_of_Anchor` | 0.1610 | High anchor ratio with invalid targets indicates deception |
| 3 | `web_traffic` | 0.0556 | Domain dash usage mimic brand names |
| 4 | `having_Sub_Domain` | 0.0500 | Unranked or low-traffic sites strongly skew phishing |
| 5 | `Links_in_tags` | 0.0426 | Subdomain depth masks genuine domain ownership |
| 6 | `Prefix_Suffix` | 0.0387 | Short domain registration lifespan |
| 7 | `SFH` | 0.0246 | Mismatched domain in page assets |
| 8 | `Request_URL` | 0.0180 | External links in script/link tags |
| 9 | `Links_pointing_to_page` | 0.0135 | Presence of Google Search indexation |
| 10 | `Domain_registeration_length` | 0.0128 | DNS record validation presence |

## 3. Visualization Deliverables
- `reports/figures/shap_importance_global.png`: Ranking of top features by average attribution magnitude.
- `reports/figures/shap_summary_beeswarm.png`: Detailed beeswarm density showing how high vs. low feature values drive predictions.
