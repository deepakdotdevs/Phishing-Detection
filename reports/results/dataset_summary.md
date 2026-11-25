# UCI Phishing Websites Dataset — Statistical Summary

## 1. High-Level Metrics
- **Total Records:** 11,055
- **Feature Count:** 30 website attributes
- **Target Variable:** `Result` (-1 = Legitimate, 1 = Phishing)
- **Phishing Samples:** 6,157 (55.69%)
- **Legitimate Samples:** 4,898 (44.31%)
- **Missing Values:** 0 (Zero null values across all columns)
- **Duplicate Records:** 5,206 (Pre-cleaned categorical feature vectors)

## 2. Top Correlated Features with Phishing (+ positive correlation)
| Feature Name | Pearson Correlation | Cybersecurity Interpretation |
| :--- | :---: | :--- |
| `SSLfinal_State` | +0.7147 | Untrusted or non-existent SSL certificate indicates high risk |
| `URL_of_Anchor` | +0.6929 | Large % of anchor links pointing off-domain or JavaScript `void(0)` |
| `Prefix_Suffix` | +0.3486 | Hyphens used to imitate genuine domains (e.g., `paypal-update.com`) |
| `web_traffic` | +0.3461 | Low or absent Alexa/web rank commonly associated with temporary phishing pages |
| `having_Sub_Domain` | +0.2983 | Multi-level subdomains masking true domain identity |

## 3. Top Protective Features (- negative correlation)
| Feature Name | Pearson Correlation | Cybersecurity Interpretation |
| :--- | :---: | :--- |
| `Domain_registeration_length` | -0.2258 | Legitimate domains frequently registered for > 1 year |
| `DNSRecord` | 0.0757 | Authentic websites have complete, verifiable DNS records |
| `age_of_domain` | 0.1215 | Mature domains (> 6 months) rarely used for throwaway phishing |

## 4. Multicollinearity & Correlation Observations
- Strong positive collinearity observed between `popUpWidnow` and `Favicon` (r ~ 0.94), as well as `port` and `HTTPS_token`.
- These pairings will be managed in Phase 1 (Issue #3) via feature selection and regularized modeling to ensure model generalization.
