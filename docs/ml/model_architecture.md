# SentinelAI: Machine Learning Architecture & Explainability

## 1. Zero External LLM Architecture
SentinelAI adheres to a strict **100% Local Machine Learning** architecture:
- Zero cloud inference costs.
- Zero credential exposure or third-party telemetry sharing.
- Sub-10ms inference latency for inline log stream scoring.
- Mathematical explainability with feature attributions.

---

## 2. 14-Dimensional Feature Engineering Pipeline
The feature extraction engine transforms normalized canonical event streams into a 14-dimensional mathematical feature vector $\mathbf{x} \in \mathbb{R}^{14}$:

| Index | Feature Name | Description | Formula / Intuition |
|:---|:---|:---|:---|
| 0 | `failed_login_count` | Number of failed auth events in window | Rolling sum |
| 1 | `successful_login_count` | Number of successful auth events | Rolling sum |
| 2 | `event_frequency` | Events per second from entity | Velocity metric |
| 3 | `requests_per_minute` | Rate of HTTP / API requests | Velocity metric |
| 4 | `unique_ip_count` | Distinct remote IPs contacted | Dispersion |
| 5 | `unique_user_count` | Distinct accounts touched | Lateral movement |
| 6 | `time_of_day_deviation` | Divergence from diurnal baseline | $\lvert h - \mu_h \rvert / \sigma_h$ |
| 7 | `weekend_deviation` | Indicator for weekend off-hours activity | Binary / Gaussian weight |
| 8 | `resource_sensitivity` | Tier of accessed resource (0.0 - 1.0) | Critical asset weighting |
| 9 | `authentication_failure_ratio`| $\frac{\text{Failed}}{\text{Failed} + \text{Success} + \epsilon}$ | Authentication anomaly |
| 10 | `repeated_event_score` | Entropy of repetitive event sequences | Sequence predictability |
| 11 | `source_reputation_score` | Threat intel reputation deficit | 0 (trusted) to 1.0 (malicious) |
| 12 | `behavioral_deviation` | Mahalanobis / Euclidean distance from baseline | Entity drift |
| 13 | `correlation_score` | Degree of temporal linkage with other alerts | Graph connectivity |

---

## 3. Anomaly Detection: Scikit-Learn IsolationForest
- **Model**: `sklearn.ensemble.IsolationForest`
- **Parameters**: `n_estimators=150`, `contamination=0.03`, `max_samples='auto'`, `random_state=42`.
- **Explainability (SHAP Proxy)**:
  Rather than relying on non-deterministic external LLMs, SentinelAI computes exact marginal feature contributions by comparing the evaluation point against the normal feature centroid normalized by feature variance:
  $$\phi_j = \frac{|x_j - \mu_j|}{\sigma_j + \epsilon}$$
  The top 3 contributing factors are converted into human-readable explanatory narratives in real-time.
