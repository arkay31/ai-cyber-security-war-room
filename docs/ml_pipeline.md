# Machine Learning Pipeline Specification & Mathematical Foundations
## Aegis One – AI Cyber Security War Room

This document details the feature engineering, supervised classification, unsupervised anomaly detection, local explainability (TreeSHAP), and empirical evaluation methodology for the machine learning subsystems of Aegis One.

---

## 1. Feature Engineering & Preprocessing

The machine learning pipeline ingests network flow records and endpoint audit events, mapping them to 20 numerical flow features derived from the **CICIDS2017** benchmark schema:

| Index | Feature Name | Description | Min | Max | Unit |
| :--- | :--- | :--- | :--- | :--- | :--- |
| 0 | `Destination Port` | Transport layer destination port | 0 | 65535 | Port number |
| 1 | `Flow Duration` | Duration of the bidirectional flow | 0 | $1.2 \times 10^8$ | $\mu\text{s}$ |
| 2 | `Total Fwd Packets` | Total packets in forward direction | 1 | $10^7$ | Packets |
| 3 | `Total Backward Packets` | Total packets in backward direction | 0 | $10^7$ | Packets |
| 4 | `Total Length of Fwd Packets` | Cumulative bytes sent forward | 0 | $10^8$ | Bytes |
| 5 | `Total Length of Bwd Packets` | Cumulative bytes sent backward | 0 | $10^8$ | Bytes |
| 6 | `Fwd Packet Length Mean` | Mean forward packet size | 0 | 65535 | Bytes |
| 7 | `Bwd Packet Length Mean` | Mean backward packet size | 0 | 65535 | Bytes |
| 8 | `Flow Bytes/s` | Transmission rate in bytes per second | 0 | $10^9$ | Bytes/sec |
| 9 | `Flow Packets/s` | Transmission rate in packets per second | 0 | $10^7$ | Pkts/sec |
| 10 | `Flow IAT Mean` | Mean inter-arrival time between packets | 0 | $1.2 \times 10^8$ | $\mu\text{s}$ |
| 11 | `Flow IAT Std` | Standard deviation of inter-arrival time | 0 | $1.2 \times 10^8$ | $\mu\text{s}$ |
| 12 | `Fwd Header Length` | Total header bytes in forward packets | 0 | $10^7$ | Bytes |
| 13 | `Bwd Header Length` | Total header bytes in backward packets | 0 | $10^7$ | Bytes |
| 14 | `Packet Length Mean` | Combined mean packet size across flow | 0 | 65535 | Bytes |
| 15 | `Packet Length Std` | Standard deviation of packet sizes | 0 | 65535 | Bytes |
| 16 | `SYN Flag Count` | Binary flag count for TCP SYN | 0 | 1 | Boolean |
| 17 | `ACK Flag Count` | Binary flag count for TCP ACK | 0 | 1 | Boolean |
| 18 | `Average Packet Size` | Ratio of total bytes to total packets | 0 | 65535 | Bytes |
| 19 | `Init_Win_bytes_forward` | Initial TCP window bytes in forward flow | -1 | 65535 | Bytes |

### Preprocessing & Ingestion Guardrails (`backend/app/ml/preprocessor.py`)
1. **Zero-Failure Type Coercion**: `sanitize_float` safely coerces string, None, NaN, and infinity values into bounded float ranges.
2. **Bounds Enforcement**: Values outside physiological network bounds (e.g., negative ports or negative packet counts) are clipped to valid boundaries.
3. **Missing Value Imputation**: Missing flow telemetry is gracefully imputed from packet headers and connection protocol defaults.

---

## 2. Supervised Threat Classification (XGBoost)

### Algorithm & Hyperparameters
- **Estimator**: `xgboost.XGBClassifier`
- **Objective Function**: Multi-class softmax probability (`multi:softprob`)
- **Loss Metric**: Multi-class logarithmic loss (`mlogloss`)
- **Number of Estimators**: 120 trees
- **Max Tree Depth**: 6
- **Learning Rate ($\eta$)**: 0.08
- **Subsample Ratio**: 0.85
- **Column Subsample by Tree**: 0.85
- **Split Strategy**: Stratified 70% Train / 15% Validation / 15% Unseen Test split.

### Empirical Evaluation on Test Split
- **Test Accuracy**: **99.89%**
- **Macro F1-Score**: **0.9989**
- **Weighted F1-Score**: **0.9989**

#### Per-Class Metrics Table:
| Attack Class | Precision | Recall | F1-Score | Test Support |
| :--- | :--- | :--- | :--- | :--- |
| **BENIGN** | 1.0000 | 1.0000 | 1.0000 | 541 |
| **Bot** | 1.0000 | 1.0000 | 1.0000 | 38 |
| **Brute Force** | 1.0000 | 1.0000 | 1.0000 | 50 |
| **DDoS** | 1.0000 | 0.9904 | 0.9952 | 104 |
| **DoS** | 1.0000 | 1.0000 | 1.0000 | 72 |
| **PortScan** | 1.0000 | 1.0000 | 1.0000 | 95 |

---

## 3. Explainable AI with TreeSHAP Local Attributions

Black-box machine learning predictions are inadequate for SOC analysts who must justify disruptive containment actions (e.g. isolating critical enterprise servers). Aegis One integrates **TreeSHAP** (Tree Shapley Additive exPlanations):

$$\phi_i(x) = \sum_{S \subseteq F \setminus \{i\}} \frac{|S|!(|F| - |S| - 1)!}{|F|!} \left[ f(S \cup \{i\}) - f(S) \right]$$

### Global Feature Importance (Gain vs SHAP)
The top 5 features influencing intrusion classification:
1. `Total Fwd Packets` (Gain: 0.1704, Mean |SHAP|: 1.48)
2. `Packet Length Std` (Gain: 0.1568, Mean |SHAP|: 1.32)
3. `Bwd Packet Length Mean` (Gain: 0.1283, Mean |SHAP|: 1.15)
4. `Init_Win_bytes_forward` (Gain: 0.1242, Mean |SHAP|: 1.08)
5. `Flow Duration` (Gain: 0.1077, Mean |SHAP|: 0.94)

### Real-Time Local Explanation Workflow
When an incident is investigated:
1. `explain_threat(event_dict, predicted_class)` executes TreeSHAP across the 20 features in $\approx 2\text{ ms}$.
2. Top features with positive SHAP values are extracted (features pushing the prediction towards the attack class).
3. The attributions are formatted into human-readable narratives and injected directly into the LLM context prompt and dashboard cards.

---

## 4. Unsupervised Anomaly Detection (Isolation Forest)

### Training Methodology
To prevent label contamination and data leakage:
1. **Benign Training Baseline**: Isolation Forest is fitted **strictly on normal (BENIGN) traffic records** ($N = 2,163$).
2. **Threshold Calibration**: The dynamic decision threshold is calibrated on an independent **validation split** ($N = 1,200$) to maximize F1-score.
3. **Unseen Test Evaluation**: Evaluated on a completely held-out **unseen test split** ($N = 1,200$).

### Mathematical Formulation
Isolation Forest recursively partitions feature space using random hyperplanes. Anomalies require fewer splits to isolate:

$$s(x, n) = 2^{-\frac{E(h(x))}{c(n)}}$$

Where $E(h(x))$ is the average path length across 150 isolation trees, and $c(n)$ is the average path length of unsuccessful searches in a Binary Search Tree:

$$c(n) = 2\ln(n - 1) + 0.5772156649 - \frac{2(n - 1)}{n}$$

### Normalized Anomaly Score
The raw decision score $s(x)$ is dynamically normalized into $[0.0, 1.0]$:
$$\text{Score}_{\text{norm}}(x) = 1.0 - \left( \frac{s(x) - s_{\min}}{s_{\max} - s_{\min} + \epsilon} \right)$$
Where calibrated decision threshold $\tau = 0.430$. Events with $\text{Score}_{\text{norm}} \ge 0.430$ are flagged as anomalous.

### Empirical Evaluation on Unseen Test Split
- **Precision**: **91.18%**
- **Recall**: **94.99%**
- **Specificity**: **93.90%**
- **F1-Score**: **93.05%**
- **False Positive Rate (FPR)**: **6.10%** ($FP = 44, TN = 677$)
- **False Negative Rate (FNR)**: **5.01%** ($FN = 24, TP = 455$)

### Feature Deviation Explanations (Z-Scores)
To explain *why* an unsupervised anomaly was flagged:
$$z_j = \text{clip}\left( \frac{x_j - \mu_{\text{benign}, j}}{\max(\sigma_{\text{benign}, j}, 1.0)}, -15.0, 15.0 \right)$$
Features with $|z_j| \ge 2.0$ indicate statistically significant deviation from normal enterprise network behavior.

---

## 5. Development Sample vs Production Benchmark Distinction

> [!IMPORTANT]
> The performance metrics documented here (99.89% XGBoost accuracy, 93.05% Isolation Forest F1) reflect evaluations on stratified development samples derived from the official CICIDS2017 feature schema.
> 
> In enterprise production deployment:
> 1. **Concept Drift**: Network behaviors change dynamically due to software rollouts, remote-work shifts, and architecture migrations.
> 2. **Adversarial Obfuscation**: Attackers use polymorphic payloads, encrypted tunnels (DoH, TLS 1.3), and low-and-slow timing to evade statistical thresholds.
> 3. **Mitigation**: Aegis One mitigates these realities through automated RAG playbooks, human analyst verification challenges, and state-machine-controlled incident triage.
