# Tech Mahindra AI Engineer Fresher Technical Interview Preparation Guide
## Aegis One – AI Cyber Security War Room

This guide is custom-tailored for technical rounds, machine learning interviews, and system architecture discussions for the **AI Engineer (Fresher / Associate)** role at **Tech Mahindra**.

---

## Table of Contents
1. [The 2-Minute Elevator Pitch](#1-the-2-minute-elevator-pitch)
2. [Machine Learning & Anomaly Detection Deep-Dive](#2-machine-learning--anomaly-detection-deep-dive)
3. [Explainable AI (TreeSHAP & Z-Scores)](#3-explainable-ai-treeshap--z-scores)
4. [RAG Pipeline & pgvector Mechanics](#4-rag-pipeline--pgvector-mechanics)
5. [Polymorphic LLM Architecture & Anti-Hallucination](#5-polymorphic-llm-architecture--anti-hallucination)
6. [Cybersecurity Domain Knowledge & SOC Workflows](#6-cybersecurity-domain-knowledge--soc-workflows)
7. [Full-Stack Engineering & Deployment (FastAPI, Next.js, Docker)](#7-full-stack-engineering--deployment)
8. [High-Impact Coding & Architecture Questions with Model Answers](#8-high-impact-interview-questions--answers)

---

## 1. The 2-Minute Elevator Pitch

> *"Aegis One is an autonomous, AI-driven Security Operations Center (SOC) war room platform that addresses alert fatigue and false positives in enterprise cybersecurity.
>
> When raw network flows or authentication events arrive, our pipeline passes them through a dual-model ML ensemble: an **XGBoost Classifier** that identifies specific attack classes with 99.89% test accuracy, and an **Isolation Forest** fitted on benign baselines to catch novel anomalies with a 93.05% F1-score.
>
> To eliminate black-box obscurity, we integrated real-time **TreeSHAP** to expose the exact mathematical feature contributions behind each prediction. 
>
> Events are correlated across a 30-minute sliding window into incidents, mapped to the **MITRE ATT&CK** matrix, and enriched with defense playbooks retrieved via **PostgreSQL pgvector** using 384-dimensional dense embeddings.
>
> Our autonomous **AI Analyst** synthesizes the telemetry, SHAP attributions, and retrieved playbooks using either a local **Ollama Llama 3** instance or cloud LLMs (Groq / OpenAI) with strict Pydantic JSON validation.
>
> Finally, to prevent disruptive false-positive lockdowns, we built a **Human-in-the-Loop User Verification portal** requiring PIN authentication before executing automated containment actions like IP blocking or host isolation—with every action forensically logged into an immutable audit trail."*

---

## 2. Machine Learning & Anomaly Detection Deep-Dive

### Q1: Why did you choose XGBoost over Random Forest or Deep Neural Networks for network flow threat classification?
**Answer:**
1. **Tabular Data Superiority**: Tabular network flow records (like CICIDS2017) are characterized by heterogeneous feature scales, extreme non-linearities, and zero-inflated distributions. Gradient Boosted Decision Trees (GBDT) consistently outperform Deep Neural Networks on tabular data without requiring complex normalization or prone-to-overfitting dense architectures.
2. **Gradient Boosting vs Random Forest**: Random Forest builds independent trees and averages predictions (bagging), reducing variance. XGBoost builds trees sequentially to minimize residual errors using second-order Taylor expansion (gradient and hessian), optimizing both bias and variance.
3. **Inference Latency & Efficiency**: In a real-time SOC environment processing thousands of events per second, XGBoost executes inference in sub-millisecond latency with a minimal memory footprint.

### Q2: How did you handle class imbalance in cybersecurity datasets?
**Answer:**
In enterprise security datasets, benign traffic represents $>90\%$ of events, while dangerous attacks (like Botnets or Privilege Escalation) represent $<2\%$.
1. **Stratified Sampling**: During train/val/test splitting, we enforced stratification (`stratify=y`) to guarantee that rare attack classes maintain identical proportional representation across all splits.
2. **Loss Objective**: We utilized `objective="multi:softprob"` with `eval_metric="mlogloss"`, which penalizes confident errors on minority classes heavily.
3. **Evaluation Metrics**: We never rely on raw accuracy alone (which is deceptive during severe imbalance). We monitor **Macro-averaged Precision, Recall, and F1-score**, ensuring rare classes contribute equally to the final evaluation metric.

### Q3: Explain how Isolation Forest works and why you trained it strictly on benign traffic.
**Answer:**
- **Mechanism**: Isolation Forest isolates observations by randomly selecting a feature and randomly splitting between its min and max values. Because anomalies have extreme or rare values, they require significantly fewer random splits to isolate (shorter average tree path length $h(x)$).
- **The Semi-Supervised Baseline Philosophy**: If you train an anomaly detector on dirty data containing attacks, the model accepts malicious traffic as part of the normal envelope (masking effect). By fitting strictly on filtered `BENIGN` traffic ($N = 2,163$), the model builds an uncontaminated baseline of normal enterprise operations.
- **Dynamic Threshold Calibration**: Rather than guessing the contamination factor, we calibrated the decision threshold on a validation split to find the exact threshold ($\tau = 0.430$) that maximized the F1-score before evaluating on held-out test data.

---

## 3. Explainable AI (TreeSHAP & Z-Scores)

### Q4: What is TreeSHAP and why is it superior to LIME or KernelSHAP for your platform?
**Answer:**
1. **Mathematical Grounding**: SHAP is rooted in cooperative game theory (Shapley values). It satisfies crucial axioms that heuristic explainers violate: **Efficiency** (attributions sum to the difference between prediction and expected value), **Symmetry**, **Dummy player**, and **Additivity**.
2. **Computational Complexity**:
   - KernelSHAP and LIME treat the model as a black box and sample perturbations, scaling exponentially $\mathcal{O}(2^{|F|})$ or taking several seconds per sample.
   - **TreeSHAP** optimizes tree traversal by tracking the proportion of leaves compatible with each subset, reducing complexity to polynomial time $\mathcal{O}(T \cdot L \cdot D^2)$ (where $T$ is trees, $L$ is leaves, $D$ is depth). In our system, TreeSHAP evaluates all 20 features in **~2 ms**, making real-time inline explainability viable.

### Q5: How do you explain unsupervised anomalies when Isolation Forest doesn't have class feature weights?
**Answer:**
Isolation Forest produces a global scalar anomaly score but cannot inherently attribute which specific feature caused the anomaly. We solved this by pre-computing the **empirical feature baseline** (mean $\mu_j$ and standard deviation $\sigma_j$) across the benign training split.
At inference time, we calculate the bounded Z-Score:
$$z_j = \text{clip}\left( \frac{x_j - \mu_{\text{benign}, j}}{\max(\sigma_{\text{benign}, j}, 1.0)}, -15.0, 15.0 \right)$$
Any feature with $|z_j| \ge 2.0$ (e.g. `Flow Packets/s` at $+14.2\sigma$) provides instant, mathematically grounded attribution of why the traffic signature deviated from the enterprise baseline.

---

## 4. RAG Pipeline & pgvector Mechanics

### Q6: Why did you choose SentenceTransformers with PostgreSQL pgvector instead of a standalone vector database like Pinecone or Milvus?
**Answer:**
1. **Relational + Vector Co-location**: In a SOC platform, vector embeddings of playbooks must join directly with structured incidents, security events, and audit logs. Using PostgreSQL with the `pgvector` extension allows us to execute unified ACID transactions and relational joins in a single database, avoiding distributed network hops, data synchronization drift, and vendor sprawl.
2. **Low Latency & Indexing**: Using `all-MiniLM-L6-v2` produces compact 384-dimensional dense vectors. With `IVFFlat` indexing and the `<=>` cosine distance operator, vector retrieval executes in **~18 ms**, well within interactive SOC dashboard thresholds.
3. **Quantitative Retrieval Evaluation**: We verified our RAG pipeline through an automated benchmark achieving **100% Precision@1** and **1.00 MRR** across canonical MITRE ATT&CK queries.

### Q7: How do you prevent low-similarity RAG documents from polluting the LLM context?
**Answer:**
When an incident is atypical or novel, vector search still returns the mathematically closest documents even if their semantic similarity is low. In Aegis One:
- We compute $\text{similarity} = 1 - \text{cosine\_distance}$.
- Documents with similarity $< 0.45$ are tagged with `is_low_relevance: true`.
- In the LLM prompt, they are prepended with `(LOW RELEVANCE - USE CAUTION)`.
- The LLM prompt explicitly instructs the model: *"If playbooks are marked LOW RELEVANCE, note that they are general guidelines and not verified evidence."*

---

## 5. Polymorphic LLM Architecture & Anti-Hallucination

### Q8: What is your "Polymorphic LLM Provider" pattern and why is it architected this way?
**Answer:**
In production enterprise environments, cybersecurity data cannot always leave on-premise infrastructure due to GDPR, HIPAA, or defense secrecy compliance.
We architected a polymorphic provider abstraction (`BaseLLMProvider`):
1. **Local Mode (`LLM_PROVIDER=ollama`)**: Queries a local Ollama daemon running Llama 3 (8B quantized) on Apple Silicon GPU or local servers. Completely offline, zero external data transit.
2. **Cloud Mode (`LLM_PROVIDER=openai` or `groq`)**: Seamlessly connects to hosted APIs for ultra-fast throughput without changing any business logic.
3. **Honest Fallback Guarantee**: If the LLM service is offline or times out ($>120\text{s}$), the system executes a deterministic rule-based analysis and explicitly labels the output as `RULE_BASED` with `llm_status: "LLM_UNAVAILABLE"`. It **never disguises rule-based outputs as AI generations**.

### Q9: How do you ensure the LLM strictly produces valid JSON without hallucinations?
**Answer:**
1. **Ollama Format Enforcement**: We pass `"format": "json"` in the Ollama API payload, which restricts decoding tokens strictly to valid JSON syntax at the grammar level.
2. **Multi-Tier Robust Parser**: If the response contains markdown wrappers (````json ... ````) or conversational preambles, `LLMService._parse_json_safely` uses regular expression extraction to isolate and parse the innermost JSON object.
3. **Pydantic Schema Validation**: `AIInvestigationSchema.sanitize_raw_llm_dict` validates types, bounds confidence to $[0.0, 1.0]$, cleans technique lists, and backfills required fields if missing.

---

## 6. Cybersecurity Domain Knowledge & SOC Workflows

### Q10: Walk me through the multi-stage attack kill chain in your Faculty Demo scenario.
**Answer:**
The demonstration illustrates a realistic 7-event kill chain across an internal server (`sec-ops-srv01`):
1. **Reconnaissance & Brute Force**: Attacker `198.51.100.200` executes repeated failed SSH logins (T1110) against user `mjackson`.
2. **Initial Access**: Attacker achieves successful authentication using compromised credentials (T1078).
3. **Privilege Escalation**: Attacker executes `sudo /bin/bash` to gain root privileges (T1548.003).
4. **Credential Dumping / Sensitive Access**: Attacker reads `/etc/shadow` and copies corporate database dumps (T1003, T1005).
5. **Data Exfiltration**: Attacker stages and transmits 15.5 MB of encrypted data to external dropzone `dropzone.c2-exfil-node.net` (T1048).
The system correlates all 7 events into a single Critical incident (`INC-2026-0018`), calculates a risk score of 98.4/100, maps all 5 MITRE techniques, and retrieves containment playbooks.

### Q11: Why is Human-in-the-Loop (HITL) verification critical in automated incident response?
**Answer:**
Fully automated response engines often cause catastrophic self-inflicted outages (e.g. blocking a core database server because a legitimate database admin ran a bulk export script during odd hours).
Our platform addresses this by issuing an automated **User Verification Challenge** (`/verify/{challengeId}`). The affected user receives a prompt asking: *"Did you attempt to access /etc/shadow on sec-ops-srv01 at 10:14 PM?"*
- If the user confirms with their PIN, the incident transitions to `USER_CONFIRMED` and the analyst can safely close it as a legitimate authorized action.
- If the user denies or reports suspicious activity, the incident is instantly escalated to `CONFIRMED_INCIDENT` with automated host quarantine.

---

## 7. Full-Stack Engineering & Deployment

### Q12: How did you overcome the macOS iCloud storage eviction problem (`ETIMEDOUT`) during development?
**Answer:**
On macOS devices with iCloud Drive active, the "Optimize Mac Storage" feature silently marks large, infrequently modified folder trees (such as `node_modules` and Python `venv`) as `SF_DATALESS` (`0x40000000`), purging file bytes from local disk to the cloud. When Node.js or Python tries to synchronously `readFileSync` or `stat` thousands of files, the OS blocks on an unauthenticated background network daemon, causing `ETIMEDOUT`.
We engineered a bulletproof shield:
1. Created `node_modules.nosync` and `venv.nosync` (macOS iCloud strictly ignores any directory ending in `.nosync`).
2. Symlinked `node_modules -> node_modules.nosync` and `venv -> venv.nosync`.
3. Integrated automated verification checks into `./start_warroom.sh` to ensure zero developer downtime.

---

## 8. High-Impact Interview Questions & Answers

### Cheat Sheet: Quick Reference Facts for Your Interview
- **Primary Model**: XGBoost Classifier (120 estimators, depth 6, $\eta=0.08$, accuracy 99.89%).
- **Anomaly Model**: Isolation Forest (150 trees, contamination 0.08, calibrated threshold 0.430, F1-score 93.05%).
- **Explainability**: TreeSHAP ($\approx 2\text{ ms}$ local attribution) + Benign Z-Score feature deviations.
- **RAG Architecture**: SentenceTransformers `all-MiniLM-L6-v2` (384 dimensions) + PostgreSQL 16 `pgvector` with `<=>` cosine distance operator (Precision@1: 100%, MRR: 1.00, latency ~18 ms).
- **LLM Pipeline**: Polymorphic router supporting local Ollama (`llama3:latest` 8B) and cloud APIs (Groq / OpenAI) with Pydantic `AIInvestigationSchema` validation and honest rule-based fallback.
- **Backend**: FastAPI + SQLAlchemy 2.0 (`psycopg[binary]`) + PostgreSQL 16.
- **Frontend**: Next.js 16.3 + TypeScript + Tailwind CSS 4 + Lucide React + Recharts + React Flow.
