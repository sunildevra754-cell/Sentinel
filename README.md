# 🛡️ SENTINEL — Real-Time AI Model Integrity & Trust Layer

> **Exhibition-Ready AI Security & Governance Platform**  
> Protects machine learning models in high-stakes financial, fraud detection, and credit scoring systems from silent data poisoning, adversarial drift, and malicious manipulation.

---

## 🌟 Key Highlights & All-in-One Capabilities

| Component | Description | Exhibition Feature |
| :--- | :--- | :--- |
| **Protected Models** | Two enterprise-grade classifiers (`Payment Fraud Engine` & `KYC Credit Risk Classifier`) trained on realistic multi-factor synthetic financial data. | Real-time live inference stream with feature attribution and dynamic decisioning. |
| **Attack Simulator** | Realistic attack injectors: *Gradual Decision Boundary Poisoning*, *Stealth Backdoor Injection*, *Adversarial Honeypot Probing*, and *Covariate Shift Surge*. | **Interactive Exhibition Sandbox** — visitors can select an attack type, intensity, and launch it live. |
| **Drift Detection Engine** | Real-time Population Stability Index (**PSI**) and Kullback-Leibler (**KL**) Divergence calculated per feature against clean baseline distributions. | Live interactive Bar Chart with Warning ($\text{PSI} \ge 0.10$) and Severe ($\text{PSI} \ge 0.25$) thresholds. |
| **SHAP Explainability** | Model explainability engine generating individual prediction explanations and executive-level drift summaries in plain language. | Converts complex SHAP weight vectors into clear sentences explaining *why* an alert fired. |
| **Trust Score Engine** | Continuously updated **0–100 Trust Score** combining drift severity, anomaly rates, honeypot alarms, and model health. | Large visual circular animated gauge with color morphing (Emerald $\rightarrow$ Amber $\rightarrow$ Crimson). |
| **Confidence Throttling** | Graduated defense: auto-approval threshold automatically tightens (50% $\rightarrow$ 75% $\rightarrow$ 88%) as trust degrades, routing uncertain cases to Step-Up verification. | Visual throttling meter showing live tightening before full quarantine. |
| **Auto-Quarantine & Rollback** | When Trust Score drops below 50%, Sentinel automatically quarantines the compromised model and switches 100% of live traffic to the verified clean checkpoint. | Visible failover state change with instant incident logging and traffic preservation. |
| **Vernacular Alerts (Hindi)** | Bilingual translation engine providing alerts in **English**, **Hindi (Devanagari)**, and **Hinglish** + **Web Speech API Audio Voice Readout**. | Booth visitors can hear audio alerts spoken aloud in Hindi and English! |
| **Credential-Leak Correlation** | Cross-references incoming anomalous traffic indicators with a simulated dark-web breach intelligence feed. | Flags when an attack matches compromised credentials or spoofed device profiles. |
| **Adversarial Honeypots** | Deliberately seeded canary bait signatures in the feature space that trigger instant intrusion alarms when probed. | Detects probing actors before full poisoning takes effect. |
| **SHA-256 Hash Chain** | Tamper-evident cryptographic audit log where every model version change, attack, and incident is chained via SHA-256 hashes. | "Verify Integrity" button that recalculates the entire cryptographic chain live. |
| **1-Click Exhibition Demo Story** | Single-button automated demo sequence that plays the entire 7-step defense narrative seamlessly for judges. | Zero-hassle judging presentation. |

---

## 🏛️ System Architecture

```
                                  ┌─────────────────────────────┐
                                  │   Incoming Traffic Stream   │
                                  │   (Normal / Poisoned)       │
                                  └──────────────┬──────────────┘
                                                 │
                                                 ▼
                                  ┌─────────────────────────────┐
                                  │ Adversarial Honeypot Canary │
                                  │       Detection Layer       │
                                  └──────────────┬──────────────┘
                                                 │
                                                 ▼
                                  ┌─────────────────────────────┐
                                  │  Protected Classifiers      │
                                  │  (Fraud & KYC Risk Models)  │
                                  └──────────────┬──────────────┘
                                                 │
                ┌────────────────────────────────┼────────────────────────────────┐
                │                                │                                │
                ▼                                ▼                                ▼
  ┌───────────────────────────┐    ┌───────────────────────────┐    ┌───────────────────────────┐
  │ Feature Drift Engine      │    │ SHAP Explainability       │    │ Threat Intel & DarkWeb    │
  │ • Population Stability    │    │ • Prediction Attribution  │    │   Credential Leak         │
  │   Index (PSI)             │    │ • Plain Language Drift    │    │   Correlation Engine      │
  │ • KL Divergence           │    │   Summary Sentences       │    │                           │
  └─────────────┬─────────────┘    └─────────────┬─────────────┘    └─────────────┬─────────────┘
                │                                │                                │
                └────────────────────────────────┼────────────────────────────────┘
                                                 │
                                                 ▼
                                  ┌─────────────────────────────┐
                                  │ Multi-Factor Trust Engine   │
                                  │ Trust Score: 0 - 100        │
                                  └──────────────┬──────────────┘
                                                 │
                   ┌─────────────────────────────┴─────────────────────────────┐
                   │                                                           │
                   ▼                                                           ▼
    ┌──────────────────────────────┐                            ┌──────────────────────────────┐
    │ Graduated Response           │                            │ Critical Failover            │
    │ Confidence-Based Throttling  │                            │ Auto-Quarantine & Rollback   │
    │ (50% -> 75% -> 88% Certainty)│                            │ to Clean Checkpoint          │
    └──────────────┬───────────────┘                            └──────────────┬───────────────┘
                   │                                                           │
                   └─────────────────────────────┬─────────────────────────────┘
                                                 │
                                                 ▼
                                  ┌─────────────────────────────┐
                                  │ Vernacular Alerting & TTS   │
                                  │ • English + Hindi Script    │
                                  │ • Browser Speech Readout    │
                                  └──────────────┬──────────────┘
                                                 │
                                                 ▼
                                  ┌─────────────────────────────┐
                                  │ Immutable SHA-256 Chain     │
                                  │ SQLite Tamper-Proof Audit   │
                                  └─────────────────────────────┘
```

---

## 🚀 Quickstart & Setup Guide

### 1. Prerequisites
- Python 3.10, 3.11, 3.12, or 3.13
- Works completely **offline** without internet access once installed!

### 2. Installation
Clone or navigate to the repository directory:
```bash
cd Sentinel
```

Install dependencies:
```bash
pip install -r requirements.txt
```

### 3. Launch Sentinel Platform
Run the all-in-one starter script:
```bash
python run_server.py
```
This automatically initializes the SQLite database, verifies baseline models, and launches the live interactive web dashboard at:
👉 **`http://127.0.0.1:8000`**

*(Swagger API Documentation available at: `http://127.0.0.1:8000/docs`)*

---

## 🎨 Alternative: Streamlit Dashboard
If you prefer running the dedicated Streamlit interface for evaluation:
```bash
streamlit run app_streamlit.py
```

---

## 🎬 Exhibition Booth Live Demo Flow (Step-by-Step)

Follow this 2-minute demonstration flow when presenting to judges or visitors:

1. **Clean Baseline Overview**:
   - Show the dashboard with both models healthy, trust score at **98.5%**, and status marked **HEALTHY • BASELINE VERIFIED**.
   - Point out the **Cross-Model Risk Matrix** ranking both models and the **SHA-256 Audit Chain: INTACT** badge.

2. **Interactive Attack Injection**:
   - In the **Exhibition Attack Sandbox** panel on the right, select `Model 1: Payment Fraud Classifier`.
   - Select attack vector: `1. Gradual Decision Boundary Poisoning` (or `2. Adversarial Canary Honeypot Probing`) at `85% Intensity`.
   - Click **"Inject Poisoning Attack"**.

3. **Observe Real-Time Degradation & Drift**:
   - The **Trust Score** visibly drops (98% $\rightarrow$ 76% $\rightarrow$ 48%).
   - The **Feature Drift Chart** shows real-time PSI spikes on `amount` and `foreign_ip_flag` crossing the red $\text{PSI} \ge 0.25$ threshold.
   - The **Graduated Throttling Meter** tightens to `MODERATE` / `STRICT`, demanding 88% confidence before approving.

4. **SHAP Explanation & Threat Intel Match**:
   - The SHAP explanation updates: *"Feature 'amount' shifted 3.4x — decision boundary warped by data poisoning."*
   - Threat intelligence badge flags: *"Matched DarkWeb Breach Dump v4"*.

5. **Auto-Quarantine & Instant Rollback**:
   - As trust crosses below 50%, Sentinel automatically triggers **Auto-Quarantine**.
   - The banner turns crimson: **"🚨 QUARANTINED • ROLLED BACK TO SAFE CHECKPOINT"**.
   - Traffic is safely rerouted through the clean checkpoint, and the trust score stabilizes!

6. **Vernacular Audio Alert**:
   - The vernacular panel flashes bilingual English + Hindi alerts:  
     *गंभीर विचलन चेतावनी: मॉडल में फीचर 'amount' सामान्य से बदल गया है।*
   - Click the **"Speak"** button to hear the audio alert aloud.

7. **Cryptographic Audit Verification**:
   - In the bottom-right panel, click **"Verify Integrity"**.
   - Sentinel walks through the entire SHA-256 hash chain and confirms: **"100% Chain Integrity Verified"**.

---

## 🧪 Running Automated Tests
Sentinel includes a full end-to-end automated test suite verifying all 16 capabilities:
```bash
python -m unittest tests/test_sentinel_e2e.py
```

---

## 📁 Repository Structure

```
Sentinel/
├── backend/
│   ├── config.py                  # Thresholds, paths, and model metadata
│   ├── app.py                     # FastAPI server, REST endpoints, background traffic loop
│   ├── models/
│   │   ├── data_generator.py      # Realistic synthetic financial & KYC data generator
│   │   ├── train_models.py        # Baseline model training and checkpoint serialization
│   │   └── model_registry.py      # Active vs quarantined model state manager & failover router
│   ├── engine/
│   │   ├── drift_detector.py      # Population Stability Index (PSI) & KL-divergence engine
│   │   ├── explainability.py      # SHAP explainer & natural-language sentence translator
│   │   ├── trust_score.py         # 0-100 Trust Score & confidence throttling engine
│   │   ├── honeypot.py            # Adversarial canary & bait signature detector
│   │   ├── leak_correlator.py     # Threat intel & dark web breach correlator
│   │   └── vernacular.py          # English -> Hindi template translator & speech script generator
│   ├── attack_simulator/
│   │   └── simulator.py           # Multi-vector synthetic attack injector
│   └── storage/
│       ├── database.py            # SQLite schema (incidents, transactions, trust history)
│       └── audit_chain.py         # Tamper-evident SHA-256 hash chain log
├── static/
│   ├── index.html                 # Cyber-defense real-time dashboard UI
│   ├── style.css                  # Custom glassmorphism dark-mode stylesheet
│   └── app.js                     # Real-time WebSocket/polling client, audio synthesizer
├── tests/
│   └── test_sentinel_e2e.py       # End-to-end automated unit test suite
├── data/
│   ├── sentinel.db                # SQLite database
│   └── checkpoints/               # Verified clean baseline models and stats
├── app_streamlit.py               # Companion Streamlit application
├── run_server.py                  # One-click startup script
└── requirements.txt               # Pinned Python dependencies
```

---

## 🏆 Exhibition Judging Cheat Sheet

- **Why is Sentinel unique?** Unlike passive logging tools, Sentinel combines real-time statistical drift detection (PSI), SHAP explainability, dark-web threat correlation, and adversarial honeypots into a single automated trust engine with graduated confidence throttling and automatic safe rollback.
- **Language Inclusivity:** Indigenous vernacular alerts (Hindi Devanagari + phonetic Hinglish + voice speech synthesis) allow non-technical operators and frontline officers to understand security incidents instantly.
- **Tamper Resistance:** The SHA-256 hash-chain ensures compliance and forensic auditability that cannot be silently modified after an attack.
