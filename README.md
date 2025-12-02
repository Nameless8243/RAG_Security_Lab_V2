# RAG Security Lab V2

A multi-layer defensive lab demonstrating **enterprise-grade security controls** for RAG ingestion pipelines:

- Lineage & integrity verification (hash + signature)
- Semantic anomaly detection (poisoning, drift)
- Multi-stage quarantine workflow
- Tamper-evident audit log (hash-chain)
- Full adversarial attack simulation

This lab shows how to secure document pipelines *before* data reaches LLMs.

---

## 🏗 Architecture Overview

```
              ┌────────────────────────┐
              │   Document Ingestion    │
              └─────────────┬──────────┘
                            ▼
              ┌────────────────────────┐
              │    Lineage Verifier     │
              │  (hash + signature)     │
              └─────────────┬──────────┘
                            ▼
              ┌────────────────────────┐
              │    Semantic Scanner     │
              │ (poisoning & drift)     │
              └─────────────┬──────────┘
                            ▼
              ┌────────────────────────┐
              │   Quarantine Manager    │
              │  (evidence bundling)    │
              └─────────────┬──────────┘
                            ▼
              ┌────────────────────────┐
              │ Audit Log (Hash-Chain) │
              └────────────────────────┘
```

Each layer blocks a different attack surface.

---

## 🧩 Requirements

```
numpy
sentence-transformers
torch
```

> *Note:* The default torch package installed via pip is the CPU-only version (lightweight, no GPU required). 
> If you want GPU acceleration, install a CUDA-enabled PyTorch build manually.

---

## 🛠 Installation

```
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

## 🧪 Full Attack Simulation

**Run:**

```
python3 -m simulations.full_attack_simulation
```

**Example output:**

```
═══════════════════════════════════════════════════════════════════════════
   RAG SECURITY LAB V2 – FULL ATTACK SIMULATION REPORT
═══════════════════════════════════════════════════════════════════════════
Timestamp: 2025-12-02T15:45:56Z

[OK] doc-clean                ACCEPTED

[!] doc-lineage-attack        QUARANTINED (blocked: lineage)
     evidence: data/quarantine/...

[!] doc-semantic-attack       QUARANTINED (blocked: semantic)
     evidence: data/quarantine/...

[!] doc-combined-attack       QUARANTINED (blocked: lineage)
     evidence: data/quarantine/...

───────────────────────────────────────────────────────────────────────────
 SUMMARY
───────────────────────────────────────────────────────────────────────────
 Total documents    : 4
 Accepted           : 1
 Quarantined        : 3
 Lineage blocked    : 2
 Semantic blocked   : 1

 Audit log          : data/audit/audit_log.jsonl
 Quarantine folder  : data/quarantine/
═══════════════════════════════════════════════════════════════════════════
```

Evidence bundles and audit logs are automatically generated:

- `data/audit/audit_log.jsonl`
- `data/quarantine/...`

---

## 🧹 Cleanup Utility (reset_data.py)

A helper script is included to wipe all runtime data.

Run:
python3 simulations/reset_data.py

This deletes:
- data/audit/*
- data/quarantine/*

Useful for rerunning the full attack simulation from a clean state.

---

## 📂 Project Structure

```
RAG_SECURITY_LAB_V2/
├── data/
│   ├── audit/
│   └── quarantine/
├── security/
│   ├── audit/
│   ├── lineage/
│   ├── pipeline/
│   ├── quarantine/
│   └── semantic/
├── simulations/
│   └── full_attack_simulation.py
│   └── reset_data.py
├── README.md
└── requirements.txt
```

---


## 🛡 Recommended Use Cases

This project is intended for **enterprise LLM security architectures**, including:

- **Secure RAG Ingestion Pipelines**  
  Hardening document intake before embedding or retrieval.

- **AI Supply Chain Security Controls**  
  Ensuring integrity, authenticity, and tamper-evidence for ingested content.

- **Content Integrity Enforcement**  
  Detecting manipulation, poisoning, and semantic drift.

- **Governance, Risk & Compliance (GRC)**  
  Tamper-evident auditability for regulated AI environments.

- **Threat Modeling & Architecture**  
  Demonstrating defensive layers against RAG poisoning and lineage attacks.

This aligns with emerging frameworks such as **NIST AI RMF** and **ISO/IEC 42001**.

---

## ⚠️ Disclaimer

This project is provided for **educational and research purposes only**.  
It is **not** intended to be used as a production security control without additional
hardening, validation, and organization-specific review.

The authors and contributors provide this software **“as is” without warranty** of any kind,
express or implied, including but not limited to fitness for a particular purpose,  
security guarantees, or compliance with regulatory requirements.

Use this project **at your own risk**.

---

## 📜 License

MIT License
