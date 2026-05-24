# 🛡️ TIP — Advanced Threat Intelligence Platform

> A real-world cybersecurity project simulating a **Finance & Banking SOC environment**.  
> Built for internship evaluation at **Infotact Solutions**.

---

## 📌 Project Overview

The **Threat Intelligence Platform (TIP)** automatically collects, normalizes, scores, and indexes malicious indicators (IOCs) from multiple OSINT sources — and enforces dynamic firewall rules to block threats in real time.

---

## 🏗️ Architecture
OSINT Sources (OTX + VirusTotal)
↓
Async Ingestion Engine
↓
MongoDB (raw_threats)
↓
Threat Scoring Engine
↓
Elasticsearch (ioc_threat_intel)
↓
Kibana Dashboard  ←──  [Week 3]
↓
Firewall Automation (iptables)  ←──  [Week 3]

---

## ⚙️ Tech Stack

| Layer | Technology |
|---|---|
| Language | Python 3.13 |
| Database | MongoDB |
| SIEM | Elasticsearch 8.13 + Kibana |
| Threat Feeds | AlienVault OTX + VirusTotal |
| Async | aiohttp + motor |
| OS | Kali Linux |

---

## 📁 Project Structure
tip-project/
├── app/
│   ├── ingestion/
│   │   ├── otx_feed.py           # OTX threat feed ingestion
│   │   ├── virustotal_feed.py    # VirusTotal IOC enrichment
│   │   └── async_ingestion.py    # Async ingestion pipeline
│   ├── analysis/
│   │   └── threat_scoring.py     # Risk score calculation
│   ├── indexing/
│   │   ├── elastic_client.py     # Elasticsearch connection + index
│   │   └── sync_mongo_to_es.py   # MongoDB → Elasticsearch sync
│   └── database/
│       └── mongo_client.py       # MongoDB client
├── ingestion/
│   └── otx_feed.py               # Original OTX script
├── config/
│   └── .env                      # API keys (not committed)
└── README.md

---

## 🚀 Setup & Run

### 1. Clone & Setup
```bash
git clone https://github.com/yourusername/tip-project.git
cd tip-project
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure Environment
```bash
cp config/.env.example config/.env
# Add your OTX_API_KEY, VT_API_KEY, MONGO_URI, DB_NAME
```

### 3. Start Services
```bash
sudo systemctl start mongod
sudo systemctl start elasticsearch
```

### 4. Run Pipeline
```bash
# Ingest from OTX
python3 app/ingestion/async_ingestion.py

# Enrich with VirusTotal
python3 app/ingestion/virustotal_feed.py

# Score + sync to Elasticsearch
python3 -m app.indexing.sync_mongo_to_es
```

---

## 📊 Week Progress

| Week | Focus | Status |
|---|---|---|
| Week 1 | OTX Ingestion + MongoDB Setup | ✅ Done |
| Week 2 | Elasticsearch + Threat Scoring + VirusTotal + Async | ✅ Done |
| Week 3 | Firewall Automation + Alerting + Correlation | 🔄 In Progress |
| Week 4 | Kibana Dashboard + Docs + Testing | ⏳ Pending |

---

## 🔑 Key Features

- **Multi-source OSINT ingestion** — OTX + VirusTotal
- **Async pipeline** — faster ingestion using aiohttp + motor
- **Risk scoring engine** — scores IOCs by source, type, and tags
- **Elasticsearch indexing** — searchable threat database
- **Deduplication** — no duplicate IOCs stored
- **Modular architecture** — easy to extend with new feeds

---

## 👨‍💻 Author

**Raj Joshi**  
B.Tech IT | CHARUSAT University  
Cybersecurity Intern — Infotact Solutions

---

> ⚠️ This project is built for educational and internship evaluation purposes only.
