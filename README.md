# 🛡️ Advanced Threat Intelligence Platform (TIP)

> A real-world cybersecurity project simulating a **Finance & Banking SOC environment**.  
> Built during cybersecurity internship at **Infotact Solutions**.

---

## 📌 Project Overview

The **Threat Intelligence Platform (TIP)** automatically collects, normalizes, scores, and indexes malicious indicators (IOCs) from multiple OSINT sources — and enforces dynamic firewall rules to block threats in real time.

---

## 🏗️ Architecture
OSINT Sources (OTX + VirusTotal)
↓
Async Ingestion Engine  (aiohttp + motor)
↓
MongoDB  (raw_threats collection)
↓
Threat Scoring Engine  (risk_score 0.0 - 1.0)
↓
Elasticsearch  (ioc_threat_intel index)
↓
Kibana Dashboard + Flask SOC Dashboard
↓
Firewall Automation  (iptables block/rollback)

---

## ⚙️ Tech Stack

| Layer | Technology |
|---|---|
| Language | Python 3.13 |
| Database | MongoDB |
| SIEM | Elasticsearch 8.13 + Kibana |
| Threat Feeds | AlienVault OTX + VirusTotal |
| Async | aiohttp + motor |
| Dashboard | Flask + Kibana |
| Firewall | Linux iptables |
| OS | Kali Linux |

---

## 📁 Project Structure
tip-project/
├── app/
│   ├── ingestion/
│   │   ├── otx_feed.py              # OTX threat feed ingestion
│   │   ├── virustotal_feed.py       # VirusTotal IOC enrichment
│   │   └── async_ingestion.py       # Async ingestion pipeline
│   ├── analysis/
│   │   ├── threat_scoring.py        # Risk score calculation
│   │   └── correlation.py           # IOC correlation engine
│   ├── indexing/
│   │   ├── elastic_client.py        # Elasticsearch connection + index
│   │   └── sync_mongo_to_es.py      # MongoDB → Elasticsearch sync
│   ├── firewall/
│   │   ├── firewall_engine.py       # iptables automation
│   │   ├── rollback.py              # Firewall rule rollback
│   │   └── alerting.py              # Critical IOC alerting
│   ├── dashboard/
│   │   ├── app.py                   # Flask SOC dashboard
│   │   └── kibana_setup.py          # Kibana setup verification
│   └── database/
│       └── mongo_client.py          # MongoDB client
├── tests/
│   └── test_pipeline.py             # Full pipeline integration tests
├── config/
│   └── .env.example                 # Environment variables template
├── logs/                            # Firewall and alert logs
└── README.md

---

## 🚀 Setup & Run

### 1. Clone & Setup
```bash
git clone https://github.com/RajJoshi5453/Advanced-Threat-Intelligence-Platform.git
cd Advanced-Threat-Intelligence-Platform
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
sudo systemctl start kibana
```

### 4. Run Full Pipeline
```bash
# Fetch IOCs from OTX
python3 app/ingestion/async_ingestion.py

# Enrich with VirusTotal
python3 app/ingestion/virustotal_feed.py

# Score + sync to Elasticsearch
python3 -m app.indexing.sync_mongo_to_es

# Run firewall automation
python3 app/firewall/firewall_engine.py

# Launch SOC dashboard
python3 app/dashboard/app.py
```

### 5. Run Tests
```bash
python3 tests/test_pipeline.py
```

### 6. Open Dashboards
Flask SOC Dashboard  →  http://localhost:5000
Kibana Dashboard     →  http://localhost:5601

---

## 📊 Week Progress

| Week | Focus | Status |
|---|---|---|
| Week 1 | OTX Ingestion + MongoDB Setup | ✅ Done |
| Week 2 | Elasticsearch + Threat Scoring + VirusTotal + Async | ✅ Done |
| Week 3 | Firewall Automation + Alerting + Correlation + Dashboards | ✅ Done |
| Week 4 | Testing + Documentation + Final Review | ✅ Done |

---

## 🔑 Key Features

- **Multi-source OSINT ingestion** — OTX + VirusTotal
- **Async pipeline** — faster ingestion using aiohttp + motor
- **Risk scoring engine** — scores IOCs by source, type, and tags
- **Elasticsearch indexing** — searchable threat database
- **Kibana dashboards** — visual SOC threat monitoring
- **Flask SOC dashboard** — custom real-time web UI
- **Firewall automation** — auto-blocks high-risk IPs via iptables
- **Rollback module** — safely removes firewall rules
- **Alerting system** — logs critical IOCs above risk threshold
- **Correlation engine** — groups related IOC campaigns
- **Deduplication** — no duplicate IOCs stored
- **Full test suite** — 6/6 integration tests passing

---

## 🧪 Test Results
==================================================
TIP — Full Pipeline Integration Test
[1] MongoDB connection        ✅ PASS — IOCs in DB: 54
[2] Elasticsearch connection  ✅ PASS — IOCs indexed: 216
[3] Threat scoring engine     ✅ PASS — Scores: 0.5, 1.0
[4] VirusTotal enrichment     ✅ PASS — Enriched: 30
[5] Elasticsearch search      ✅ PASS — High risk found: 5
[6] Log directory             ✅ PASS — Exists
Results: 6/6 tests passed
🎉 All systems operational

---

## 👨‍💻 Author

**Raj Joshi** (Enrollment: D24DIT095)  
B.Tech IT | CHARUSAT University  
Cybersecurity Intern — Infotact Solutions

---

> ⚠️ This project is built for educational and internship evaluation purposes only.
