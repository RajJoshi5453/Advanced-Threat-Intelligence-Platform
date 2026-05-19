# Advanced Threat Intelligence Platform (TIP)

## Overview

The Advanced Threat Intelligence Platform (TIP) is an enterprise-grade cybersecurity solution designed for banking and financial environments.

The system automatically ingests threat intelligence feeds, normalizes Indicators of Compromise (IOCs), stores data in MongoDB, integrates with Elasticsearch for indexing and analytics, and prepares data for dynamic firewall policy enforcement.

---

## Features

- Threat intelligence ingestion from AlienVault OTX
- IOC normalization and deduplication
- MongoDB integration
- Elasticsearch indexing
- Threat scoring engine
- Async ingestion pipeline
- Dynamic firewall automation (planned)
- SIEM integration with ELK Stack
- Risk-based threat analysis

---

## Tech Stack

### Backend
- Python

### Database
- MongoDB

### Threat Intelligence Sources
- AlienVault OTX
- VirusTotal

### SIEM Stack
- Elasticsearch
- Kibana

### Operating System
- Kali Linux

---

## Project Structure

```text
app/
├── ingestion/
├── normalization/
├── database/
├── analysis/
└── utils/
Current Progress

Week 1

Environment setup

MongoDB integration

OTX feed ingestion

IOC storage pipeline

Basic normalization

Week 2

Elasticsearch setup

Threat scoring engine

ELK integration (in progress)

Future Improvements

Dynamic firewall automation

Real-time IOC correlation

Kibana dashboards

Alerting system

Incident response workflows

Rule rollback engine

Author:Raj Joshi

Cybersecurity Internship Project
