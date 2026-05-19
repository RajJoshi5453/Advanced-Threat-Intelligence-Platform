import os
from dotenv import load_dotenv
from pymongo import MongoClient
from datetime import datetime, timezone
import re

load_dotenv("config/.env")

MONGO_URI = os.getenv("MONGO_URI")
DB_NAME = os.getenv("DB_NAME")

client = MongoClient(MONGO_URI)
db = client[DB_NAME]

raw = db["raw_threats"]
clean = db["threats"]

# Check if string is valid IP
def is_ip(value):
    pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    return bool(re.match(pattern, value))

# Calculate risk score 1-10
def calculate_risk(source, malicious_votes=0, pulse_count=0):
    if source == "VirusTotal":
        if malicious_votes >= 15:
            return 9
        elif malicious_votes >= 10:
            return 7
        elif malicious_votes >= 5:
            return 5
        else:
            return 3
    elif source == "OTX":
        if pulse_count >= 10:
            return 8
        elif pulse_count >= 5:
            return 6
        elif pulse_count >= 1:
            return 4
        else:
            return 2
    return 1

def normalize():
    records = raw.find()
    saved = 0
    skipped = 0

    print("[*] Starting normalization...")

    for record in records:
        indicator = record.get("indicator", "").strip()
        source = record.get("source", "unknown")

        if not indicator:
            continue

        # Fix type — check if IP or domain
        ioc_type = "IPv4" if is_ip(indicator) else "domain"

        # Calculate risk score
        malicious_votes = record.get("malicious_votes", 0)
        pulse_count = record.get("pulse_count", 0)
        risk_score = calculate_risk(source, malicious_votes, pulse_count)

        # Skip low risk OTX domains
        if ioc_type == "domain" and risk_score <= 2:
            skipped += 1
            continue

        # Deduplication check
        if clean.find_one({"indicator": indicator}):
            skipped += 1
            continue

        doc = {
            "indicator": indicator,
            "type": ioc_type,
            "source": source,
            "risk_score": risk_score,
            "malicious_votes": malicious_votes,
            "pulse_count": pulse_count,
            "normalized_at": datetime.now(timezone.utc)
        }

        clean.insert_one(doc)
        saved += 1

    print(f"[+] Normalized: {saved} saved, {skipped} skipped")

if __name__ == "__main__":
    normalize()
