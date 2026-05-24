import requests
import os
from dotenv import load_dotenv
from pymongo import MongoClient
from datetime import datetime, timezone

load_dotenv("config/.env")

VT_API_KEY = os.getenv("VT_API_KEY")
MONGO_URI = os.getenv("MONGO_URI")
DB_NAME = os.getenv("DB_NAME")

client = MongoClient(MONGO_URI)
db = client[DB_NAME]
collection = db["raw_threats"]

def is_ip(indicator):
    parts = indicator.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)

def enrich_with_virustotal(indicator: str) -> dict:
    if is_ip(indicator):
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}"
    else:
        url = f"https://www.virustotal.com/api/v3/domains/{indicator}"

    headers = {"x-apikey": VT_API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        return {}
    data = response.json()
    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    return {
        "malicious":  stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless":   stats.get("harmless", 0)
    }

def enrich_all():
    docs = list(collection.find({}))
    print(f"[*] Enriching {len(docs)} IOCs with VirusTotal...")
    enriched = 0
    for doc in docs:
        if doc.get("vt_enriched"):
            continue
        indicator = doc.get("indicator")
        vt_data = enrich_with_virustotal(indicator)
        if vt_data:
            collection.update_one(
                {"_id": doc["_id"]},
                {"$set": {
                    "vt_data": vt_data,
                    "vt_enriched": True,
                    "enriched_at": datetime.now(timezone.utc)
                }}
            )
            enriched += 1
    print(f"[+] Enriched {enriched} IOCs with VirusTotal data")

if __name__ == "__main__":
    enrich_all()
