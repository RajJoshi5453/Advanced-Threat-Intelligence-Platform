import requests
import os
from dotenv import load_dotenv
from pymongo import MongoClient
from datetime import datetime, timezone

# Load API keys from .env
load_dotenv("config/.env")

OTX_API_KEY = os.getenv("OTX_API_KEY")
MONGO_URI = os.getenv("MONGO_URI")
DB_NAME = os.getenv("DB_NAME")

# Connect to MongoDB
client = MongoClient(MONGO_URI)
db = client[DB_NAME]
collection = db["raw_threats"]

# OTX API endpoint — fetches recently modified malicious IPs
OTX_URL = "https://otx.alienvault.com/api/v1/indicators/export"

def fetch_otx_threats():
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    params = {"type": "IPv4", "limit": 50}

    print("[*] Connecting to OTX...")
    response = requests.get(OTX_URL, headers=headers, params=params)

    if response.status_code != 200:
        print(f"[!] OTX API error: {response.status_code}")
        return

    data = response.json()
    results = data.get("results", [])
    print(f"[+] Fetched {len(results)} indicators from OTX")

    saved = 0
    for item in results:
        indicator = item.get("indicator")
        if not indicator:
            continue

        # Check duplicate
        if collection.find_one({"indicator": indicator, "source": "OTX"}):
            continue

        doc = {
            "indicator": indicator,
            "type": "IPv4",
            "source": "OTX",
            "pulse_count": item.get("pulse_info", {}).get("count", 0),
            "fetched_at": datetime.now(timezone.utc)
        }

        collection.insert_one(doc)
        saved += 1

    print(f"[+] Saved {saved} new indicators to MongoDB")

if __name__ == "__main__":
    fetch_otx_threats()
