import requests
import os
from dotenv import load_dotenv
from pymongo import MongoClient
from datetime import datetime, timezone

load_dotenv("config/.env")
OTX_API_KEY = os.getenv("OTX_API_KEY")
MONGO_URI   = os.getenv("MONGO_URI")
DB_NAME     = os.getenv("DB_NAME")

client     = MongoClient(MONGO_URI)
db         = client[DB_NAME]
collection = db["raw_threats"]

OTX_EXPORT_URL = "https://otx.alienvault.com/api/v1/indicators/export"

def normalize_type(otx_type):
    mapping = {
        "IPv4":           "IPv4",
        "IPv6":           "IPv4",
        "domain":         "domain",
        "hostname":       "domain",
        "URL":            "url",
        "FileHash-MD5":   "FileHash",
        "FileHash-SHA1":  "FileHash",
        "FileHash-SHA256":"FileHash",
        "email":          "email",
    }
    return mapping.get(otx_type, otx_type)

def fetch_otx_threats():
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    saved   = 0

    for ioc_type in ["IPv4", "domain", "URL", "FileHash-MD5"]:
        print(f"[*] Fetching {ioc_type} indicators from OTX...")
        params   = {"type": ioc_type, "limit": 20}
        response = requests.get(OTX_EXPORT_URL, headers=headers, params=params)

        if response.status_code != 200:
            print(f"[!] OTX API error for {ioc_type}: {response.status_code}")
            continue

        results = response.json().get("results", [])
        print(f"[+] Got {len(results)} {ioc_type} indicators")

        for item in results:
            indicator = item.get("indicator")
            if not indicator:
                continue

            if collection.find_one({"indicator": indicator, "source": "OTX"}):
                continue

            pulse_info = item.get("pulse_info", {})
            tags       = []

            for pulse in pulse_info.get("pulses", []):
                for tag in pulse.get("tags", []):
                    t = tag.lower().strip()
                    if t and t not in tags:
                        tags.append(t)
                name = pulse.get("name", "").lower()
                for keyword in ["malware", "ransomware", "botnet", "phishing",
                                "c2", "trojan", "banker", "ddos", "exploit",
                                "scanner", "bruteforce", "infostealer", "keylogger"]:
                    if keyword in name and keyword not in tags:
                        tags.append(keyword)

            doc = {
                "indicator":   indicator,
                "type":        normalize_type(ioc_type),
                "source":      "OTX",
                "tags":        tags[:5],
                "pulse_count": pulse_info.get("count", 0),
                "fetched_at":  datetime.now(timezone.utc)
            }
            collection.insert_one(doc)
            saved += 1
            if tags:
                print(f"  [+] {indicator} -> tags: {tags}")

    print(f"\n[+] Saved {saved} new indicators with real tags")

if __name__ == "__main__":
    fetch_otx_threats()
