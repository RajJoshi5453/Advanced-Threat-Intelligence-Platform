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

# VT endpoint — fetch malicious IPs from threat feed
VT_URL = "https://www.virustotal.com/api/v3/ip_addresses"

# Known malicious IPs to check (VT free tier has no feed, so we check samples)
SAMPLE_IPS = [
    "185.220.101.45",
    "194.165.16.11",
    "45.142.212.100",
    "91.92.109.196",
    "193.32.162.157"
]

def fetch_vt_threats():
    headers = {"x-apikey": VT_API_KEY}
    saved = 0

    print("[*] Connecting to VirusTotal...")

    for ip in SAMPLE_IPS:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        response = requests.get(url, headers=headers)

        if response.status_code != 200:
            print(f"[!] VT error for {ip}: {response.status_code}")
            continue

        data = response.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)

        if malicious == 0:
            print(f"[-] {ip} not malicious, skipping")
            continue

        if collection.find_one({"indicator": ip, "source": "VirusTotal"}):
            print(f"[=] {ip} already exists, skipping")
            continue

        doc = {
            "indicator": ip,
            "type": "IPv4",
            "source": "VirusTotal",
            "malicious_votes": malicious,
            "fetched_at": datetime.now(timezone.utc)
        }

        collection.insert_one(doc)
        print(f"[+] Saved {ip} — malicious votes: {malicious}")
        saved += 1

    print(f"[+] Done. Saved {saved} indicators from VirusTotal")

if __name__ == "__main__":
    fetch_vt_threats()
