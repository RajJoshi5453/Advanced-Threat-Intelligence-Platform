import subprocess
import logging
from datetime import datetime
from pymongo import MongoClient
from elasticsearch import Elasticsearch
import os
from dotenv import load_dotenv

load_dotenv("config/.env")
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

RISK_THRESHOLD = 0.5
LOG_FILE = "logs/firewall_blocks.log"

os.makedirs("logs", exist_ok=True)

def get_high_risk_iocs():
    es = Elasticsearch("http://localhost:9200")
    result = es.search(
        index="ioc_threat_intel",
        body={
            "query": {"range": {"risk_score": {"gte": RISK_THRESHOLD}}},
            "size": 100
        }
    )
    hits = result["hits"]["hits"]
    iocs = [h["_source"] for h in hits]
    logger.info(f"Found {len(iocs)} high-risk IOCs above threshold {RISK_THRESHOLD}")
    return iocs

def is_valid_ip(indicator):
    parts = indicator.split(".")
    return len(parts) == 4 and all(p.isdigit() for p in parts)

def block_ip(ip):
    try:
        # Check if rule already exists
        check = subprocess.run(
            ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True
        )
        if check.returncode == 0:
            logger.info(f"Rule already exists for {ip}")
            return False

        # Add block rule
        subprocess.run(
            ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
            check=True
        )
        log_block(ip)
        logger.info(f"Blocked IP: {ip}")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to block {ip}: {e}")
        return False

def log_block(ip):
    with open(LOG_FILE, "a") as f:
        f.write(f"{datetime.now()} | BLOCKED | {ip}\n")

def run():
    iocs = get_high_risk_iocs()
    blocked = 0
    skipped = 0
    for ioc in iocs:
        indicator = ioc.get("indicator", "")
        if is_valid_ip(indicator):
            result = block_ip(indicator)
            if result:
                blocked += 1
            else:
                skipped += 1
        else:
            logger.info(f"Skipping non-IP indicator: {indicator}")
            skipped += 1

    logger.info(f"Done — Blocked: {blocked} | Skipped: {skipped}")

if __name__ == "__main__":
    run()
