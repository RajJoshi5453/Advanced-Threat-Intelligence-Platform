import logging
import os
from datetime import datetime
from elasticsearch import Elasticsearch

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

ALERT_LOG = "logs/alerts.log"
RISK_THRESHOLD = 0.7

os.makedirs("logs", exist_ok=True)

def get_critical_iocs():
    es = Elasticsearch("http://localhost:9200")
    result = es.search(
        index="ioc_threat_intel",
        body={
            "query": {"range": {"risk_score": {"gte": RISK_THRESHOLD}}},
            "size": 50
        }
    )
    return [h["_source"] for h in result["hits"]["hits"]]

def write_alert(ioc):
    with open(ALERT_LOG, "a") as f:
        f.write(f"{datetime.now()} | ALERT | {ioc['indicator']} | score={ioc['risk_score']} | type={ioc['type']} | source={ioc['source']}\n")

def run_alerts():
    iocs = get_critical_iocs()
    logger.info(f"Found {len(iocs)} critical IOCs above threshold {RISK_THRESHOLD}")
    for ioc in iocs:
        write_alert(ioc)
        logger.warning(f"ALERT: {ioc['indicator']} | risk_score={ioc['risk_score']} | type={ioc['type']}")
    logger.info(f"Alerts written to {ALERT_LOG}")

if __name__ == "__main__":
    run_alerts()
