from pymongo import MongoClient
from app.indexing.elastic_client import get_client, create_index, index_ioc
from app.analysis.threat_scoring import calculate_risk_score
from dotenv import load_dotenv
import os
import logging

load_dotenv("config/.env")
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def sync():
    client = MongoClient(os.getenv("MONGO_URI"))
    db = client[os.getenv("DB_NAME")]
    collection = db["raw_threats"]

    es = get_client()
    create_index(es)

    docs = list(collection.find({}))
    count = 0
    for doc in docs:
        ioc = {
            "indicator":  doc.get("indicator", ""),
            "type":       doc.get("type", "IPv4"),
            "source":     doc.get("source", "OTX"),
            "tags":       [],
            "created_at": doc.get("fetched_at", None),
            "raw":        {}
        }
        ioc["risk_score"] = calculate_risk_score(ioc)
        index_ioc(es, ioc)
        count += 1

    logger.info(f"Synced {count} IOCs with risk scores to Elasticsearch")

if __name__ == "__main__":
    sync()
