from pymongo import MongoClient
from app.indexing.elastic_client import get_client, create_index, index_ioc
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
            "type":       doc.get("type", "unknown"),
            "source":     doc.get("source", "OTX"),
            "risk_score": 0.0,
            "tags":       [],
            "created_at": doc.get("fetched_at", None),
            "raw":        {}
        }
        index_ioc(es, ioc)
        count += 1

    logger.info(f"Synced {count} IOCs to Elasticsearch")

if __name__ == "__main__":
    sync()
