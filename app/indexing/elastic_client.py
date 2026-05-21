from elasticsearch import Elasticsearch
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

INDEX_NAME = "ioc_threat_intel"

def get_client():
    es = Elasticsearch(
        "http://localhost:9200",
        verify_certs=False,
        ssl_show_warn=False
    )
    if es.ping():
        logger.info("Elasticsearch connected")
    else:
        logger.error("Elasticsearch connection failed")
    return es

def create_index(es):
    mapping = {
        "mappings": {
            "properties": {
                "indicator":  {"type": "keyword"},
                "type":       {"type": "keyword"},
                "source":     {"type": "keyword"},
                "risk_score": {"type": "float"},
                "tags":       {"type": "keyword"},
                "created_at": {"type": "date"},
                "raw":        {"type": "object", "enabled": False}
            }
        }
    }
    if not es.indices.exists(index=INDEX_NAME):
        es.indices.create(index=INDEX_NAME, body=mapping)
        logger.info(f"Index '{INDEX_NAME}' created")
    else:
        logger.info(f"Index '{INDEX_NAME}' already exists")

def index_ioc(es, ioc_doc):
    resp = es.index(index=INDEX_NAME, document=ioc_doc)
    return resp["result"]
