import logging
from collections import defaultdict
from pymongo import MongoClient
from dotenv import load_dotenv
import os

load_dotenv("config/.env")
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_all_iocs():
    client = MongoClient(os.getenv("MONGO_URI"))
    db = client[os.getenv("DB_NAME")]
    return list(db["raw_threats"].find({}))

def correlate_by_domain(iocs):
    domain_groups = defaultdict(list)
    for ioc in iocs:
        indicator = ioc.get("indicator", "")
        # Extract base domain
        for part in ["https://", "http://"]:
            indicator = indicator.replace(part, "")
        base = indicator.split("/")[0]
        domain_groups[base].append(ioc)
    # Only return groups with more than 1 IOC
    correlated = {k: v for k, v in domain_groups.items() if len(v) > 1}
    return correlated

def correlate_by_source(iocs):
    source_groups = defaultdict(list)
    for ioc in iocs:
        source_groups[ioc.get("source", "unknown")].append(ioc)
    return dict(source_groups)

def run():
    iocs = get_all_iocs()
    logger.info(f"Running correlation on {len(iocs)} IOCs")

    domain_corr = correlate_by_domain(iocs)
    logger.info(f"Domain correlation groups: {len(domain_corr)}")
    for domain, related in list(domain_corr.items())[:5]:
        logger.info(f"  {domain} → {len(related)} related IOCs")

    source_corr = correlate_by_source(iocs)
    logger.info(f"Source breakdown:")
    for source, items in source_corr.items():
        logger.info(f"  {source}: {len(items)} IOCs")

if __name__ == "__main__":
    run()
