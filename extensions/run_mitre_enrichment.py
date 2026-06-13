import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from pymongo import MongoClient
from extensions.mitre_mapping import enrich_and_save

client = MongoClient("mongodb://localhost:27017/")
col    = client["tip_database"]["raw_threats"]

total = 0
for doc in col.find({"mitre": {"$exists": False}}):
    enrich_and_save(doc, col)
    total += 1

print(f"[✓] MITRE enriched {total} IOCs")
