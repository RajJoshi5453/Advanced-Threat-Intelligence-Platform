import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from pymongo import MongoClient
from app.analysis.threat_scoring import calculate_risk_score

client = MongoClient("mongodb://localhost:27017/")
col    = client["tip_database"]["raw_threats"]

updated = 0
for doc in col.find():
    score = calculate_risk_score(doc)
    col.update_one({"_id": doc["_id"]}, {"$set": {"risk_score": score}})
    updated += 1

print(f"[✓] Updated risk scores for {updated} IOCs")
