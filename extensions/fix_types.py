import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import re
from pymongo import MongoClient

client = MongoClient("mongodb://localhost:27017/")
col    = client["tip_database"]["raw_threats"]

def detect_type(indicator):
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', indicator):
        return "IPv4"
    elif re.match(r'^[a-f0-9]{32,64}$', indicator, re.I):
        return "FileHash"
    elif indicator.startswith("http"):
        return "url"
    else:
        return "domain"

updated = 0
for doc in col.find():
    correct_type = detect_type(doc["indicator"])
    if doc.get("type") != correct_type:
        col.update_one({"_id": doc["_id"]}, {"$set": {"type": correct_type}})
        updated += 1

print(f"[✓] Fixed types for {updated} IOCs")
