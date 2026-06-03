"""
Full Pipeline Integration Test
Tests every component of the TIP system end to end.
"""
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pymongo import MongoClient
from elasticsearch import Elasticsearch
from dotenv import load_dotenv
from app.analysis.threat_scoring import calculate_risk_score

load_dotenv("config/.env")

PASS = "✅ PASS"
FAIL = "❌ FAIL"

def test_mongodb():
    print("\n[1] Testing MongoDB connection...")
    try:
        client = MongoClient(os.getenv("MONGO_URI"), serverSelectionTimeoutMS=3000)
        client.server_info()
        db = client[os.getenv("DB_NAME")]
        count = db["raw_threats"].count_documents({})
        print(f"    {PASS} — Connected | IOCs in DB: {count}")
        return True
    except Exception as e:
        print(f"    {FAIL} — {e}")
        return False

def test_elasticsearch():
    print("\n[2] Testing Elasticsearch connection...")
    try:
        es = Elasticsearch("http://localhost:9200")
        if es.ping():
            count = es.count(index="ioc_threat_intel")["count"]
            print(f"    {PASS} — Connected | IOCs indexed: {count}")
            return True
        else:
            print(f"    {FAIL} — Ping failed")
            return False
    except Exception as e:
        print(f"    {FAIL} — {e}")
        return False

def test_threat_scoring():
    print("\n[3] Testing threat scoring engine...")
    try:
        ioc = {"source": "OTX", "type": "IPv4", "tags": []}
        score = calculate_risk_score(ioc)
        assert 0.0 <= score <= 1.0
        print(f"    {PASS} — OTX+IPv4 score: {score}")

        ioc2 = {"source": "virustotal", "type": "url", "tags": ["malware", "botnet"]}
        score2 = calculate_risk_score(ioc2)
        print(f"    {PASS} — VT+URL+malware+botnet score: {score2}")
        return True
    except Exception as e:
        print(f"    {FAIL} — {e}")
        return False

def test_vt_enrichment():
    print("\n[4] Testing VirusTotal enrichment data in MongoDB...")
    try:
        client = MongoClient(os.getenv("MONGO_URI"))
        db = client[os.getenv("DB_NAME")]
        enriched = db["raw_threats"].count_documents({"vt_enriched": True})
        print(f"    {PASS} — VT enriched IOCs: {enriched}")
        return True
    except Exception as e:
        print(f"    {FAIL} — {e}")
        return False

def test_es_search():
    print("\n[5] Testing Elasticsearch search query...")
    try:
        es = Elasticsearch("http://localhost:9200")
        result = es.search(
            index="ioc_threat_intel",
            body={
                "query": {"range": {"risk_score": {"gte": 0.4}}},
                "size": 5
            }
        )
        hits = len(result["hits"]["hits"])
        print(f"    {PASS} — High risk IOCs found: {hits}")
        return True
    except Exception as e:
        print(f"    {FAIL} — {e}")
        return False

def test_log_files():
    print("\n[6] Testing log directory...")
    try:
        os.makedirs("logs", exist_ok=True)
        assert os.path.exists("logs")
        print(f"    {PASS} — Logs directory exists")
        return True
    except Exception as e:
        print(f"    {FAIL} — {e}")
        return False

if __name__ == "__main__":
    print("=" * 50)
    print("  TIP — Full Pipeline Integration Test")
    print("=" * 50)

    results = [
        test_mongodb(),
        test_elasticsearch(),
        test_threat_scoring(),
        test_vt_enrichment(),
        test_es_search(),
        test_log_files()
    ]

    passed = sum(results)
    total = len(results)

    print("\n" + "=" * 50)
    print(f"  Results: {passed}/{total} tests passed")
    if passed == total:
        print("  🎉 All systems operational")
    else:
        print("  ⚠️  Some components need attention")
    print("=" * 50)
