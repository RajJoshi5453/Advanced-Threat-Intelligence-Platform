import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask import Flask, render_template, jsonify, request, send_file
from pymongo import MongoClient
from bson import ObjectId
from datetime import datetime
import tempfile

client = MongoClient("mongodb://localhost:27017/")
db  = client["tip_database"]
col = db["raw_threats"]

try:
    from extensions.mitre_mapping import map_to_mitre
    MITRE_ENABLED = True
except ImportError:
    MITRE_ENABLED = False
    def map_to_mitre(ioc): return {"techniques": [], "tactics": [], "confidence": "unknown"}

app = Flask(__name__)

def serialize(doc):
    doc["_id"] = str(doc["_id"])
    if isinstance(doc.get("fetched_at"), datetime):
        doc["fetched_at"] = doc["fetched_at"].strftime("%Y-%m-%d %H:%M:%S")
    if isinstance(doc.get("enriched_at"), datetime):
        doc["enriched_at"] = doc["enriched_at"].strftime("%Y-%m-%d %H:%M:%S")
    doc["risk_score"] = float(doc.get("risk_score") or 0.0)
    if "mitre" not in doc:
        doc["mitre"] = map_to_mitre(doc)
    doc.pop("vt_data", None)
    return doc

@app.route("/")
def index():
    total      = col.count_documents({})
    critical   = col.count_documents({"risk_score": {"$gte": 0.8}})
    with_mitre = col.count_documents({"mitre": {"$exists": True}})
    iocs = [serialize(doc) for doc in col.find().sort("fetched_at", -1).limit(20)]
    return render_template("index.html",
        iocs=iocs, total=total, critical=critical,
        with_mitre=with_mitre, mitre_enabled=MITRE_ENABLED)

@app.route("/api/ioc/<ioc_id>")
def api_ioc(ioc_id):
    try:
        doc = col.find_one({"_id": ObjectId(ioc_id)})
    except Exception:
        return jsonify({"error": "invalid id"}), 400
    if not doc:
        return jsonify({"error": "not found"}), 404
    return jsonify(serialize(doc))

@app.route("/api/stats")
def api_stats():
    pipeline  = [{"$group": {"_id": "$type",   "count": {"$sum": 1}}}]
    pipeline2 = [{"$group": {"_id": "$source", "count": {"$sum": 1}}}]
    return jsonify({
        "total":     col.count_documents({}),
        "by_type":   {d["_id"]: d["count"] for d in col.aggregate(pipeline)},
        "by_source": {d["_id"]: d["count"] for d in col.aggregate(pipeline2)},
        "critical":  col.count_documents({"risk_score": {"$gte": 0.8}})
    })

@app.route("/report")
def download_report():
    from extensions.report_generator import build_report
    tmp = tempfile.mktemp(suffix=".pdf")
    build_report(tmp)
    return send_file(tmp, as_attachment=True,
                     download_name="TIP_Threat_Report.pdf",
                     mimetype="application/pdf")

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
