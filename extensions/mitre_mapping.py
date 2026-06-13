"""
extensions/mitre_mapping.py
MITRE ATT&CK Mapping Module — TIP Project Extension
Maps IOCs to MITRE ATT&CK Tactics & Techniques based on
indicator type, tags, and threat context.
"""

from datetime import datetime, timezone
from typing import Optional

# ─────────────────────────────────────────────
# MITRE ATT&CK Knowledge Base (Finance/Banking focused)
# Source: https://attack.mitre.org
# ─────────────────────────────────────────────

MITRE_TECHNIQUES = {
    # TAG → list of (TechniqueID, TechniqueName, Tactic)
    "phishing": [
        ("T1566.001", "Spearphishing Attachment",       "Initial Access"),
        ("T1566.002", "Spearphishing Link",             "Initial Access"),
        ("T1598.003", "Spearphishing Link (Recon)",     "Reconnaissance"),
    ],
    "malware": [
        ("T1059",     "Command and Scripting Interpreter", "Execution"),
        ("T1204",     "User Execution",                    "Execution"),
        ("T1027",     "Obfuscated Files or Information",   "Defense Evasion"),
    ],
    "ransomware": [
        ("T1486",     "Data Encrypted for Impact",      "Impact"),
        ("T1490",     "Inhibit System Recovery",        "Impact"),
        ("T1489",     "Service Stop",                   "Impact"),
        ("T1083",     "File and Directory Discovery",   "Discovery"),
    ],
    "botnet": [
        ("T1071.001", "Web Protocols (C2)",             "Command and Control"),
        ("T1090",     "Proxy",                          "Command and Control"),
        ("T1571",     "Non-Standard Port",              "Command and Control"),
    ],
    "c2": [
        ("T1071",     "Application Layer Protocol",     "Command and Control"),
        ("T1095",     "Non-Application Layer Protocol", "Command and Control"),
        ("T1572",     "Protocol Tunneling",             "Command and Control"),
        ("T1008",     "Fallback Channels",              "Command and Control"),
    ],
    "trojan": [
        ("T1055",     "Process Injection",              "Defense Evasion"),
        ("T1036",     "Masquerading",                   "Defense Evasion"),
        ("T1547",     "Boot or Logon Autostart",        "Persistence"),
    ],
    "banker": [
        ("T1185",     "Browser Session Hijacking",      "Collection"),
        ("T1539",     "Steal Web Session Cookie",       "Credential Access"),
        ("T1056.001", "Keylogging",                     "Collection"),
        ("T1557",     "Adversary-in-the-Middle",        "Credential Access"),
    ],
    "keylogger": [
        ("T1056.001", "Keylogging",                     "Collection"),
        ("T1119",     "Automated Collection",           "Collection"),
    ],
    "infostealer": [
        ("T1555",     "Credentials from Password Stores", "Credential Access"),
        ("T1552",     "Unsecured Credentials",            "Credential Access"),
        ("T1005",     "Data from Local System",           "Collection"),
    ],
    "ddos": [
        ("T1498",     "Network Denial of Service",      "Impact"),
        ("T1499",     "Endpoint Denial of Service",     "Impact"),
    ],
    "exploit": [
        ("T1203",     "Exploitation for Client Execution", "Execution"),
        ("T1190",     "Exploit Public-Facing Application", "Initial Access"),
        ("T1068",     "Exploitation for Privilege Escalation", "Privilege Escalation"),
    ],
    "scanner": [
        ("T1046",     "Network Service Discovery",      "Discovery"),
        ("T1595",     "Active Scanning",                "Reconnaissance"),
    ],
    "bruteforce": [
        ("T1110",     "Brute Force",                    "Credential Access"),
        ("T1110.001", "Password Guessing",              "Credential Access"),
        ("T1110.003", "Password Spraying",              "Credential Access"),
    ],
    "credential": [
        ("T1078",     "Valid Accounts",                 "Defense Evasion"),
        ("T1110",     "Brute Force",                    "Credential Access"),
        ("T1539",     "Steal Web Session Cookie",       "Credential Access"),
    ],
    "lateral": [
        ("T1021",     "Remote Services",                "Lateral Movement"),
        ("T1570",     "Lateral Tool Transfer",          "Lateral Movement"),
    ],
    "exfiltration": [
        ("T1041",     "Exfiltration Over C2 Channel",  "Exfiltration"),
        ("T1048",     "Exfiltration Over Alternative Protocol", "Exfiltration"),
    ],
}

# IOC type → default techniques (when no tags match)
TYPE_DEFAULT_TECHNIQUES = {
    "IPv4": [
        ("T1071",     "Application Layer Protocol",     "Command and Control"),
        ("T1219",     "Remote Access Software",         "Command and Control"),
    ],
    "domain": [
        ("T1071.004", "DNS",                            "Command and Control"),
        ("T1568",     "Dynamic Resolution",             "Command and Control"),
    ],
    "url": [
        ("T1566.002", "Spearphishing Link",             "Initial Access"),
        ("T1102",     "Web Service",                    "Command and Control"),
    ],
    "FileHash-MD5": [
        ("T1027",     "Obfuscated Files or Information","Defense Evasion"),
        ("T1204",     "User Execution",                 "Execution"),
    ],
    "FileHash-SHA256": [
        ("T1027",     "Obfuscated Files or Information","Defense Evasion"),
        ("T1204",     "User Execution",                 "Execution"),
    ],
    "email": [
        ("T1566.001", "Spearphishing Attachment",       "Initial Access"),
        ("T1598",     "Phishing for Information",       "Reconnaissance"),
    ],
}

# ─────────────────────────────────────────────
# Core Mapping Function
# ─────────────────────────────────────────────

def map_to_mitre(ioc: dict) -> dict:
    """
    Takes an IOC dict, returns MITRE ATT&CK mapping.

    Input IOC fields used:
        - type     : IPv4 | domain | url | FileHash-MD5 | etc.
        - tags     : list of threat tags
        - source   : OTX | virustotal | manual
        - indicator: the actual IOC value

    Returns:
        {
            "techniques": [ {id, name, tactic, url}, ... ],
            "tactics":    [ "Initial Access", ... ],   # unique
            "confidence": "high" | "medium" | "low",
            "mapped_at":  datetime
        }
    """
    tags = [t.lower() for t in ioc.get("tags", [])]
    ioc_type = ioc.get("type", "")

    matched_techniques = []
    seen_ids = set()

    # Step 1: match by tags
    for tag in tags:
        techniques = MITRE_TECHNIQUES.get(tag, [])
        for tech_id, tech_name, tactic in techniques:
            if tech_id not in seen_ids:
                matched_techniques.append({
                    "id":     tech_id,
                    "name":   tech_name,
                    "tactic": tactic,
                    "url":    f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}",
                    "source": "tag_match"
                })
                seen_ids.add(tech_id)

    # Step 2: fallback to IOC type defaults if no tag match
    if not matched_techniques:
        defaults = TYPE_DEFAULT_TECHNIQUES.get(ioc_type, [])
        for tech_id, tech_name, tactic in defaults:
            if tech_id not in seen_ids:
                matched_techniques.append({
                    "id":     tech_id,
                    "name":   tech_name,
                    "tactic": tactic,
                    "url":    f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}",
                    "source": "type_default"
                })
                seen_ids.add(tech_id)

    # Step 3: unique tactics list
    tactics = list(dict.fromkeys(t["tactic"] for t in matched_techniques))

    # Step 4: confidence scoring
    if tags and any(t in MITRE_TECHNIQUES for t in tags):
        confidence = "high"
    elif ioc_type in TYPE_DEFAULT_TECHNIQUES:
        confidence = "medium"
    else:
        confidence = "low"

    return {
        "techniques": matched_techniques,
        "tactics":    tactics,
        "confidence": confidence,
        "mapped_at":  datetime.now(timezone.utc).isoformat()
    }


def enrich_ioc_with_mitre(ioc: dict) -> dict:
    """
    Returns the IOC dict with 'mitre' field added.
    Does NOT modify MongoDB — caller handles persistence.
    """
    mitre = map_to_mitre(ioc)
    enriched = dict(ioc)
    enriched["mitre"] = mitre
    return enriched


def bulk_enrich(iocs: list[dict]) -> list[dict]:
    """Enrich a list of IOCs with MITRE mappings."""
    return [enrich_ioc_with_mitre(ioc) for ioc in iocs]


def get_technique_summary(ioc: dict) -> str:
    """Human-readable one-line summary of MITRE mapping."""
    mitre = map_to_mitre(ioc)
    if not mitre["techniques"]:
        return "No MITRE mapping found"
    tactic_str = " → ".join(mitre["tactics"][:3])
    tech_ids   = ", ".join(t["id"] for t in mitre["techniques"][:3])
    return f"[{mitre['confidence'].upper()}] Tactics: {tactic_str} | Techniques: {tech_ids}"


# ─────────────────────────────────────────────
# MongoDB Integration (optional, needs pymongo)
# ─────────────────────────────────────────────

def enrich_and_save(ioc: dict, collection) -> Optional[dict]:
    """
    Enriches IOC with MITRE data and updates MongoDB.
    Pass in pymongo collection object.

    Usage:
        from pymongo import MongoClient
        client = MongoClient(MONGO_URI)
        col = client[DB_NAME]["raw_threats"]
        enrich_and_save(ioc, col)
    """
    try:
        mitre = map_to_mitre(ioc)
        result = collection.update_one(
            {"indicator": ioc["indicator"], "source": ioc["source"]},
            {"$set": {"mitre": mitre}},
            upsert=False
        )
        if result.modified_count > 0:
            print(f"[+] MITRE mapped: {ioc['indicator']} → {mitre['tactics']}")
        return mitre
    except Exception as e:
        print(f"[!] Error enriching {ioc.get('indicator')}: {e}")
        return None


def batch_enrich_mongodb(collection, limit: int = 100):
    """
    Fetches IOCs from MongoDB that don't have MITRE data yet,
    enriches them, and saves back.

    Usage:
        batch_enrich_mongodb(col, limit=200)
    """
    query  = {"mitre": {"$exists": False}}
    cursor = collection.find(query).limit(limit)
    total  = 0

    for ioc in cursor:
        enrich_and_save(ioc, collection)
        total += 1

    print(f"[✓] MITRE enrichment complete: {total} IOCs processed")


# ─────────────────────────────────────────────
# CLI / Quick Test
# ─────────────────────────────────────────────

if __name__ == "__main__":
    # Test IOCs
    test_iocs = [
        {
            "indicator": "192.168.1.100",
            "type": "IPv4",
            "source": "OTX",
            "tags": ["c2", "botnet"]
        },
        {
            "indicator": "evil-bank-login.com",
            "type": "domain",
            "source": "virustotal",
            "tags": ["phishing", "banker"]
        },
        {
            "indicator": "http://malware.ru/payload.exe",
            "type": "url",
            "source": "OTX",
            "tags": ["malware", "ransomware"]
        },
        {
            "indicator": "10.0.0.5",
            "type": "IPv4",
            "source": "manual",
            "tags": []          # no tags → type fallback
        },
    ]

    print("=" * 60)
    print("  MITRE ATT&CK Mapping — TIP Extension Test")
    print("=" * 60)

    for ioc in test_iocs:
        print(f"\n[IOC] {ioc['indicator']} ({ioc['type']})")
        print(f"      Tags: {ioc['tags']}")
        result = map_to_mitre(ioc)
        print(f"      Confidence : {result['confidence'].upper()}")
        print(f"      Tactics    : {' → '.join(result['tactics'])}")
        print(f"      Techniques :")
        for t in result["techniques"]:
            print(f"        • {t['id']} — {t['name']} [{t['tactic']}]")
            print(f"          {t['url']}")

    print("\n" + "=" * 60)
    print("  Summary Test")
    print("=" * 60)
    for ioc in test_iocs:
        print(f"  {ioc['indicator']:35} → {get_technique_summary(ioc)}")
