"""
Kibana Dashboard Setup Script
Run this to verify Kibana connection and index pattern exists.
"""
import requests
import json

KIBANA_URL = "http://localhost:5601"

def check_kibana():
    try:
        r = requests.get(f"{KIBANA_URL}/api/status")
        if r.status_code == 200:
            print("[+] Kibana is running")
            return True
        else:
            print(f"[!] Kibana status: {r.status_code}")
            return False
    except Exception as e:
        print(f"[!] Kibana not reachable: {e}")
        return False

def check_index_pattern():
    headers = {"kbn-xsrf": "true", "Content-Type": "application/json"}
    r = requests.get(
        f"{KIBANA_URL}/api/saved_objects/_find?type=index-pattern",
        headers=headers
    )
    if r.status_code == 200:
        patterns = r.json().get("saved_objects", [])
        for p in patterns:
            if "ioc_threat_intel" in p.get("attributes", {}).get("title", ""):
                print("[+] Index pattern 'ioc_threat_intel' found")
                return True
    print("[!] Index pattern not found — create it manually in Kibana")
    return False

if __name__ == "__main__":
    print("[*] Checking Kibana setup...")
    check_kibana()
    check_index_pattern()
    print(f"[*] Dashboard URL: {KIBANA_URL}/app/dashboards")
    print("[*] Index Management: http://localhost:5601/app/management/data/index_management")
