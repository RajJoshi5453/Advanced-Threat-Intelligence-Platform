def calculate_risk_score(ioc: dict) -> float:
    score = 0.0

    source_weights = {
        "OTX": 0.4,
        "virustotal": 0.6,
        "manual": 0.3
    }
    score += source_weights.get(ioc.get("source", ""), 0.2)

    high_risk_tags = ["malware", "ransomware", "botnet", "phishing", "c2"]
    tags = [t.lower() for t in ioc.get("tags", [])]
    for tag in tags:
        if tag in high_risk_tags:
            score += 0.2

    type_weights = {
        "IPv4": 0.1,
        "domain": 0.15,
        "url": 0.2
    }
    score += type_weights.get(ioc.get("type", ""), 0.05)

    return round(min(score, 1.0), 2)
