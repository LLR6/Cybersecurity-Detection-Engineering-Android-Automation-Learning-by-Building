RULE_TECHNIQUES = {
    "AUTH-SEQ-001": [
        {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
    ],
    "NET-SCAN-001": [
        {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
    ],
    "DNS-TUNNEL-001": [
        {"id": "T1071.004", "name": "DNS", "tactic": "Command and Control"},
    ],
    "CHAIN-001": [
        {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
        {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
    ],
}


def enrich(alerts):
    for alert in alerts:
        alert.techniques = [dict(item) for item in RULE_TECHNIQUES.get(alert.rule_id, [])]
    return alerts
