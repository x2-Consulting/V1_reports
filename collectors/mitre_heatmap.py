"""
Collector for the MITRE ATT&CK Heatmap report.

Extracts technique and tactic IDs from both workbench alerts and OAT detections,
then aggregates counts and builds coverage summaries.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from client import TrendVisionOneClient

# ── Built-in technique name mapping ──────────────────────────────────────────

TECHNIQUE_NAMES: dict[str, str] = {
    "T1136":     "Create Account",
    "T1136.001": "Create Account: Local Account",
    "T1052":     "Exfiltration over Physical Medium",
    "T1564.002": "Hide Artifacts: Hidden Users",
    "T1098":     "Account Manipulation",
    "T1078.003": "Valid Accounts: Local Accounts",
    "T1036.010": "Masquerading: Masquerade File Type",
    "T1033":     "System Owner/User Discovery",
    "T1505.003": "Server Software Component: Web Shell",
    "T1190":     "Exploit Public-Facing Application",
    "T1204.002": "User Execution: Malicious File",
    "T1105":     "Ingress Tool Transfer",
    "T1040":     "Network Sniffing",
    "T1567":     "Exfiltration Over Web Service",
    "T1059.001": "Command and Scripting Interpreter: PowerShell",
    "T1071.001": "Application Layer Protocol: Web Protocols",
    "T1547":     "Boot or Logon Autostart Execution",
    "T1543":     "Create or Modify System Process",
    "T1082":     "System Information Discovery",
    "T1057":     "Process Discovery",
    "T1012":     "Query Registry",
    "T1021":     "Remote Services",
    "T1078":     "Valid Accounts",
    "T1484":     "Domain Policy Modification",
    "T1059":     "Command and Scripting Interpreter",
    "T1055":     "Process Injection",
    "T1003":     "OS Credential Dumping",
    "T1110":     "Brute Force",
    "T1566":     "Phishing",
    "T1027":     "Obfuscated Files or Information",
    "T1070":     "Indicator Removal",
    "T1562":     "Impair Defenses",
    "T1486":     "Data Encrypted for Impact",
    "T1489":     "Service Stop",
    "T1490":     "Inhibit System Recovery",
    "T1071":     "Application Layer Protocol",
    "T1095":     "Non-Application Layer Protocol",
    "T1132":     "Data Encoding",
    "T1041":     "Exfiltration Over C2 Channel",
    "T1048":     "Exfiltration Over Alternative Protocol",
    "T1560":     "Archive Collected Data",
    "T1005":     "Data from Local System",
    "T1074":     "Data Staged",
    "T1210":     "Exploitation of Remote Services",
    "T1534":     "Internal Spearphishing",
    "T1550":     "Use Alternate Authentication Material",
    "T1558":     "Steal or Forge Kerberos Tickets",
    "T1552":     "Unsecured Credentials",
    "T1087":     "Account Discovery",
    "T1018":     "Remote System Discovery",
    "T1049":     "System Network Connections Discovery",
    "T1016":     "System Network Configuration Discovery",
    "T1046":     "Network Service Discovery",
    "T1135":     "Network Share Discovery",
    "T1069":     "Permission Groups Discovery",
    "T1083":     "File and Directory Discovery",
    "T1007":     "System Service Discovery",
    "T1047":     "Windows Management Instrumentation",
    "T1053":     "Scheduled Task/Job",
    "T1218":     "System Binary Proxy Execution",
    "T1548":     "Abuse Elevation Control Mechanism",
}

# ── Built-in tactic name mapping ──────────────────────────────────────────────

TACTIC_NAMES: dict[str, str] = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0011": "Command and Control",
    "TA0040": "Impact",
}


def collect_mitre_data(
    client: "TrendVisionOneClient",
    start_time: datetime,
    end_time: datetime,
) -> dict:
    """
    Collect MITRE ATT&CK technique and tactic data from alerts and OAT detections.

    Returns a dict with:
        technique_counts, tactic_counts, technique_to_tactics,
        top_techniques, coverage_by_tactic
    """
    start_str = start_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    end_str = end_time.strftime("%Y-%m-%dT%H:%M:%SZ")

    technique_counts: dict[str, int] = defaultdict(int)
    tactic_counts: dict[str, int] = defaultdict(int)
    technique_to_tactics: dict[str, set] = defaultdict(set)
    # severity breakdown per technique
    technique_severity: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))

    # ── Process workbench alerts ──────────────────────────────────────────────
    try:
        params = {
            "startDateTime": start_str,
            "endDateTime": end_str,
        }
        for alert in client.paginate("/v3.0/workbench/alerts", params=params):
            sev = (alert.get("severity") or "unknown").lower()
            matched_rules = alert.get("matchedRules") or []
            for rule in matched_rules:
                filters = rule.get("matchedFilters") or []
                for f in filters:
                    tids = f.get("mitreTechniqueIds") or []
                    taids = f.get("mitreTacticIds") or []
                    for tid in tids:
                        technique_counts[tid] += 1
                        technique_severity[tid][sev] += 1
                        for taid in taids:
                            technique_to_tactics[tid].add(taid)
                            tactic_counts[taid] += 1
    except Exception:
        pass

    # ── Process OAT detections ────────────────────────────────────────────────
    try:
        params = {
            "startDateTime": start_str,
            "endDateTime": end_str,
        }
        for det in client.paginate("/v3.0/oat/detections", params=params):
            filters = det.get("filters") or []
            for f in filters:
                risk = (f.get("riskLevel") or "unknown").lower()
                tids = f.get("mitreTechniqueIds") or []
                taids = f.get("mitreTacticIds") or []
                for tid in tids:
                    technique_counts[tid] += 1
                    technique_severity[tid][risk] += 1
                    for taid in taids:
                        technique_to_tactics[tid].add(taid)
                        tactic_counts[taid] += 1
    except Exception:
        pass

    # ── Build top_techniques list ─────────────────────────────────────────────
    top_techniques: list[dict] = []
    for tid, count in sorted(technique_counts.items(), key=lambda x: x[1], reverse=True)[:20]:
        tactics_for_tech = sorted(technique_to_tactics.get(tid, set()))
        first_tactic = tactics_for_tech[0] if tactics_for_tech else ""
        tactic_name = TACTIC_NAMES.get(first_tactic, first_tactic)
        top_techniques.append({
            "id": tid,
            "name": TECHNIQUE_NAMES.get(tid, tid),
            "tactic": tactic_name,
            "tactic_id": first_tactic,
            "count": count,
            "severity_breakdown": dict(technique_severity[tid]),
        })

    # ── Build coverage_by_tactic ──────────────────────────────────────────────
    coverage_by_tactic: dict[str, dict] = {}
    for taid, tname in TACTIC_NAMES.items():
        techniques_in_tactic = [
            tid for tid, tacset in technique_to_tactics.items()
            if taid in tacset
        ]
        total_dets = sum(technique_counts.get(tid, 0) for tid in techniques_in_tactic)
        coverage_by_tactic[taid] = {
            "name": tname,
            "technique_count": len(techniques_in_tactic),
            "total_detections": total_dets,
        }

    # Convert sets to lists for JSON serialisability
    technique_to_tactics_serialisable = {
        k: sorted(v) for k, v in technique_to_tactics.items()
    }

    return {
        "technique_counts": dict(technique_counts),
        "tactic_counts": dict(tactic_counts),
        "technique_to_tactics": technique_to_tactics_serialisable,
        "top_techniques": top_techniques,
        "coverage_by_tactic": coverage_by_tactic,
    }
