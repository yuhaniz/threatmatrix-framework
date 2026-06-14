"""
threatmatrix_mitre_nist_mapping.py
===================================
Standalone MITRE ATT&CK + NIST SP 800-61 Rev. 2 reference mapping.

This file is PURE METADATA. It does not affect training, inference, or any
model artifact in Phase 1 (binary), Phase 2 (multiclass severity) or Phase 3
(fine-grained RF + OSR). It is intended solely as a reference for the dashboard and final report, to 
ensure all MITRE/NIST mappings are factually accurate and consistently applied across the project.

────────────────────────────────────────────────────────────────────────────
  TWO-LAYER MAPPING
────────────────────────────────────────────────────────────────────────────
  PHASE_2_TIER_MAPPING       — severity tiers from threatmatrix_multiclass.py
                               {Reconnaissance, Credential_Abuse,
                                Active_Exploitation, UNCERTAIN}

  PHASE_3_CLASS_MAPPING      — fine-grained classes from threatmatrix_anomaly.py
                               (RF classifier + Open-Set Recognition)
                               Known classes:
                                 {Benign, Portscan,
                                  BruteForce_HTTP, BruteForce_HTTPS,
                                  SQLi_HTTP,        SQLi_HTTPS}
                               OSR rejection label:
                                 {UNKNOWN}
                               Held-out novel labels (used for OSR evaluation
                               only — never predicted directly by the model,
                               but listed so the dashboard can cross-reference
                               flagged-UNKNOWN samples against ground truth):
                                 {RevShell, XSS, SSRF, SSH_Login_Success}

────────────────────────────────────────────────────────────────────────────
  VERIFIED SOURCES — OFFICIAL ONLY
  All URLs checked against attack.mitre.org and official NIST/OWASP sites.
────────────────────────────────────────────────────────────────────────────

  MITRE ATT&CK Enterprise — Tactics
    TA0001  Initial Access         https://attack.mitre.org/tactics/TA0001/
    TA0002  Execution              https://attack.mitre.org/tactics/TA0002/
    TA0006  Credential Access      https://attack.mitre.org/tactics/TA0006/
    TA0007  Discovery              https://attack.mitre.org/tactics/TA0007/
    TA0008  Lateral Movement       https://attack.mitre.org/tactics/TA0008/
    TA0043  Reconnaissance         https://attack.mitre.org/tactics/TA0043/

  MITRE ATT&CK Enterprise — Techniques
    T1046           Network Service Discovery
                    https://attack.mitre.org/techniques/T1046/
    T1059.004       Command and Scripting Interpreter: Unix Shell
                    https://attack.mitre.org/techniques/T1059/004/
    T1059.007       Command and Scripting Interpreter: JavaScript
                    https://attack.mitre.org/techniques/T1059/007/
    T1078           Valid Accounts
                    https://attack.mitre.org/techniques/T1078/
    T1021.004       Remote Services: SSH
                    https://attack.mitre.org/techniques/T1021/004/
    T1110           Brute Force
                    https://attack.mitre.org/techniques/T1110/
    T1110.001       Brute Force: Password Guessing
                    https://attack.mitre.org/techniques/T1110/001/
    T1110.003       Brute Force: Password Spraying
                    https://attack.mitre.org/techniques/T1110/003/
    T1190           Exploit Public-Facing Application
                    https://attack.mitre.org/techniques/T1190/
    T1552.005       Unsecured Credentials: Cloud Instance Metadata API
                    https://attack.mitre.org/techniques/T1552/005/
    T1595           Active Scanning
                    https://attack.mitre.org/techniques/T1595/
    T1595.001       Active Scanning: Scanning IP Blocks
                    https://attack.mitre.org/techniques/T1595/001/

  MITRE ATT&CK Enterprise — Mitigations
    M1016   Vulnerability Scanning        https://attack.mitre.org/mitigations/M1016/
    M1018   User Account Management       https://attack.mitre.org/mitigations/M1018/
    M1026   Privileged Account Management https://attack.mitre.org/mitigations/M1026/
    M1027   Password Policies             https://attack.mitre.org/mitigations/M1027/
    M1030   Network Segmentation          https://attack.mitre.org/mitigations/M1030/
    M1031   Network Intrusion Prevention  https://attack.mitre.org/mitigations/M1031/
    M1032   Multi-factor Authentication   https://attack.mitre.org/mitigations/M1032/
    M1036   Account Use Policies          https://attack.mitre.org/mitigations/M1036/
    M1037   Filter Network Traffic        https://attack.mitre.org/mitigations/M1037/
    M1038   Execution Prevention          https://attack.mitre.org/mitigations/M1038/
    M1041   Encrypt Sensitive Information https://attack.mitre.org/mitigations/M1041/
    M1042   Disable or Remove Feature     https://attack.mitre.org/mitigations/M1042/
    M1048   Application Isolation         https://attack.mitre.org/mitigations/M1048/
    M1050   Exploit Protection            https://attack.mitre.org/mitigations/M1050/
    M1051   Update Software               https://attack.mitre.org/mitigations/M1051/

  NIST
    NIST SP 800-61 Rev. 2 — Computer Security Incident Handling Guide
    https://csrc.nist.gov/pubs/sp/800/61/r2/final

  OWASP
    OWASP Top 10 (2021)     https://owasp.org/Top10/
    A03:2021 — Injection    https://owasp.org/Top10/A03_2021-Injection/
    A10:2021 — SSRF         https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_(SSRF)/

"""

from __future__ import annotations


# ============================================================================
#  PHASE 2 — SEVERITY-TIER MAPPING
#  Mirrors CLASS_NAMES in threatmatrix_multiclass.py
# ============================================================================
PHASE_2_TIER_MAPPING: dict = {

    "Reconnaissance": {
        "mitre_tactics": [
            "TA0043 (Reconnaissance)",
            "TA0007 (Discovery)",
        ],
        "mitre_techniques": [
            "T1595 (Active Scanning)",
            "T1595.001 (Active Scanning: Scanning IP Blocks)",
            "T1046 (Network Service Discovery)",
        ],
        "mitre_urls": [
            "https://attack.mitre.org/tactics/TA0043/",
            "https://attack.mitre.org/tactics/TA0007/",
            "https://attack.mitre.org/techniques/T1595/",
            "https://attack.mitre.org/techniques/T1595/001/",
            "https://attack.mitre.org/techniques/T1046/",
        ],
        "training_source": "web-ids23_portscan.csv (Nmap -sS)",
        "nist_sp80061_category": "Reconnaissance",
        "nist_severity":         "Low",
        "nist_response":         "Monitor and log; correlate with subsequent activity.",
        "mitre_mitigations": [
            "M1031 (Network Intrusion Prevention) — https://attack.mitre.org/mitigations/M1031/",
            "M1030 (Network Segmentation) — https://attack.mitre.org/mitigations/M1030/",
            "M1042 (Disable or Remove Feature/Program) — https://attack.mitre.org/mitigations/M1042/",
        ],
    },

    "Credential_Abuse": {
        "mitre_tactics": [
            "TA0006 (Credential Access)",
        ],
        "mitre_techniques": [
            "T1110 (Brute Force)",
            "T1110.001 (Brute Force: Password Guessing)",
            "T1110.003 (Brute Force: Password Spraying)",
        ],
        "mitre_urls": [
            "https://attack.mitre.org/tactics/TA0006/",
            "https://attack.mitre.org/techniques/T1110/",
            "https://attack.mitre.org/techniques/T1110/001/",
            "https://attack.mitre.org/techniques/T1110/003/",
        ],
        "training_source": (
            "web-ids23_bruteforce_http.csv, "
            "web-ids23_bruteforce_https.csv (Hydra)"
        ),
        "nist_sp80061_category": "Unauthorized Access",
        "nist_severity":         "Medium",
        "nist_response":         "Lock account, force password reset, alert SOC.",
        "mitre_mitigations": [
            "M1036 (Account Use Policies) — https://attack.mitre.org/mitigations/M1036/",
            "M1032 (Multi-factor Authentication) — https://attack.mitre.org/mitigations/M1032/",
            "M1027 (Password Policies) — https://attack.mitre.org/mitigations/M1027/",
            "M1030 (Network Segmentation) — https://attack.mitre.org/mitigations/M1030/",
        ],
    },

    "Active_Exploitation": {
        "mitre_tactics": [
            "TA0001 (Initial Access)",
        ],
        "mitre_techniques": [
            "T1190 (Exploit Public-Facing Application)",
        ],
        "mitre_urls": [
            "https://attack.mitre.org/tactics/TA0001/",
            "https://attack.mitre.org/techniques/T1190/",
        ],
        "training_source": (
            "web-ids23_sql_injection_http.csv, "
            "web-ids23_sql_injection_https.csv (sqlmap). "
            "RevShell/SSRF/XSS withheld for Phase 3 OSR evaluation."
        ),
        "nist_sp80061_category": "Malicious Code",
        "nist_severity":         "High",
        "nist_response":         "Isolate host, capture forensics, IR team activation.",
        "mitre_mitigations": [
            "M1048 (Application Isolation and Sandboxing) — https://attack.mitre.org/mitigations/M1048/",
            "M1050 (Exploit Protection) — https://attack.mitre.org/mitigations/M1050/",
            "M1051 (Update Software) — https://attack.mitre.org/mitigations/M1051/",
            "M1016 (Vulnerability Scanning) — https://attack.mitre.org/mitigations/M1016/",
        ],
    },

    "UNCERTAIN": {
        "mitre_tactics":    ["Pending — routed to Phase 3 RF + OSR for fine-grained classification"],
        "mitre_techniques": [],
        "mitre_urls":       [],
        "training_source":  "Phase 3 RF + Open-Set Recognition",
        "nist_sp80061_category": "Suspicious Activity (pending)",
        "nist_severity":         "Medium",
        "nist_response": (
            "Defer to Phase 3 fine-grained RF classifier; if OSR rejects "
            "as UNKNOWN, escalate for analyst review."
        ),
        "mitre_mitigations": ["Quarantine flow metadata; flag for analyst review."],
    },
}


# ============================================================================
#  PHASE 3 — FINE-GRAINED CLASS MAPPING
#  Mirrors CLASS_FILES + PHASE3_NOVEL_FILES in threatmatrix_anomaly.py.
# ============================================================================
PHASE_3_CLASS_MAPPING: dict = {

    # ── Known classes (model emits these directly) ──────────────────────────

    "Benign": {
        "mitre_tactics":         [],
        "mitre_techniques":      [],
        "mitre_urls":            [],
        "training_source":       "web-ids23_benign.csv",
        "nist_sp80061_category": "Normal",
        "nist_severity":         "None",
        "nist_response":         "No action; reference baseline for drift monitoring.",
        "mitre_mitigations":     [],
        "notes": (
            "Negative-baseline class — anchors the OSR threshold and "
            "serves as the reference distribution for benign FPR."
        ),
    },

    "Portscan": {
        "mitre_tactics": [
            "TA0043 (Reconnaissance)",
            "TA0007 (Discovery)",
        ],
        "mitre_techniques": [
            "T1595 (Active Scanning)",
            "T1595.001 (Active Scanning: Scanning IP Blocks)",
            "T1046 (Network Service Discovery)",
        ],
        "mitre_urls": [
            "https://attack.mitre.org/tactics/TA0043/",
            "https://attack.mitre.org/tactics/TA0007/",
            "https://attack.mitre.org/techniques/T1595/",
            "https://attack.mitre.org/techniques/T1595/001/",
            "https://attack.mitre.org/techniques/T1046/",
        ],
        "training_source":       "web-ids23_portscan.csv (Nmap -sS)",
        "nist_sp80061_category": "Reconnaissance",
        "nist_severity":         "Low",
        "nist_response":         "Monitor and log; correlate with subsequent activity.",
        "mitre_mitigations": [
            "M1031 (Network Intrusion Prevention) — https://attack.mitre.org/mitigations/M1031/",
            "M1030 (Network Segmentation) — https://attack.mitre.org/mitigations/M1030/",
        ],
        "phase_2_tier": "Reconnaissance",
    },

    "BruteForce_HTTP": {
        "mitre_tactics":    ["TA0006 (Credential Access)"],
        "mitre_techniques": [
            "T1110 (Brute Force)",
            "T1110.001 (Brute Force: Password Guessing)",
            "T1110.003 (Brute Force: Password Spraying)",
        ],
        "mitre_urls": [
            "https://attack.mitre.org/tactics/TA0006/",
            "https://attack.mitre.org/techniques/T1110/",
            "https://attack.mitre.org/techniques/T1110/001/",
            "https://attack.mitre.org/techniques/T1110/003/",
        ],
        "training_source":       "web-ids23_bruteforce_http.csv (Hydra over HTTP)",
        "nist_sp80061_category": "Unauthorized Access",
        "nist_severity":         "Medium",
        "nist_response":         "Lock account, force password reset, alert SOC.",
        "mitre_mitigations": [
            "M1036 (Account Use Policies) — https://attack.mitre.org/mitigations/M1036/",
            "M1032 (Multi-factor Authentication) — https://attack.mitre.org/mitigations/M1032/",
            "M1027 (Password Policies) — https://attack.mitre.org/mitigations/M1027/",
        ],
        "phase_2_tier": "Credential_Abuse",
        "protocol":     "HTTP",
    },

    "BruteForce_HTTPS": {
        "mitre_tactics":    ["TA0006 (Credential Access)"],
        "mitre_techniques": [
            "T1110 (Brute Force)",
            "T1110.001 (Brute Force: Password Guessing)",
            "T1110.003 (Brute Force: Password Spraying)",
        ],
        "mitre_urls": [
            "https://attack.mitre.org/tactics/TA0006/",
            "https://attack.mitre.org/techniques/T1110/",
            "https://attack.mitre.org/techniques/T1110/001/",
            "https://attack.mitre.org/techniques/T1110/003/",
        ],
        "training_source":       "web-ids23_bruteforce_https.csv (Hydra over TLS)",
        "nist_sp80061_category": "Unauthorized Access",
        "nist_severity":         "Medium",
        "nist_response":         "Lock account, force password reset, alert SOC.",
        "mitre_mitigations": [
            "M1036 (Account Use Policies) — https://attack.mitre.org/mitigations/M1036/",
            "M1032 (Multi-factor Authentication) — https://attack.mitre.org/mitigations/M1032/",
            "M1027 (Password Policies) — https://attack.mitre.org/mitigations/M1027/",
        ],
        "phase_2_tier": "Credential_Abuse",
        "protocol":     "HTTPS",
    },

    "SQLi_HTTP": {
        "mitre_tactics":    ["TA0001 (Initial Access)"],
        "mitre_techniques": ["T1190 (Exploit Public-Facing Application)"],
        "mitre_urls": [
            "https://attack.mitre.org/tactics/TA0001/",
            "https://attack.mitre.org/techniques/T1190/",
        ],
        "training_source":       "web-ids23_sql_injection_http.csv (sqlmap over HTTP)",
        "nist_sp80061_category": "Malicious Code",
        "nist_severity":         "High",
        "nist_response":         "Isolate host, capture forensics, IR team activation.",
        "mitre_mitigations": [
            "M1048 (Application Isolation and Sandboxing) — https://attack.mitre.org/mitigations/M1048/",
            "M1050 (Exploit Protection) — https://attack.mitre.org/mitigations/M1050/",
        ],
        "phase_2_tier": "Active_Exploitation",
        "protocol":     "HTTP",
        "owasp": "A03:2021 — Injection — https://owasp.org/Top10/A03_2021-Injection/",
    },

    "SQLi_HTTPS": {
        "mitre_tactics":    ["TA0001 (Initial Access)"],
        "mitre_techniques": ["T1190 (Exploit Public-Facing Application)"],
        "mitre_urls": [
            "https://attack.mitre.org/tactics/TA0001/",
            "https://attack.mitre.org/techniques/T1190/",
        ],
        "training_source":       "web-ids23_sql_injection_https.csv (sqlmap over TLS)",
        "nist_sp80061_category": "Malicious Code",
        "nist_severity":         "High",
        "nist_response":         "Isolate host, capture forensics, IR team activation.",
        "mitre_mitigations": [
            "M1048 (Application Isolation and Sandboxing) — https://attack.mitre.org/mitigations/M1048/",
            "M1050 (Exploit Protection) — https://attack.mitre.org/mitigations/M1050/",
        ],
        "phase_2_tier": "Active_Exploitation",
        "protocol":     "HTTPS",
        "owasp": "A03:2021 — Injection — https://owasp.org/Top10/A03_2021-Injection/",
    },

    # ── OSR rejection label ──────────────────────────────────────────────────
    "UNKNOWN": {
        "mitre_tactics":    ["Pending — tactic determined by analyst after triage"],
        "mitre_techniques": [],
        "mitre_urls":       [],
        "training_source":  "Out-of-distribution (OSR-rejected by max-softmax or Mahalanobis)",
        "nist_sp80061_category": "Suspicious Activity (novel/unclassified)",
        "nist_severity":         "Medium-High",
        "nist_response": (
            "Treat as suspected novel attack. Capture full PCAP, escalate to "
            "analyst, and cross-reference against held-out novel-class ground "
            "truth (RevShell / SSRF / XSS / SSH_Login_Success) where available."
        ),
        "mitre_mitigations": [
            "Quarantine flow metadata",
            "Capture PCAP for forensic analysis",
            "Manual triage by SOC analyst",
        ],
        "notes": (
            "OSR methods: (1) Maximum Softmax Probability — confidence-based "
            "baseline; (2) Mahalanobis distance in RF leaf-embedding space — "
            "representation-distance method. Both calibrated on the 5th "
            "percentile of correctly-classified known-class scores."
        ),
    },

    # ── Held-out novel labels (ground-truth references, NOT model outputs) ──

    "RevShell": {
        "mitre_tactics":    ["TA0002 (Execution)"],
        "mitre_techniques": [
            "T1059.004 (Command and Scripting Interpreter: Unix Shell)",
        ],
        "mitre_urls": [
            "https://attack.mitre.org/tactics/TA0002/",
            "https://attack.mitre.org/techniques/T1059/004/",
        ],
        "training_source": (
            "web-ids23_revshell_http.csv, "
            "web-ids23_revshell_https.csv (Selenium + netcat via SSTI) — HELD OUT"
        ),
        "nist_sp80061_category": "Malicious Code",
        "nist_severity":         "High",
        "nist_response":         "Isolate host, capture forensics, IR team activation.",
        "mitre_mitigations": [
            "M1031 (Network Intrusion Prevention) — https://attack.mitre.org/mitigations/M1031/",
            "M1038 (Execution Prevention) — https://attack.mitre.org/mitigations/M1038/",
            "M1042 (Disable or Remove Feature/Program) — https://attack.mitre.org/mitigations/M1042/",
        ],
        "phase_2_tier":     "Active_Exploitation",
        "novel_in_phase_3": True,
        "dataset_note": (
            "Per the WEB-IDS23 technical report, revshell is inherently "
            "difficult to detect from a single flow — the exploit payload "
            "travels inside an encrypted HTTPS body. Proper detection requires "
            "inspecting the resulting outbound shell connection (second flow). "
            "Expected Phase 3 OSR detection rate: 55–80%."
        ),
    },

    "XSS": {
        "mitre_tactics":    ["TA0002 (Execution)"],
        "mitre_techniques": [
            "T1059.007 (Command and Scripting Interpreter: JavaScript)",
        ],
        "mitre_urls": [
            "https://attack.mitre.org/tactics/TA0002/",
            "https://attack.mitre.org/techniques/T1059/007/",
        ],
        "training_source": (
            "web-ids23_xss_http.csv, "
            "web-ids23_xss_https.csv (Selenium via OWASP Juice Shop) — HELD OUT"
        ),
        "nist_sp80061_category": "Malicious Code",
        "nist_severity":         "High",
        "nist_response": (
            "Sanitize affected endpoint, force re-authentication, "
            "review session tokens for potential theft."
        ),
        "mitre_mitigations": [
            "M1048 (Application Isolation and Sandboxing) — https://attack.mitre.org/mitigations/M1048/",
            "M1050 (Exploit Protection) — https://attack.mitre.org/mitigations/M1050/",
        ],
        "phase_2_tier":     "Active_Exploitation",
        "novel_in_phase_3": True,
        "owasp": (
            "A03:2021 — Injection (XSS) — "
            "https://owasp.org/Top10/A03_2021-Injection/"
        ),
        "dataset_note": (
            "XSS flows resemble normal HTTPS browsing at the flow level. "
            "OSR detection is expected to be lower than RevShell because "
            "XSS payloads are embedded in standard web request patterns."
        ),
    },

    "SSRF": {
        "mitre_tactics": [
            "TA0001 (Initial Access)",
            "TA0006 (Credential Access)",
        ],
        "mitre_techniques": [
            "T1190 (Exploit Public-Facing Application)",
            "T1552.005 (Unsecured Credentials: Cloud Instance Metadata API)",
        ],
        "mitre_urls": [
            "https://attack.mitre.org/tactics/TA0001/",
            "https://attack.mitre.org/tactics/TA0006/",
            "https://attack.mitre.org/techniques/T1190/",
            "https://attack.mitre.org/techniques/T1552/005/",
        ],
        "training_source": (
            "web-ids23_ssrf_http.csv, "
            "web-ids23_ssrf_https.csv (Selenium targeting 5 external hosts) — HELD OUT"
        ),
        "nist_sp80061_category": "Malicious Code",
        "nist_severity":         "High",
        "nist_response": (
            "Isolate proxy / web service, audit outbound traffic to internal "
            "metadata endpoints, rotate any cloud credentials reachable from "
            "the affected host."
        ),
        "mitre_mitigations": [
            "M1048 (Application Isolation and Sandboxing) — https://attack.mitre.org/mitigations/M1048/",
            "M1037 (Filter Network Traffic) — https://attack.mitre.org/mitigations/M1037/",
            "M1041 (Encrypt Sensitive Information) — https://attack.mitre.org/mitigations/M1041/",
        ],
        "phase_2_tier":     "Active_Exploitation",
        "novel_in_phase_3": True,
        "owasp": (
            "A10:2021 — Server-Side Request Forgery — "
            "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_(SSRF)/"
        ),
        "dataset_note": (
            "Per the WEB-IDS23 technical report, SSRF is only detectable "
            "by inspecting the resulting outbound flow initiated by the victim "
            "server. Single-flow inspection cannot distinguish SSRF from a "
            "legitimate web request."
        ),
    },

    "SSH_Login_Success": {
        "mitre_tactics": [
            "TA0001 (Initial Access)",
            "TA0008 (Lateral Movement)",
        ],
        "mitre_techniques": [
            "T1078 (Valid Accounts)",
            "T1021.004 (Remote Services: SSH)",
        ],
        "mitre_urls": [
            "https://attack.mitre.org/tactics/TA0001/",
            "https://attack.mitre.org/tactics/TA0008/",
            "https://attack.mitre.org/techniques/T1078/",
            "https://attack.mitre.org/techniques/T1021/004/",
        ],
        "training_source": (
            "web-ids23_ssh_login_successful.csv "
            "(Metasploit ssh_login, authenticated session) — HELD OUT"
        ),
        "nist_sp80061_category": "Unauthorized Access",
        "nist_severity":         "High",
        "nist_response": (
            "Verify session against authentication logs and known-good "
            "user behaviour baselines (impossible travel, off-hours, "
            "key-vs-password mismatch). Rotate credentials if anomalous."
        ),
        "mitre_mitigations": [
            "M1032 (Multi-factor Authentication) — https://attack.mitre.org/mitigations/M1032/",
            "M1027 (Password Policies) — https://attack.mitre.org/mitigations/M1027/",
            "M1018 (User Account Management) — https://attack.mitre.org/mitigations/M1018/",
            "M1026 (Privileged Account Management) — https://attack.mitre.org/mitigations/M1026/",
        ],
        "phase_2_tier":     "Credential_Abuse",
        "novel_in_phase_3": True,
        "honest_caveat": (
            "Flow-level features cannot capture 'wrong identity logged in'. "
            "A successful SSH login looks identical to a benign session at "
            "the flow level. Expected Phase 3 OSR detection rate: 10–30%."
        ),
    },
}


# ============================================================================
#  CONVENIENCE ACCESSORS
# ============================================================================

def enrich_phase_2(tier_label: str) -> dict:
    """Return MITRE/NIST enrichment for a Phase 2 severity tier."""
    return PHASE_2_TIER_MAPPING.get(tier_label, {})


def enrich_phase_3(class_label: str) -> dict:
    """Return MITRE/NIST enrichment for a Phase 3 fine-grained class."""
    return PHASE_3_CLASS_MAPPING.get(class_label, {})


def all_phase_2_tiers() -> list[str]:
    return list(PHASE_2_TIER_MAPPING.keys())


def all_phase_3_classes(*, include_held_out: bool = True) -> list[str]:
    """
    Args:
        include_held_out: include RevShell/XSS/SSRF/SSH_Login_Success
                          (ground-truth-only; not direct model outputs).
    """
    keys = list(PHASE_3_CLASS_MAPPING.keys())
    if not include_held_out:
        keys = [k for k in keys
                if not PHASE_3_CLASS_MAPPING[k].get("novel_in_phase_3")]
    return keys



MITRE_NIST_MAPPING = PHASE_2_TIER_MAPPING


# ============================================================================
#  CLI sanity check
# ============================================================================
if __name__ == "__main__":
    import json

    print("=" * 72)
    print(" PHASE 2 — SEVERITY-TIER MAPPING")
    print("=" * 72)
    print(json.dumps(PHASE_2_TIER_MAPPING, indent=2))

    print()
    print("=" * 72)
    print(" PHASE 3 — FINE-GRAINED CLASS MAPPING")
    print("=" * 72)
    print(json.dumps(PHASE_3_CLASS_MAPPING, indent=2))

    print()
    print(" KNOWN CLASSES (direct model outputs):", all_phase_3_classes(include_held_out=False))
    print(" ALL CLASSES (incl. held-out novel):  ", all_phase_3_classes(include_held_out=True))