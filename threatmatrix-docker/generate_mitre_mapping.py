"""
generate_mitre_mapping.py
=========================
Build tool — generates app/threatmatrix_mitre_nist_mapping.py from the
official MITRE ATT&CK STIX bundle. Run from project root.
"""
from __future__ import annotations

import os
import urllib.request
from mitreattack.stix20 import MitreAttackData

# ============================================================================
#  SEED DATA — class -> ATT&CK IDs to resolve
#  Order in `techniques` matters: index 0 is the primary/lead technique.
# ============================================================================
SEEDS = {

    # ── Phase 2 tiers ───────────────────────────────────────────────────────
    "Reconnaissance": {
        "techniques":  ["T1595.001", "T1595", "T1046"],
        "tactics":     ["TA0043", "TA0007"],
        "mitigations": ["M1031", "M1030", "M1042"],
        "primary_pairing": {
            "tactic_id":    "TA0043",
            "technique_id": "T1595.001",
            "rationale": (
                "External Nmap-style IP-block scanning before any foothold. "
                "This is the WEB-IDS23 portscan dataset's default scenario."
            ),
        },
        "secondary_pairing": {
            "tactic_id":    "TA0007",
            "technique_id": "T1046",
            "rationale": (
                "Applies when the scanner is already on the internal network "
                "(post-foothold service enumeration)."
            ),
        },
        "training_source": "web-ids23_portscan.csv (Nmap -sS)",
    },

    "Credential_Abuse": {
        "techniques":  ["T1110", "T1110.001", "T1110.003"],
        "tactics":     ["TA0006"],
        "mitigations": ["M1036", "M1032", "M1027", "M1030"],
        "training_source": (
            "web-ids23_bruteforce_http.csv, "
            "web-ids23_bruteforce_https.csv (Hydra)"
        ),
    },

    "Active_Exploitation": {
        "techniques":  ["T1190"],
        "tactics":     ["TA0001"],
        "mitigations": ["M1048", "M1050", "M1051", "M1016"],
        "training_source": (
            "web-ids23_sql_injection_http.csv, "
            "web-ids23_sql_injection_https.csv (sqlmap). "
            "RevShell/SSRF/XSS withheld for Phase 3 OSR evaluation."
        ),
    },

    "UNCERTAIN": {
        "techniques": [], "tactics": [], "mitigations": [],
        "training_source": "Phase 3 RF + Open-Set Recognition",
    },

    # ── Phase 3 known classes (model emits these directly) ──────────────────
    "Benign": {
        "techniques": [], "tactics": [], "mitigations": [],
        "training_source": "web-ids23_benign.csv",
        "notes": (
            "Negative-baseline class — anchors the OSR threshold and "
            "serves as the reference distribution for benign FPR."
        ),
    },

    "Portscan": {
        "techniques":  ["T1595.001", "T1595", "T1046"],
        "tactics":     ["TA0043", "TA0007"],
        "mitigations": ["M1031", "M1030"],
        "primary_pairing":   {"tactic_id": "TA0043", "technique_id": "T1595.001"},
        "secondary_pairing": {"tactic_id": "TA0007", "technique_id": "T1046"},
        "training_source": "web-ids23_portscan.csv (Nmap -sS)",
        "phase_2_tier":    "Reconnaissance",
    },

    "BruteForce_HTTP": {
        "techniques":  ["T1110", "T1110.001", "T1110.003"],
        "tactics":     ["TA0006"],
        "mitigations": ["M1036", "M1032", "M1027"],
        "training_source": "web-ids23_bruteforce_http.csv (Hydra over HTTP)",
        "phase_2_tier":    "Credential_Abuse",
        "protocol":        "HTTP",
    },

    "BruteForce_HTTPS": {
        "techniques":  ["T1110", "T1110.001", "T1110.003"],
        "tactics":     ["TA0006"],
        "mitigations": ["M1036", "M1032", "M1027"],
        "training_source": "web-ids23_bruteforce_https.csv (Hydra over TLS)",
        "phase_2_tier":    "Credential_Abuse",
        "protocol":        "HTTPS",
    },

    "SQLi_HTTP": {
        "techniques":  ["T1190"],
        "tactics":     ["TA0001"],
        "mitigations": ["M1048", "M1050"],
        "training_source": "web-ids23_sql_injection_http.csv (sqlmap over HTTP)",
        "phase_2_tier":    "Active_Exploitation",
        "protocol":        "HTTP",
        "owasp": "A03:2021 — Injection — https://owasp.org/Top10/A03_2021-Injection/",
    },

    "SQLi_HTTPS": {
        "techniques":  ["T1190"],
        "tactics":     ["TA0001"],
        "mitigations": ["M1048", "M1050"],
        "training_source": "web-ids23_sql_injection_https.csv (sqlmap over TLS)",
        "phase_2_tier":    "Active_Exploitation",
        "protocol":        "HTTPS",
        "owasp": "A03:2021 — Injection — https://owasp.org/Top10/A03_2021-Injection/",
    },

    "UNKNOWN": {
        "techniques": [], "tactics": [], "mitigations": [],
        "training_source": "Out-of-distribution (OSR-rejected by max-softmax or Mahalanobis)",
        "notes": (
            "OSR methods: (1) Maximum Softmax Probability — confidence-based "
            "baseline; (2) Mahalanobis distance in RF leaf-embedding space — "
            "representation-distance method. Both calibrated on the 5th "
            "percentile of correctly-classified known-class scores."
        ),
    },

    # ── Phase 3 held-out novel classes (NOT direct model outputs) ────────────
    "RevShell": {
        "techniques":  ["T1059.004"],
        "tactics":     ["TA0002"],
        "mitigations": ["M1038", "M1026"],
        "training_source": (
            "web-ids23_revshell_http.csv, "
            "web-ids23_revshell_https.csv (Selenium + netcat via SSTI) — HELD OUT"
        ),
        "phase_2_tier":     "Active_Exploitation",
        "novel_in_phase_3": True,
        "dataset_note": (
            "Per the WEB-IDS23 technical report, revshell is inherently "
            "difficult to detect from a single flow — the exploit payload "
            "travels inside an encrypted HTTPS body. Proper detection requires "
            "inspecting the resulting outbound shell connection (second flow). "
            "Expected Phase 3 OSR detection rate: 55-80%."
        ),
    },

    "XSS": {
        "techniques":  ["T1059.007"],
        "tactics":     ["TA0002"],
        "mitigations": ["M1038", "M1048"],
        "training_source": (
            "web-ids23_xss_http.csv, "
            "web-ids23_xss_https.csv (Selenium via OWASP Juice Shop) — HELD OUT"
        ),
        "phase_2_tier":     "Active_Exploitation",
        "novel_in_phase_3": True,
        "owasp": "A03:2021 — Injection (XSS) — https://owasp.org/Top10/A03_2021-Injection/",
        "dataset_note": (
            "XSS flows resemble normal HTTPS browsing at the flow level. "
            "OSR detection is expected to be lower than RevShell because "
            "XSS payloads are embedded in standard web request patterns."
        ),
    },

    "SSRF": {
        "techniques":  ["T1190", "T1552.005"],
        "tactics":     ["TA0001", "TA0006"],
        "mitigations": ["M1048", "M1037", "M1041"],
        "training_source": (
            "web-ids23_ssrf_http.csv, "
            "web-ids23_ssrf_https.csv (Selenium targeting 5 external hosts) — HELD OUT"
        ),
        "phase_2_tier":     "Active_Exploitation",
        "novel_in_phase_3": True,
        "owasp": (
            "A10:2021 — Server-Side Request Forgery — "
            "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_(SSRF)/"
        ),
        "dataset_note": (
            "Per the WEB-IDS23 technical report, SSRF is only detectable by "
            "inspecting the resulting outbound flow initiated by the victim "
            "server. Single-flow inspection cannot distinguish SSRF from a "
            "legitimate web request."
        ),
    },

    "SSH_Login_Success": {
        "techniques":  ["T1078", "T1021.004"],
        "tactics":     ["TA0001", "TA0008"],
        "mitigations": ["M1032", "M1027", "M1018", "M1026"],
        "training_source": (
            "web-ids23_ssh_login_successful.csv "
            "(Metasploit ssh_login, authenticated session) — HELD OUT"
        ),
        "phase_2_tier":     "Credential_Abuse",
        "novel_in_phase_3": True,
        "honest_caveat": (
            "Flow-level features cannot capture 'wrong identity logged in'. "
            "A successful SSH login looks identical to a benign session at "
            "the flow level. Expected Phase 3 OSR detection rate: 10-30%."
        ),
    },
}


# ===============================================================================
#  NIST SP 800-61 Rev. 2 mapping overlay — class -> category, severity, response
# ===============================================================================
# Reusable patterns: sub-classes share their parent tier's NIST values
_RECON = {
    "category": "Reconnaissance",
    "severity": "Low",
    "response": "Monitor and log; correlate with subsequent activity.",
}
_CRED = {
    "category": "Unauthorized Access",
    "severity": "Medium",
    "response": "Lock account, force password reset, alert SOC.",
}
_EXPLOIT = {
    "category": "Malicious Code",
    "severity": "High",
    "response": "Isolate host, capture forensics, IR team activation.",
}

NIST_OVERLAY = {
    # Phase 2 tiers
    "Reconnaissance":      _RECON,
    "Credential_Abuse":    _CRED,
    "Active_Exploitation": _EXPLOIT,
    "UNCERTAIN": {
        "category": "Suspicious Activity (pending)",
        "severity": "Medium",
        "response": "Defer to Phase 3 RF+OSR; if UNKNOWN, escalate for analyst review.",
    },

    # Phase 3 known
    "Benign": {
        "category": "Normal",
        "severity": "None",
        "response": "No action; reference baseline for drift monitoring.",
    },
    "Portscan":         _RECON,
    "BruteForce_HTTP":  _CRED,
    "BruteForce_HTTPS": _CRED,
    "SQLi_HTTP":        _EXPLOIT,
    "SQLi_HTTPS":       _EXPLOIT,
    "UNKNOWN": {
        "category": "Unknown",
        "severity": "Critical",
        "response": "Novel/unseen attack pattern — escalate immediately for analyst review.",
    },

    # Phase 3 held-out novel
    "RevShell": {
        "category": "Malicious Code",
        "severity": "Critical",
        "response": "Terminate session, preserve memory forensics, IR escalation.",
    },
    "XSS": {
        "category": "Malicious Code",
        "severity": "High",
        "response": "Block origin IP, audit injected payloads, notify app team.",
    },
    "SSRF": {
        "category": "Malicious Code",
        "severity": "High",
        "response": (
            "Isolate proxy/web service, audit outbound traffic to internal "
            "metadata endpoints, rotate any cloud credentials reachable from "
            "the affected host."
        ),
    },
    "SSH_Login_Success": {
        "category": "Unauthorized Access",
        "severity": "High",
        "response": (
            "Verify session against auth logs and known-good user behaviour "
            "baselines. Rotate credentials if anomalous."
        ),
    },
}


# ============================================================================
#  ATT&CK RESOLVERS — turn an ID string into {id, name, url}
#  Returns None and warns (does not crash) if an ID is missing from the bundle.
# ============================================================================
ATTACK_BASE_URL = "https://attack.mitre.org"

# Track missing IDs so we warn once per build, not per call
_warned: set[str] = set()


def _warn_once(key: str, msg: str) -> None:
    if key not in _warned:
        print(f"  [WARN] {msg}")
        _warned.add(key)


def technique_url(tid: str) -> str:
    # Sub-techniques: T1595.001 -> .../techniques/T1595/001/
    if "." in tid:
        parent, sub = tid.split(".", 1)
        return f"{ATTACK_BASE_URL}/techniques/{parent}/{sub}/"
    return f"{ATTACK_BASE_URL}/techniques/{tid}/"


def tactic_url(tid: str) -> str:
    return f"{ATTACK_BASE_URL}/tactics/{tid}/"


def mitigation_url(mid: str) -> str:
    return f"{ATTACK_BASE_URL}/mitigations/{mid}/"


def resolve_technique(attack: MitreAttackData, tid: str) -> dict | None:
    obj = attack.get_object_by_attack_id(tid, "attack-pattern")
    if obj is None:
        _warn_once(tid, f"Technique {tid} not found in ATT&CK bundle")
        return None
    return {"id": tid, "name": obj.name, "url": technique_url(tid)}


def resolve_tactic(attack: MitreAttackData, tid: str) -> dict | None:
    obj = attack.get_object_by_attack_id(tid, "x-mitre-tactic")
    if obj is None:
        _warn_once(tid, f"Tactic {tid} not found in ATT&CK bundle")
        return None
    return {"id": tid, "name": obj.name, "url": tactic_url(tid)}


def resolve_mitigation(attack: MitreAttackData, mid: str) -> dict | None:
    obj = attack.get_object_by_attack_id(mid, "course-of-action")
    if obj is None:
        _warn_once(mid, f"Mitigation {mid} not found in ATT&CK bundle")
        return None
    return {"id": mid, "name": obj.name, "url": mitigation_url(mid)}


# ============================================================================
#  ENTRY ASSEMBLY — combine resolved ATT&CK data with NIST overlay
# ============================================================================

def fmt_id_name(d: dict | None) -> str | None:
    # {id: 'T1190', name: 'Exploit Public-Facing Application'} -> "T1190 (Exploit ...)"
    if d is None:
        return None
    return f"{d['id']} ({d['name']})"


def fmt_mitigation(d: dict | None) -> str | None:
    # "M1048 (Application Isolation and Sandboxing) — https://..."
    if d is None:
        return None
    return f"{d['id']} ({d['name']}) — {d['url']}"


def build_entry(attack: MitreAttackData, cls: str, seed: dict, nist: dict) -> dict:
    """Assemble one class's final dict in the canonical key order."""
    # Resolve and drop any IDs the bundle doesn't know about
    techs = [r for r in (resolve_technique(attack, t)  for t in seed["techniques"])  if r]
    tacs  = [r for r in (resolve_tactic(attack, t)     for t in seed["tactics"])     if r]
    mits  = [r for r in (resolve_mitigation(attack, m) for m in seed["mitigations"]) if r]

    # mitre_urls = tactic URLs first, then technique URLs (matches existing file)
    urls = [t["url"] for t in tacs] + [t["url"] for t in techs]

    entry: dict = {
        "mitre_tactics":    [fmt_id_name(t) for t in tacs],
        "mitre_techniques": [fmt_id_name(t) for t in techs],
        "mitre_urls":       urls,
    }

    # Pairings (only Reconnaissance and Portscan)
    for pair_key in ("primary_pairing", "secondary_pairing"):
        if pair_key in seed:
            p = seed[pair_key]
            pairing = {
                "tactic":    fmt_id_name(resolve_tactic(attack, p["tactic_id"])),
                "technique": fmt_id_name(resolve_technique(attack, p["technique_id"])),
            }
            if "rationale" in p:
                pairing["rationale"] = p["rationale"]
            entry[pair_key] = pairing

    entry["training_source"]       = seed.get("training_source", "")
    entry["nist_sp80061_category"] = nist["category"]
    entry["nist_severity"]         = nist["severity"]
    entry["nist_response"]         = nist["response"]
    entry["mitre_mitigations"]     = [fmt_mitigation(m) for m in mits]

    # Optional extras in canonical order (matches existing file's per-class layout)
    for key in ("phase_2_tier", "novel_in_phase_3", "protocol",
                "owasp", "dataset_note", "honest_caveat", "notes"):
        if key in seed:
            entry[key] = seed[key]

    return entry


# ============================================================================
#  Sanity check and build all entries
# ============================================================================
if __name__ == "__main__":
    import json

    BUNDLE_URL = (
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
        "master/enterprise-attack/enterprise-attack.json"
    )
    BUNDLE = "enterprise-attack.json"
    if not os.path.exists(BUNDLE):
        print("Downloading ATT&CK bundle...")
        urllib.request.urlretrieve(BUNDLE_URL, BUNDLE)

    attack = MitreAttackData(BUNDLE)
    assert set(SEEDS) == set(NIST_OVERLAY)

    entries = {
        cls: build_entry(attack, cls, seed, NIST_OVERLAY[cls])
        for cls, seed in SEEDS.items()
    }

    # check  again three representative entries
    for cls in ("Reconnaissance", "Benign", "RevShell"):
        print(f"\n── {cls} ──")
        print(json.dumps(entries[cls], indent=2, ensure_ascii=False))

    print(f"\nOKAY — built {len(entries)} entries.")