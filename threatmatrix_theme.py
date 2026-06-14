from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Dict, Optional

import matplotlib.pyplot as plt


# ============================================================
#  CANONICAL PALETTE
# ============================================================

# Model identity — same across all phases.
@dataclass(frozen=True)
class _ModelPalette:
    rf:       str = "#1976D2"   # blue   — Random Forest
    xgb:      str = "#F57C00"   # orange — XGBoost
    ensemble: str = "#388E3C"   # green  — RF + XGB ensemble
    lr:       str = "#7B1FA2"   # purple — LR diagnostic baseline
    osr:      str = "#00838F"   # teal   — Phase 3 RF + OSR (Open-Set Recognition)


# Severity tier —  mapping to NIST 800-61.
@dataclass(frozen=True)
class _SeverityPalette:
    benign:              str = "#455A64"   # blue-grey
    reconnaissance:      str = "#43A047"   # green   — Low
    credential_abuse:    str = "#FB8C00"   # orange  — Medium
    active_exploitation: str = "#E53935"   # red     — High
    uncertain:           str = "#8E24AA"   # purple  — routed to Phase 3
    anomaly:             str = "#00838F"   # teal    — Phase 3 novel detection


# Status colours — used for "good/borderline/bad" visualisations.
@dataclass(frozen=True)
class _StatusPalette:
    good:     str = "#43A047"
    warn:     str = "#FB8C00"
    bad:      str = "#E53935"
    neutral:  str = "#90A4AE"
    target:   str = "#C62828"   # 90% target line


# Top-level frozen palette singletons.
MODEL    = _ModelPalette()
SEVERITY = _SeverityPalette()
STATUS   = _StatusPalette()


# Convenience aggregation — for cases  if want all three phases'
# main "winning" colour in a list (RF, XGB, Ensemble) for bar charts.
PAL = {
    "rf":       MODEL.rf,
    "xgb":      MODEL.xgb,
    "ensemble": MODEL.ensemble,
    "lr":       MODEL.lr,
    "osr":      MODEL.osr,      
    "ok":       STATUS.good,
    "warn":     STATUS.warn,
    "bad":      STATUS.bad,
    "target":   STATUS.target,
    "neutral":  STATUS.neutral,
}


# ============================================================
#  STYLE CONFIG
# ============================================================

TITLE_KWARGS = {"fontweight": "bold"}

# 90% performance target line 
TARGET_LINE_KWARGS = {
    "color":     STATUS.target,
    "linestyle": "--",
    "linewidth": 1.5,
    "label":     "90% target",
    "zorder":    5,
}

# DPI for saved figures — 150 is a reasonable balance between file size
# and viewing crispness on a 1080p projector and a Flutter dashboard.
FIG_DPI = 150


def apply_theme() -> None:
    """
    Apply standardised matplotlib rcParams. Call ONCE at the top of any
    script that produces figures. Idempotent — safe to call multiple times.

    Sets:
      - White figure background, light-grey axes background
      - Light grid by default (axes can override per-plot)
      - DejaVu Sans font (cross-platform, ships with matplotlib)
      - Reasonable default font sizes for projector/dashboard viewing
    """
    plt.rcParams.update({
        "figure.facecolor"   : "white",
        "axes.facecolor"     : "#F8F9FA",
        "axes.edgecolor"     : "#37474F",
        "axes.linewidth"     : 0.8,
        "axes.grid"          : True,
        "axes.axisbelow"     : True,
        "grid.color"         : "#CFD8DC",
        "grid.linestyle"     : ":",
        "grid.linewidth"     : 0.6,
        "grid.alpha"         : 0.6,
        "font.family"        : "DejaVu Sans",
        "font.size"          : 10,
        "axes.titlesize"     : 12,
        "axes.titleweight"   : "bold",
        "axes.labelsize"     : 11,
        "axes.labelweight"   : "normal",
        "xtick.labelsize"    : 9,
        "ytick.labelsize"    : 9,
        "legend.fontsize"    : 9,
        "legend.frameon"     : True,
        "legend.framealpha"  : 0.95,
        "legend.edgecolor"   : "#CFD8DC",
        "savefig.dpi"        : FIG_DPI,
        "savefig.bbox"       : "tight",
        "savefig.facecolor"  : "white",
    })


# ============================================================
#  HELPERS
# ============================================================

def severity_color(label: str) -> str:
    """
    Map a severity label to its canonical colour. Falls back to neutral
    grey if the label is unknown.

    >>> severity_color("Reconnaissance")
    '#43A047'
    >>> severity_color("Active_Exploitation")
    '#E53935'
    """
    table = {
        "Benign":               SEVERITY.benign,
        "benign":               SEVERITY.benign,
        "Reconnaissance":       SEVERITY.reconnaissance,
        "reconnaissance":       SEVERITY.reconnaissance,
        "Credential_Abuse":     SEVERITY.credential_abuse,
        "credential_abuse":     SEVERITY.credential_abuse,
        "Active_Exploitation":  SEVERITY.active_exploitation,
        "active_exploitation":  SEVERITY.active_exploitation,
        "UNCERTAIN":            SEVERITY.uncertain,
        "uncertain":            SEVERITY.uncertain,
        "Anomaly":              SEVERITY.anomaly,
        "anomaly":              SEVERITY.anomaly,
        "UNKNOWN":              SEVERITY.anomaly,   # Phase 3 OSR rejection label
        "unknown":              SEVERITY.anomaly,
    }
    return table.get(label, STATUS.neutral)


def model_color(name: str) -> str:
    """Map a model name to its canonical colour."""
    n = name.lower().strip()
    if "random forest" in n or n in {"rf", "randomforest"}:
        return MODEL.rf
    if "xgboost" in n or n in {"xgb", "xgboost"}:
        return MODEL.xgb
    if "ensemble" in n or "rf+xgb" in n:
        return MODEL.ensemble
    if "lr" in n or "logistic" in n or "baseline" in n:
        return MODEL.lr
    if "osr" in n or "open-set" in n or "open set" in n or "mahalanobis" in n:
        return MODEL.osr
    return STATUS.neutral


def status_color(value: float, target: float = 0.90,
                 warn: float = 0.80) -> str:
    """
    Status colour for a metric value: green if >= target, orange if
    >= warn, red otherwise. Both threshold values are in [0, 1].
    """
    if value >= target:
        return STATUS.good
    if value >= warn:
        return STATUS.warn
    return STATUS.bad


def save_fig(fig, output_dir: str, filename: str,
             tight: bool = True, verbose: bool = True) -> str:
    """
    Standardised figure save:
      - Ensures output_dir exists
      - Applies tight_layout (unless caller already did)
      - Saves at canonical DPI with white facecolor
      - Closes the figure to free memory
      - Returns the full output path

    Use this instead of plt.savefig() in every phase script.
    """
    os.makedirs(output_dir, exist_ok=True)
    if tight:
        try:
            fig.tight_layout()
        except Exception:
            # Some compositions (subplots_adjust, manual layouts)
            # raise here, ignore and trust the caller's layout.
            pass
    full_path = os.path.join(output_dir, filename)
    fig.savefig(full_path, dpi=FIG_DPI, bbox_inches="tight",
                facecolor="white")
    plt.close(fig)
    if verbose:
        print(f"[GRAPH] {filename} saved.")
    return full_path


def add_target_line(ax, value: float = 90.0,
                    label: Optional[str] = "90% target") -> None:
    """Draw the canonical horizontal target line on an axes."""
    kw = dict(TARGET_LINE_KWARGS)
    if label is None:
        kw.pop("label", None)
    else:
        kw["label"] = label
    ax.axhline(value, **kw)


def style_axes(ax, despine_top_right: bool = True) -> None:
    """Apply consistent axis styling: hide top/right spines, dotted grid."""
    if despine_top_right:
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
    ax.yaxis.grid(True, linestyle=":", alpha=0.5)
    ax.set_axisbelow(True)


# ============================================================
#  SOURCE-FILE - DISPLAY LABEL
#  Reused by every phase to keep chart labels consistent.
# ============================================================

SOURCE_FILE_DETAIL: Dict[str, str] = {
    "web-ids23_benign.csv":               "Benign\n(browser/FTP/SMTP/SSH)",
    "web-ids23_portscan.csv":             "Portscan\n(Nmap -sS)",
    "web-ids23_bruteforce_http.csv":      "HTTP BruteForce\n(Hydra)",
    "web-ids23_bruteforce_https.csv":     "HTTPS BruteForce\n(Hydra)",
    "web-ids23_sql_injection_http.csv":   "SQLi HTTP\n(sqlmap+Selenium)",
    "web-ids23_sql_injection_https.csv":  "SQLi HTTPS\n(sqlmap+Selenium)",
    # Phase 3 withheld novel classes (OSR evaluation only)
    "web-ids23_revshell_http.csv":        "RevShell HTTP\n(Selenium+netcat)",
    "web-ids23_revshell_https.csv":       "RevShell HTTPS\n(Selenium+netcat)",
    "web-ids23_xss_http.csv":             "XSS HTTP\n(Selenium)",
    "web-ids23_xss_https.csv":            "XSS HTTPS\n(Selenium)",
    "web-ids23_ssrf_http.csv":            "SSRF HTTP\n(Selenium)",
    "web-ids23_ssrf_https.csv":           "SSRF HTTPS\n(Selenium)",
    "web-ids23_ssh_login_successful.csv": "SSH Login Successful\n(Metasploit)",
}

SOURCE_FILE_TO_SEVERITY: Dict[str, str] = {
    "web-ids23_benign.csv":              "Benign",
    "web-ids23_portscan.csv":            "Reconnaissance",
    "web-ids23_bruteforce_http.csv":     "Credential_Abuse",
    "web-ids23_bruteforce_https.csv":    "Credential_Abuse",
    "web-ids23_sql_injection_http.csv":  "Active_Exploitation",
    "web-ids23_sql_injection_https.csv": "Active_Exploitation",
}


def source_label(filename: str, with_count: Optional[int] = None) -> str:
    """Pretty-print a source filename for chart labels, optionally
    appending '(n=12,345)'."""
    base = SOURCE_FILE_DETAIL.get(filename, filename.replace(".csv", ""))
    if with_count is not None:
        return f"{base}\n(n={with_count:,})"
    return base


def source_to_severity_color(filename: str) -> str:
    """Get the severity colour for a source file."""
    sev = SOURCE_FILE_TO_SEVERITY.get(filename, "neutral")
    return severity_color(sev)


# ============================================================
#  SELF-CHECK
# ============================================================

if __name__ == "__main__":
    # Quick visual sanity check: produce a swatch grid showing every
    # canonical colour with its hex code.
    apply_theme()
    fig, ax = plt.subplots(figsize=(11, 5))

    palettes = [
        ("Models",   [(n, getattr(MODEL, n)) for n in
                       ("rf", "xgb", "ensemble", "lr", "osr")]),
        ("Severity", [("benign",              SEVERITY.benign),
                      ("reconnaissance",      SEVERITY.reconnaissance),
                      ("credential_abuse",    SEVERITY.credential_abuse),
                      ("active_exploitation", SEVERITY.active_exploitation),
                      ("uncertain",           SEVERITY.uncertain),
                      ("anomaly",             SEVERITY.anomaly)]),
        ("Status",   [(n, getattr(STATUS, n)) for n in
                       ("good", "warn", "bad", "neutral", "target")]),
    ]

    y = 0
    for group, items in palettes:
        ax.text(-0.5, y + 0.5, group, fontsize=11, fontweight="bold",
                ha="right", va="center")
        for i, (name, color) in enumerate(items):
            ax.add_patch(plt.Rectangle((i, y), 0.95, 0.95,
                                        facecolor=color, edgecolor="white"))
            ax.text(i + 0.475, y + 0.475, color,
                    ha="center", va="center", fontsize=8,
                    color="white", fontweight="bold")
            ax.text(i + 0.475, y - 0.15, name,
                    ha="center", va="top", fontsize=8.5)
        y -= 1.5

    ax.set_xlim(-3, max(len(it) for _, it in palettes) + 0.5)
    ax.set_ylim(y - 0.5, len(palettes) * 1.5 - 0.5)
    ax.set_aspect("equal")
    ax.axis("off")
    ax.set_title("ThreatMatrix Canonical Palette", fontsize=13,
                 fontweight="bold", pad=12)
    save_fig(fig, ".", "theme_swatches.png")
    print("[OK] theme_swatches.png written to current directory.")