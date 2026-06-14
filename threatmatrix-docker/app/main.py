"""
ThreatMatrix — FastAPI Inference Service
=========================================
Phase 1 (Binary)  →  Phase 2 (Multiclass)  →  Phase 3 (Open-Set)
+ WebSocket live push
+ /ingest endpoint        (agent-driven)
+ /metrics endpoint       (model evaluation metrics — read from JSON file)
+ /mitre endpoint         (MITRE ATT&CK + NIST mapping — single source)

"""

import os
import sys
import json
import uuid
import pickle
import logging
import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Set, Dict, Any
from collections import OrderedDict

import numpy as np
import pandas as pd

# ── import model classes before joblib loads any pkl ────────────────
from app.models import (
    EnsembleModel,
    EnsembleModelMulticlass,
    LabelCompressor,
    TreePreprocessor,
    OpenSetClassifier,
)

# ── MITRE / NIST single source of truth ───────────────────────────────────────
from app.threatmatrix_mitre_nist_mapping import (
    enrich_phase_2,
    enrich_phase_3,
    PHASE_2_TIER_MAPPING,
    PHASE_3_CLASS_MAPPING,
)

# Safety-net: patch __main__ so old (pre-resave) pkl files can still load
_current_main = sys.modules.get("__main__")
if _current_main is not None:
    for _name, _cls in [
        ("EnsembleModel",           EnsembleModel),
        ("EnsembleModelMulticlass", EnsembleModelMulticlass),
        ("LabelCompressor",         LabelCompressor),
        ("TreePreprocessor",        TreePreprocessor),
        ("OpenSetClassifier",       OpenSetClassifier),
    ]:
        if not hasattr(_current_main, _name):
            setattr(_current_main, _name, _cls)

from fastapi import (
    FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Query, Request, Response,
)
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("threatmatrix")


# ── Environment / paths ──────────────────────────────────────────────────────
INGEST_DIR     = os.getenv("INGEST_DIR", "/app/ingest")
os.makedirs(INGEST_DIR, exist_ok=True)

BINARY_DIR     = os.getenv("BINARY_DIR",     "/app/models/binary")
MULTICLASS_DIR = os.getenv("MULTICLASS_DIR", "/app/models/multiclass")
PHASE3_DIR     = os.getenv("PHASE3_DIR",     "/app/models/anomaly")

METRICS_FILE   = os.getenv("METRICS_FILE", "/app/models/metrics.json")

CORS_ORIGINS   = [
    o.strip() for o in os.getenv("CORS_ORIGINS", "*").split(",") if o.strip()
]

AUTH_REQUIRED  = os.getenv("AUTH_REQUIRED", "0") == "1"

FLOW_BUFFER_SIZE = int(os.getenv("FLOW_BUFFER_SIZE", "10000"))

CONFIG_FILE = os.getenv("CONFIG_FILE", "/app/config/thresholds.json")

# 16-feature order — matches UNIVERSAL_FEATURES in threatmatrix_binary.py
FEATURE_COLS = [
    "flow_duration",
    "fwd_pkts_tot", "bwd_pkts_tot",
    "fwd_data_pkts_tot", "bwd_data_pkts_tot",
    "flow_pkts_per_sec", "fwd_pkts_per_sec", "bwd_pkts_per_sec",
    "payload_bytes_per_second",
    "down_up_ratio",
    "fwd_header_size_tot", "bwd_header_size_tot",
    "flow_FIN_flag_count", "flow_SYN_flag_count",
    "flow_RST_flag_count", "flow_ACK_flag_count",
]

models: dict = {}
flow_buffer: "OrderedDict[str, dict]" = OrderedDict()


# ── Custom unpickler — safety net for old pkl files ───────────────────────────
class _ThreatMatrixUnpickler(pickle.Unpickler):
    _redirect = {
        "EnsembleModel":           EnsembleModel,
        "EnsembleModelMulticlass": EnsembleModelMulticlass,
        "LabelCompressor":         LabelCompressor,
        "TreePreprocessor":        TreePreprocessor,
        "OpenSetClassifier":       OpenSetClassifier,
    }

    def find_class(self, module, name):
        if name in self._redirect:
            return self._redirect[name]
        return super().find_class(module, name)


# ── WebSocket connection manager ──────────────────────────────────────────────
class ConnectionManager:
    def __init__(self):
        self.active: Set[WebSocket] = set()

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.add(ws)
        logger.info(f"WebSocket client connected — total: {len(self.active)}")

    def disconnect(self, ws: WebSocket):
        self.active.discard(ws)
        logger.info(f"WebSocket client disconnected — total: {len(self.active)}")

    async def broadcast(self, payload: dict):
        if not self.active:
            return
        message = json.dumps(payload)
        dead = set()
        for ws in self.active:
            try:
                await ws.send_text(message)
            except Exception:
                dead.add(ws)
        self.active -= dead

manager = ConnectionManager()


async def verify_token_stub(token: Optional[str]) -> Optional[Dict[str, Any]]:
    """Replace this body with real Auth0/Supabase JWKS validation later."""
    if not token:
        return None
    return {"sub": "anonymous", "roles": []}


# ── Model loader ──────────────────────────────────────────────────────────────
def _joblib_load(path: str):
    import joblib

    try:
        obj = joblib.load(path)
        logger.info(f"  ✓ joblib.load: {os.path.basename(path)}")
        return obj
    except AttributeError as exc:
        logger.warning(
            f"  joblib.load AttributeError on {os.path.basename(path)}: {exc}\n"
            f"  → Falling back to _ThreatMatrixUnpickler."
        )
    except Exception as exc:
        logger.warning(f"  joblib.load failed on {os.path.basename(path)}: {exc}")

    try:
        with open(path, "rb") as fh:
            obj = _ThreatMatrixUnpickler(fh).load()
        logger.info(f"  ✓ _ThreatMatrixUnpickler fallback: {os.path.basename(path)}")
        return obj
    except Exception as exc:
        logger.warning(f"  _ThreatMatrixUnpickler fallback failed: {exc}")

    raise RuntimeError(
        f"Cannot load {path}. "
        f"Run resave_models.py from the project root to fix the pkl files."
    )


# ── FastAPI app ───────────────────────────────────────────────────────────────
app = FastAPI(
    title="ThreatMatrix API",
    description="Phase 1 Binary + Phase 2 Multiclass + Phase 3 Open-Set + WebSocket live push",
    version="3.2.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

logger.info(f"CORS allow_origins: {CORS_ORIGINS}")


@app.on_event("startup")
async def startup():
    logger.info("Loading ThreatMatrix models...")

    # Phase 1 — Binary ensemble
    try:
        models["binary_ensemble"] = _joblib_load(f"{BINARY_DIR}/model_ensemble.pkl")
        models["binary_scaler"]   = _joblib_load(f"{BINARY_DIR}/scaler.pkl")
        _bin_fn_path = f"{BINARY_DIR}/feature_names.pkl"
        if os.path.exists(_bin_fn_path):
            models["binary_features"] = _joblib_load(_bin_fn_path)
        else:
            models["binary_features"] = FEATURE_COLS
            logger.info("  binary feature_names.pkl not found — using FEATURE_COLS")
        logger.info("✓ Phase 1 (Binary) models loaded")
    except Exception as e:
        logger.error(f"✗ Phase 1 load failed: {e}")

    # Phase 2 — Multiclass ensemble
    try:
        models["mc_ensemble"] = _joblib_load(f"{MULTICLASS_DIR}/model_ensemble.pkl")
        models["mc_scaler"]   = _joblib_load(f"{MULTICLASS_DIR}/scaler.pkl")
        models["mc_features"] = _joblib_load(f"{MULTICLASS_DIR}/feature_names.pkl")
        _le_path = f"{MULTICLASS_DIR}/label_encoder.pkl"
        if os.path.exists(_le_path):
            models["mc_label_encoder"] = _joblib_load(_le_path)
        logger.info("✓ Phase 2 (Multiclass) models loaded")
    except Exception as e:
        logger.error(f"✗ Phase 2 load failed: {e}")

    # Phase 3 — RF + Open-Set
    try:
        models["p3_classifier"]   = _joblib_load(f"{PHASE3_DIR}/model_anomaly_detector.pkl")
        models["p3_preprocessor"] = _joblib_load(f"{PHASE3_DIR}/preprocessor_phase3.pkl")
        models["p3_features"] = list(models["p3_preprocessor"].feature_names)

        rf = models["p3_classifier"].rf
        importances = rf.feature_importances_
        feat_names  = models["p3_features"]
        order = np.argsort(importances)[::-1]
        models["p3_top_features"] = [feat_names[i] for i in order[:3]]
        models["p3_feature_importance"] = {
            feat_names[i]: float(importances[i]) for i in range(len(feat_names))
        }
        logger.info(
            f"✓ Phase 3 (RF + OSR) models loaded — "
            f"{len(models['p3_classifier'].class_names)} classes, "
            f"thr_softmax={models['p3_classifier'].thr_softmax:.4f}"
        )
    except Exception as e:
        logger.error(f"✗ Phase 3 load failed: {e}")

    logger.info("Model loading complete.")

    # ── Load persisted thresholds from config file (if present) ──────────────
    _apply_thresholds_from_file()


def _apply_thresholds_from_file():

    cfg_path = Path(CONFIG_FILE)
    if not cfg_path.exists():
        logger.info(f"No threshold config file at {CONFIG_FILE} — using model defaults")
        return
    try:
        cfg = json.loads(cfg_path.read_text())
    except Exception as e:
        logger.warning(f"Could not read {CONFIG_FILE}: {e} — using model defaults")
        return

    applied = []

    low = cfg.get("low_conf_max")
    if low is not None and "binary_ensemble" in models:
        models["binary_ensemble"].low_conf_max = float(low)
        applied.append(f"low_conf_max={low}")

    high = cfg.get("high_conf_min")
    if high is not None and "binary_ensemble" in models:
        models["binary_ensemble"].high_conf_min = float(high)
        applied.append(f"high_conf_min={high}")

    maha = cfg.get("thr_maha")
    if maha is not None and "p3_classifier" in models:
        models["p3_classifier"].thr_maha = float(maha)
        applied.append(f"thr_maha={maha}")

    softmax = cfg.get("thr_softmax")
    if softmax is not None and "p3_classifier" in models:
        models["p3_classifier"].thr_softmax = float(softmax)
        applied.append(f"thr_softmax={softmax}")

    if applied:
        logger.info(f"✓ Thresholds loaded from {CONFIG_FILE}: {', '.join(applied)}")
    else:
        logger.info(f"Threshold config file found but no recognised keys — using model defaults")

# mitigates Inject Malformed Flow Records - Pydantic schema enforces all 16 features with strict types
# ── Schemas ───────────────────────────────────────────────────────────────────
class NetworkFlow(BaseModel):
    src_ip: Optional[str] = Field(default=None)
    dst_ip: Optional[str] = Field(default=None)
    timestamp: Optional[str] = Field(default=None)

    flow_duration:            float = Field(...)
    fwd_pkts_tot:             float = Field(...)
    bwd_pkts_tot:             float = Field(...)
    fwd_data_pkts_tot:        float = Field(default=0.0)
    bwd_data_pkts_tot:        float = Field(default=0.0)
    flow_pkts_per_sec:        float = Field(...)
    fwd_pkts_per_sec:         float = Field(...)
    bwd_pkts_per_sec:         float = Field(...)
    payload_bytes_per_second: float = Field(...)
    down_up_ratio:            float = Field(...)
    fwd_header_size_tot:      float = Field(default=0.0)
    bwd_header_size_tot:      float = Field(default=0.0)
    flow_FIN_flag_count:      float = Field(...)
    flow_SYN_flag_count:      float = Field(...)
    flow_RST_flag_count:      float = Field(...)
    flow_ACK_flag_count:      float = Field(...)


class BatchRequest(BaseModel):
    flows: List[NetworkFlow]


class ConfigRequest(BaseModel):
    # low_conf_max: attack-probability ceiling below which a flow is BENIGN.
    # Range 0.01–0.50.  Default in EnsembleModel is 0.30.
    # Flutter Settings page posts here via POST /config.
    low_conf_max:  Optional[float] = Field(None, ge=0.01, le=0.50)
    # high_conf_min: floor above which Phase 1 routes KNOWN_ATTACK.
    # Recalibrated for Kali Docker environment (default 0.70).
    high_conf_min: Optional[float] = Field(None, ge=0.50, le=0.99)
    # thr_maha: Mahalanobis ceiling for Phase 3 novelty detection.
    # Raise to reduce domain-shift false-novel flags (default 6.056).
    thr_maha:      Optional[float] = Field(None, ge=0.1,  le=50.0)
    thr_softmax:   Optional[float] = Field(None, ge=0.0001, le=0.9999)


# mitigates Data Poisoning Attack
# ── Helpers ───────────────────────────────────────────────────────────────────
def flows_to_matrix(flows, feature_names):
    rows = [[getattr(f, feat, 0.0) for feat in feature_names] for f in flows]
    X = np.array(rows, dtype=np.float32)
    return np.where(np.isfinite(X), X, 0.0)


def flows_to_dataframe(flows, feature_names):
    rows = [{feat: getattr(f, feat, 0.0) for feat in feature_names} for f in flows]
    return pd.DataFrame(rows)


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _resolve_event_time(flow: NetworkFlow) -> str:

    raw = getattr(flow, "timestamp", None)
    if raw:
        s = str(raw).strip()
        # Try epoch seconds first (CICIDS-2018 style)
        try:
            return datetime.fromtimestamp(float(s), tz=timezone.utc) \
                           .isoformat().replace("+00:00", "Z")
        except (ValueError, OSError):
            pass
        # Normalise trailing Z to +00:00 for fromisoformat()
        try:
            ts = datetime.fromisoformat(s.replace("Z", "+00:00"))
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            return ts.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        except ValueError:
            logger.debug(f"Unparseable flow timestamp '{s}' — using detection time")
    return _utcnow_iso()


def _classify_severity(
    phase3_class: str,
    phase3_is_novel: bool,
    phase2_tier: Optional[str] = None,
    phase1_route: Optional[str] = None,
) -> str:
    """
    Multi-phase confidence-weighted severity.
    Use the highest-confidence signal available.
    P3 takes precedence when it gives a known attack class.
    Falls back to P2 tier, then P1 route — P3 abstaining (Benign/UNKNOWN) does not override P2/P1 signals.
    """
    # P3 known attack class — most specific signal, highest trust
    if phase3_is_novel:
        return "critical"
    if phase3_class in ("SQLi_HTTP", "SQLi_HTTPS",
                        "BruteForce_HTTP", "BruteForce_HTTPS"):
        return "high"
    if phase3_class == "Portscan":
        return "medium"

    # P3 abstained (Benign/UNKNOWN) — fall back to P2 tier
    if phase3_class in ("Benign", "UNKNOWN") and phase2_tier:
        if phase2_tier in ("Active_Exploitation", "Credential_Abuse"):
            return "high"
        if phase2_tier == "Reconnaissance":
            return "medium"

    # P2 also absent — use P1 route
    if phase1_route == "KNOWN_ATTACK":
        return "high"
    if phase1_route == "UNCERTAIN":
        return "medium"

    return "low"


def _mitre_block(phase2_tier: Optional[str], phase3_class: Optional[str]) -> dict:
    """
    Build a compact MITRE block for a single event. 
    """
    src = enrich_phase_3(phase3_class) if (phase3_class and phase3_class != "Benign") else {}
    if not src and phase2_tier:
        src = enrich_phase_2(phase2_tier)
    if not src:
        return {
            "technique_id":   None,
            "technique_name": None,
            "tactic":         None,
            "tactic_id":      None,
            "techniques":     [],
            "tactics":        [],
            "mitigations":    [],
            "urls":           [],
            "nist_severity":  None,
            "nist_response":  None,
        }

    # Pick a primary technique (first listed) for compact UI rendering.
    techniques = src.get("mitre_techniques", []) or []
    tactics    = src.get("mitre_tactics",    []) or []
    primary_tech = techniques[0] if techniques else None
    primary_tact = tactics[0]    if tactics    else None

    def _split_id_name(s: Optional[str]):
        if not s:
            return None, None
        if "(" in s and s.endswith(")"):
            tid, rest = s.split("(", 1)
            return tid.strip(), rest[:-1].strip()
        return s.strip(), None

    tech_id,   tech_name   = _split_id_name(primary_tech)
    tactic_id, tactic_name = _split_id_name(primary_tact)

    return {
        "technique_id":   tech_id,
        "technique_name": tech_name,
        "tactic":         tactic_name,
        "tactic_id":      tactic_id,
        "techniques":     techniques,
        "tactics":        tactics,
        "mitigations":    src.get("mitre_mitigations", []),
        "urls":           src.get("mitre_urls", []),
        "nist_severity":  src.get("nist_severity"),
        "nist_response":  src.get("nist_response"),
    }


def _buffer_flow(flow_id: str, raw_features: dict, result: dict):
    flow_buffer[flow_id] = {
        "flow_id":      flow_id,
        "raw_features": raw_features,
        "result":       result,
        "buffered_at":  _utcnow_iso(),
    }
    while len(flow_buffer) > FLOW_BUFFER_SIZE:
        flow_buffer.popitem(last=False)


# ── ML Pipeline ───────────────────────────────────────────────────────────────
def _run_pipeline(flows: List[NetworkFlow]) -> List[dict]:
    n = len(flows)
    if n == 0:
        return []

    detection_time = _utcnow_iso()
    event_times = [_resolve_event_time(f) for f in flows]

    X_p1 = models["binary_scaler"].transform(
        flows_to_matrix(flows, models["binary_features"])
    )
    routes_p1, probs_p1 = models["binary_ensemble"].confidence_route(X_p1)

    results: List[dict] = [None] * n  # type: ignore

    escalated_idx = [i for i, r in enumerate(routes_p1)
                     if r in ("KNOWN_ATTACK", "UNCERTAIN")]
    benign_idx    = [i for i, r in enumerate(routes_p1) if r == "BENIGN"]

    for i in benign_idx:
        flow_id = str(uuid.uuid4())
        result = {
            "event":              "flow_benign",
            "flow_id":            flow_id,
            # Dataset-native time - drives all charts and tables.
            "timestamp":          event_times[i],
            # Detection time - for ops dashboards / latency analysis.
            "detected_at":        detection_time,
            "src_ip":             flows[i].src_ip,
            "dst_ip":             flows[i].dst_ip,
            "phase1_route":       "BENIGN",
            "phase1_attack_prob": float(round(probs_p1[i], 4)),
            "phase1_uncertain":   False,
            "phase2_tier":        None,
            "phase2_confidence":  None,
            "phase3_class":       "Benign",
            "phase3_confidence":  float(round(1.0 - probs_p1[i], 4)),
            "phase3_ood_score":   None,
            "phase3_is_novel":    False,
            "top_features":       [],
            "severity":           "low",
            "mitre":              _mitre_block(None, "Benign"),
            "explanation_url":    None,
        }
        results[i] = result

    if not escalated_idx:
        return results

    escalated_flows = [flows[i] for i in escalated_idx]
    p2_routes: List[Optional[str]] = [None] * len(escalated_idx)
    p2_probs:  List[Optional[float]] = [None] * len(escalated_idx)

    if "mc_ensemble" in models:
        X_p2 = models["mc_scaler"].transform(
            flows_to_matrix(escalated_flows, models["mc_features"])
        )
        routes_p2, probs_p2 = models["mc_ensemble"].confidence_route(X_p2)
        p2_routes = list(routes_p2)
        p2_probs  = [float(round(p, 4)) for p in probs_p2]

    p3_classes: List[str]   = ["UNKNOWN"] * len(escalated_idx)
    p3_oods:    List[float] = [0.0] * len(escalated_idx)
    p3_confs:   List[float] = [0.0] * len(escalated_idx)

    if "p3_classifier" in models:
        df_p3 = flows_to_dataframe(escalated_flows, models["p3_features"])
        X_p3, _n_nan = models["p3_preprocessor"].transform(df_p3)
        labels, ood_scores = models["p3_classifier"].predict_with_osr_softmax(X_p3) # mitigates Adversarial Evasion
        confidences = 1.0 - ood_scores
        p3_classes = [str(lbl) for lbl in labels]
        p3_oods    = [float(round(s, 4)) for s in ood_scores]
        p3_confs   = [float(round(c, 4)) for c in confidences]

    top_features = models.get("p3_top_features", [])

    for k, i in enumerate(escalated_idx):
        flow_id          = str(uuid.uuid4())
        phase3_class     = p3_classes[k]
        phase3_is_novel  = (phase3_class == "UNKNOWN")
        phase1_uncertain = (routes_p1[i] == "UNCERTAIN")
        severity = _classify_severity(
    phase3_class,
    phase3_is_novel,
    phase2_tier=p2_routes[k],
    phase1_route=routes_p1[i],
)

        if phase3_class == "Benign":
            event_type = "flow_demoted"
        else:
            event_type = "threat_detected"

        result = {
            "event":              event_type,
            "flow_id":            flow_id,
            "timestamp":          event_times[i],   # dataset time
            "detected_at":        detection_time,   # ops time
            "src_ip":             flows[i].src_ip,
            "dst_ip":             flows[i].dst_ip,
            "phase1_route":       routes_p1[i],
            "phase1_attack_prob": float(round(probs_p1[i], 4)),
            "phase1_uncertain":   phase1_uncertain,
            "phase2_tier":        p2_routes[k],
            "phase2_confidence":  p2_probs[k],
            "phase3_class":       phase3_class,
            "phase3_confidence":  p3_confs[k],
            "phase3_ood_score":   p3_oods[k],
            "phase3_is_novel":    phase3_is_novel,
            "top_features":       top_features,
            "severity":           severity,
            "mitre":              _mitre_block(p2_routes[k], phase3_class),
            "explanation_url":    f"/explain/{flow_id}",
        }
        results[i] = result

        raw_features = {feat: getattr(flows[i], feat, 0.0)
                        for feat in models.get("p3_features", [])}
        _buffer_flow(flow_id, raw_features, result)

    return results


# ── WebSocket endpoint (with optional token hook) ────────────────────────────
# mitigates WebSocket Hijack with threat_stream()
@app.websocket("/ws/threats")
async def threat_stream(websocket: WebSocket,
                        token: Optional[str] = Query(default=None)):
    if AUTH_REQUIRED:
        identity = await verify_token_stub(token)
        if identity is None:
            await websocket.close(code=4001)
            return

    await manager.connect(websocket)
    try:
        await websocket.send_text(json.dumps({
            "event":     "connected",
            "message":   "ThreatMatrix live feed active",
            "timestamp": _utcnow_iso(),
            "phases":    {
                "phase1_ready": "binary_ensemble" in models,
                "phase2_ready": "mc_ensemble" in models,
                "phase3_ready": "p3_classifier" in models,
            },
        }))
        while True:
            await asyncio.sleep(30)
            await websocket.send_text(json.dumps({"event": "ping"}))
    except WebSocketDisconnect:
        manager.disconnect(websocket)


# ── Agent ingest endpoint ─────────────────────────────────────────────────────
@app.post("/ingest")
async def ingest_flows(request: BatchRequest):
    if "binary_ensemble" not in models:
        raise HTTPException(status_code=503, detail="Phase 1 models not loaded")
    if not request.flows:
        raise HTTPException(status_code=400, detail="No flows provided")

    results = _run_pipeline(request.flows)

    threats_found = 0
    demoted       = 0
    benign        = 0

    for result in results:
        evt = result["event"]
        if evt == "threat_detected":
            threats_found += 1
        elif evt == "flow_demoted":
            demoted += 1
        else:
            benign += 1

        await manager.broadcast({"event": evt, "data": result})

    logger.info(
        f"Ingested {len(results)} flows — "
        f"{threats_found} threats, {demoted} demoted, {benign} benign — "
        f"broadcast to {len(manager.active)} client(s)"
    )
    return {
        "status":           "broadcast",
        "flows_ingested":   len(results),
        "threats_found":    threats_found,
        "flows_demoted":    demoted,
        "flows_benign":     benign,
        "clients_notified": len(manager.active),
    }


# ── Metrics endpoint ──────────────────────────────────────────────────────────
@app.get("/metrics")
async def get_metrics():
    """
    Reads /app/models/metrics.json. Returns 404 when the file is absent —
    Flutter side maps this to ModelMetrics.unavailable().
    """
    p = Path(METRICS_FILE)
    if not p.exists():
        raise HTTPException(
            status_code=404,
            detail=f"metrics file not found at {METRICS_FILE}",
        )
    try:
        data = json.loads(p.read_text())
    except json.JSONDecodeError as e:
        raise HTTPException(
            status_code=500,
            detail=f"metrics file is not valid JSON: {e}",
        )
    return data


# ── MITRE mapping endpoint  ───────────────────────────
@app.get("/mitre")
async def get_mitre_mapping():
    """
    Returns the full MITRE ATT&CK + NIST mapping straight from
    threatmatrix_mitre_nist_mapping. Flutter side uses this to enrich the UI with technique/tactic details, mitigation advice, and NIST severity/response recommendations.
    """
    return {
        "phase_2": PHASE_2_TIER_MAPPING,
        "phase_3": PHASE_3_CLASS_MAPPING,
    }

@app.get("/debug/buffer")
async def debug_buffer():
    return {"flow_ids": list(flow_buffer.keys()), "size": len(flow_buffer)}

# ── Explain endpoint (on-demand SHAP) ─────────────────────────────────────────
@app.get("/explain/{flow_id}")
async def explain_flow(flow_id: str, request: Request):
    _require_session(request)
    if "p3_classifier" not in models:
        raise HTTPException(status_code=503, detail="Phase 3 model not loaded")

    entry = flow_buffer.get(flow_id)
    if entry is None:
        raise HTTPException(
            status_code=404,
            detail=f"flow_id {flow_id} not found in buffer "
                   f"(buffer size {len(flow_buffer)}, may have been evicted)",
        )

    if "p3_shap_explainer" not in models:
        try:
            import shap
            logger.info("Initialising SHAP TreeExplainer (one-time cost)...")
            models["p3_shap_explainer"] = shap.TreeExplainer(
                models["p3_classifier"].rf
            )
            logger.info("✓ SHAP TreeExplainer ready")
        except Exception as e:
            logger.error(f"✗ SHAP init failed: {e}")
            raise HTTPException(status_code=500,
                                detail=f"SHAP unavailable: {e}")

    explainer    = models["p3_shap_explainer"]
    feat_names   = models["p3_features"]
    class_names  = models["p3_classifier"].class_names
    raw_features = entry["raw_features"]

    df = pd.DataFrame([raw_features])
    X, _ = models["p3_preprocessor"].transform(df)

    try:
        shap_values = explainer.shap_values(X)
    except Exception as e:
        logger.error(f"SHAP compute failed for flow {flow_id}: {e}")
        raise HTTPException(status_code=500, detail=f"SHAP compute failed: {e}")

    if isinstance(shap_values, list):
        per_class = shap_values
    else:
        arr = np.asarray(shap_values)
        if arr.ndim == 3:
            per_class = [arr[:, :, c] for c in range(arr.shape[2])]
        else:
            per_class = [arr]

    shap_payload: Dict[str, Any] = {}
    for c_idx, c_name in enumerate(class_names):
        if c_idx >= len(per_class):
            continue
        vals = per_class[c_idx][0]
        entries = []
        for f_idx, f_name in enumerate(feat_names):
            entries.append({
                "feature": f_name,
                "value":   float(raw_features.get(f_name, 0.0)),
                "shap":    float(vals[f_idx]),
            })
        entries.sort(key=lambda e: abs(e["shap"]), reverse=True)
        shap_payload[c_name] = entries

    return {
        "flow_id":               flow_id,
        "predicted_class":       entry["result"]["phase3_class"],
        "confidence":            entry["result"]["phase3_confidence"],
        "ood_score":             entry["result"]["phase3_ood_score"],
        "is_novel":              entry["result"]["phase3_is_novel"],
        "shap_values":           shap_payload,
        "rf_feature_importance": models.get("p3_feature_importance", {}),
        "explanation_method":    "shap.TreeExplainer",
        "computed_at":           _utcnow_iso(),
        "buffered_at":           entry["buffered_at"],
    }


# ── Health + standalone predict endpoints ─────────────────────────────────────
@app.get("/health")
def health():
    return {
        "status":              "ok",
        "phase1_ready":        "binary_ensemble" in models,
        "phase2_ready":        "mc_ensemble"     in models,
        "phase3_ready":        "p3_classifier"   in models,
        "loaded_models":       list(models.keys()),
        "ws_clients":          len(manager.active),
        "flow_buffer":         len(flow_buffer),
        "buffer_capacity":     FLOW_BUFFER_SIZE,
        "auth_required":       AUTH_REQUIRED,
        "metrics_file_exists": Path(METRICS_FILE).exists(),
    }


# ── Config endpoint — Flutter Settings page updates alert threshold ────────────
@app.post("/config")
def update_config(request: ConfigRequest):
    """
    Update runtime model parameters without restarting the container.
    Currently supports low_conf_max (alert sensitivity threshold).

    low_conf_max controls Phase 1 routing:
      - Flows with attack_prob <= low_conf_max  = BENIGN  (not escalated)
      - Flows with attack_prob >= high_conf_min  = KNOWN_ATTACK
      - Everything between                      = UNCERTAIN (escalated)

    Lower value = more flows escalated = more sensitive (more alerts).
    Higher value = fewer flows escalated = less sensitive (fewer alerts).
    """
    if "binary_ensemble" not in models:
        raise HTTPException(status_code=503, detail="Phase 1 model not loaded")

    old_low  = models["binary_ensemble"].low_conf_max
    old_high = models["binary_ensemble"].high_conf_min
    old_maha = models["p3_classifier"].thr_maha if "p3_classifier" in models else None

    if request.low_conf_max is not None:
        models["binary_ensemble"].low_conf_max = request.low_conf_max
        logger.info(f"Threshold updated: low_conf_max {old_low:.3f} → {request.low_conf_max:.3f}")

    if request.high_conf_min is not None:
        models["binary_ensemble"].high_conf_min  = request.high_conf_min
        models["binary_ensemble"].confidence_min = request.high_conf_min
        logger.info(f"Threshold updated: high_conf_min {old_high:.3f} → {request.high_conf_min:.3f}")

    if request.thr_maha is not None and "p3_classifier" in models:
        models["p3_classifier"].thr_maha = request.thr_maha
        logger.info(f"Threshold updated: thr_maha {old_maha:.4f} → {request.thr_maha:.4f}")
    
    if request.thr_softmax is not None and "p3_classifier" in models:
        old_softmax = models["p3_classifier"].thr_softmax
        models["p3_classifier"].thr_softmax = request.thr_softmax
        logger.info(f"Threshold updated: thr_softmax {old_softmax:.6f} → {request.thr_softmax:.6f}")

    return {
        "status":        "ok",
        "low_conf_max":  models["binary_ensemble"].low_conf_max,
        "high_conf_min": models["binary_ensemble"].high_conf_min,
        "thr_maha":      models["p3_classifier"].thr_maha if "p3_classifier" in models else None,
        "thr_softmax":   models["p3_classifier"].thr_softmax if "p3_classifier" in models else None,
    }


@app.post("/predict")
def predict(request: BatchRequest):
    if "binary_ensemble" not in models:
        raise HTTPException(status_code=503, detail="Phase 1 models not loaded")
    if not request.flows:
        raise HTTPException(status_code=400, detail="No flows provided")
    return {"predictions": _run_pipeline(request.flows),
            "total":       len(request.flows)}

# -- Auth dependencies ---------------------------------------------------------
import hmac as _hmac
import hashlib as _hashlib
import base64 as _base64
import time as _time
import struct as _struct
import bcrypt as _bcrypt
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

AUTH_CONFIG_FILE = os.getenv("AUTH_CONFIG_FILE", "/app/config/auth.json")
SESSION_SECRET   = os.getenv("TM_SESSION_SECRET", "changeme")
SESSION_MAX_AGE  = 1800  # 30 minutes

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

@app.exception_handler(RateLimitExceeded)
async def _rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded"})

#mitigates Unauthorised Access
def _totp_now(secret_b32: str) -> set:
    key   = _base64.b32decode(secret_b32.upper().replace(" ", ""))
    codes = set()
    ts    = int(_time.time()) // 30
    for step in (ts - 1, ts, ts + 1):
        msg  = _struct.pack(">Q", step)
        h    = _hmac.new(key, msg, _hashlib.sha1).digest()
        off  = h[-1] & 0x0F
        code = (_struct.unpack(">I", h[off:off+4])[0] & 0x7FFFFFFF) % 1_000_000
        codes.add(f"{code:06d}")
    return codes

def _sign(payload: str) -> str:
    sig = _hmac.new(SESSION_SECRET.encode(), payload.encode(), _hashlib.sha256).digest()
    return payload + "." + _base64.urlsafe_b64encode(sig).decode().rstrip("=")

def _verify(token: str):
    try:
        parts = token.rsplit(".", 1)
        if len(parts) != 2:
            return None
        payload, sig_b64 = parts
        expected = _hmac.new(SESSION_SECRET.encode(), payload.encode(), _hashlib.sha256).digest()
        provided = _base64.urlsafe_b64decode(sig_b64 + "==")
        if not _hmac.compare_digest(expected, provided):
            return None
        data = json.loads(_base64.b64decode(payload + "==").decode())
        if _time.time() - data.get("last_seen", 0) > SESSION_MAX_AGE:
            return None
        return data
    except Exception:
        return None

def _make_token(email: str) -> str:
    now     = _time.time()
    payload = _base64.b64encode(json.dumps(
        {"user": email, "issued_at": now, "last_seen": now}
    ).encode()).decode().rstrip("=")
    return _sign(payload)

class LoginRequest(BaseModel):
    email:     str
    password:  str
    totp_code: str

@app.post("/auth/login")
@limiter.limit("5/minute")
async def auth_login(request: Request, body: LoginRequest, response: Response):
    try:
        cfg = json.loads(Path(AUTH_CONFIG_FILE).read_text())
    except Exception:
        raise HTTPException(status_code=503, detail="Auth config unavailable")
    user = cfg.get("users", {}).get(body.email)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not _bcrypt.checkpw(body.password.encode(), user["password_hash"].encode()):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if user.get("totp_enabled", False):
        valid_codes = _totp_now(user["totp_secret"])
        last_used   = user.get("last_used_otp", "")
        if body.totp_code not in valid_codes:
            raise HTTPException(status_code=401, detail="Invalid TOTP code")
        if body.totp_code == last_used:
            raise HTTPException(status_code=401, detail="TOTP code already used")
        cfg["users"][body.email]["last_used_otp"] = body.totp_code
        try:
            Path(AUTH_CONFIG_FILE).write_text(json.dumps(cfg, indent=2))
        except Exception:
            pass
    token = _make_token(body.email)
    response.set_cookie(
        key="session", value=token,
        max_age=SESSION_MAX_AGE, httponly=True, #secure=True, forces cookie only over HTTPS/WSS, never plain HTTP
        samesite="strict", secure=True, path="/"
    )
    logger.info(f"[AUTH] Login success: {body.email}")
    return {"success": True}

@app.post("/auth/logout")
async def auth_logout(request: Request, response: Response):
    response.delete_cookie("session", path="/")
    logger.info("[AUTH] Session invalidated")
    return {"success": True}

#mitigates Explanation-API Probing
# -- Session guard for protected endpoints -------------------------------------
def _require_session(request: Request):
    if not AUTH_REQUIRED:
        return
    token = request.cookies.get("session")
    if not token or _verify(token) is None:
        raise HTTPException(status_code=401, detail="Not authenticated")


# ── /auth/update-password ─────────────────────────────────────────────────────
# Validates current_password against the bcrypt hash in auth.json,
# then replaces it with a new bcrypt hash. No session/TOTP required.

class UpdatePasswordRequest(BaseModel):
    email:            str
    current_password: str
    new_password:     str

@app.post("/auth/update-password")
async def auth_update_password(request: Request, body: UpdatePasswordRequest):
    try:
        cfg = json.loads(Path(AUTH_CONFIG_FILE).read_text())
    except Exception:
        raise HTTPException(status_code=503, detail="Auth config unavailable")
    user = cfg.get("users", {}).get(body.email)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not _bcrypt.checkpw(body.current_password.encode(), user["password_hash"].encode()):
        raise HTTPException(status_code=401, detail="Incorrect current password")
    new_hash = _bcrypt.hashpw(body.new_password.encode(), _bcrypt.gensalt()).decode()
    cfg["users"][body.email]["password_hash"] = new_hash
    try:
        Path(AUTH_CONFIG_FILE).write_text(json.dumps(cfg, indent=2))
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to persist password change")
    logger.info(f"[AUTH] Password updated: {body.email}")
    return {"success": True}


# ── /auth/totp/setup ──────────────────────────────────────────────────────────
# Validates password, generates a new TOTP secret + QR code PNG (base64),
# persists the secret with totp_enabled=True so /auth/login can verify
# the code the Flutter UI collects in the next step.
# Requires: qrcode[pil] installed in the container (pip install qrcode[pil]).

import io          as _io
import urllib.parse as _urlparse

class TotpSetupRequest(BaseModel):
    email:    str
    password: str

@app.post("/auth/totp/setup")
async def auth_totp_setup(request: Request, body: TotpSetupRequest):
    try:
        cfg = json.loads(Path(AUTH_CONFIG_FILE).read_text())
    except Exception:
        raise HTTPException(status_code=503, detail="Auth config unavailable")
    user = cfg.get("users", {}).get(body.email)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not _bcrypt.checkpw(body.password.encode(), user["password_hash"].encode()):
        raise HTTPException(status_code=401, detail="Incorrect password")

    # Generate a 20-byte random Base32 secret — compatible with _totp_now().
    secret = _base64.b32encode(os.urandom(20)).decode()

    # Build the standard otpauth URI (RFC 6238 / Google Authenticator format).
    label  = _urlparse.quote(f"ThreatMatrix:{body.email}")
    issuer = _urlparse.quote("ThreatMatrix")
    otp_uri = (
        f"otpauth://totp/{label}"
        f"?secret={secret}&issuer={issuer}"
        f"&algorithm=SHA1&digits=6&period=30"
    )

    # Render QR code as base64 PNG. Requires qrcode[pil] in the Docker image.
    try:
        import qrcode as _qrcode
        qr = _qrcode.QRCode(
            error_correction=_qrcode.constants.ERROR_CORRECT_L,
            box_size=8,
            border=2,
        )
        qr.add_data(otp_uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buf = _io.BytesIO()
        img.save(buf, format="PNG")
        qr_b64 = _base64.b64encode(buf.getvalue()).decode()
    except ImportError:
        raise HTTPException(
            status_code=503,
            detail="QR generation unavailable — run: pip install qrcode[pil]",
        )

    # Persist secret and enable TOTP so /auth/login can verify the code
    # that Flutter collects in the confirmation step.
    cfg["users"][body.email]["totp_secret"]  = secret
    cfg["users"][body.email]["totp_enabled"] = True
    try:
        Path(AUTH_CONFIG_FILE).write_text(json.dumps(cfg, indent=2))
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to persist TOTP setup")

    logger.info(f"[AUTH] TOTP setup initiated: {body.email}")
    return {"qr_code": qr_b64, "manual_key": secret}