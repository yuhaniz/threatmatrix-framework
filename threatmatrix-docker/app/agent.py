"""
ThreatMatrix — Network Flow Agent
==================================
Forwards real network flows into the FastAPI inference service.

USAGE
─────
    python agent.py                    # WATCH MODE (default).
                                       # Drops in ./ingest/ are picked up
                                       # by watchdog and POSTed to /ingest.
                                      

ENVIRONMENT VARIABLES
─────────────────────
    TM_API_URL      FastAPI base URL (default: http://localhost:8000).

    TM_INGEST_DIR   Directory to watch for CSV files (default: ./ingest/).
    TM_BATCH_SIZE   Flows per POST to /ingest (default: 50).
    TM_INTERVAL     Seconds between synthetic batches in simulate mode (default: 5.0).
    TM_BATCH_DELAY  Seconds between batches in watch mode (default: 0.0 = max speed).
                    Set to 0.1 if the WebSocket floods the dashboard during a demo.

"""

import argparse
import csv
import logging
import os
import random
import time
from pathlib import Path

import requests
from watchdog.events import FileSystemEventHandler
from watchdog.observers.polling import PollingObserver

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [AGENT] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("threatmatrix-agent")

API_URL    = os.getenv("TM_API_URL", "http://localhost:8000")
INGEST_DIR = os.getenv(
    "TM_INGEST_DIR",
    str(Path(__file__).resolve().parent / "ingest"),
)
BATCH_SIZE  = int(os.getenv("TM_BATCH_SIZE", "50"))
INTERVAL    = float(os.getenv("TM_INTERVAL", "5.0"))      # simulate only
BATCH_DELAY = float(os.getenv("TM_BATCH_DELAY", "0.0"))   # watch-mode pacing

# 16 features — must match FEATURE_COLS in main.py exactly.
# Phase 1 uses all 16. Phase 2 and 3 use 14
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

# CSV columns that might contain timestamps, source IPs, and destination IPs
TIMESTAMP_COLS_CANDIDATES = [
    "timestamp", "Timestamp", "Time", "time", "flow_start",
    "Flow Start", "Flow_Start", "Stime", "Date first seen",
]
SRC_IP_COLS = {"src ip", "source ip", "src_ip", "source_ip"}
DST_IP_COLS = {"dst ip", "destination ip", "dst_ip", "destination_ip"}


# ── Send a batch to FastAPI ───────────────────────────────────────────────────
def send_flows(flows: list[dict], source_tag: str = "") -> dict | None:
    if not flows:
        return None
    try:
        resp = requests.post(
            f"{API_URL}/ingest",
            json={"flows": flows},
            timeout=30,
        )
        resp.raise_for_status()
        result = resp.json()
        prefix = f"[{source_tag}] " if source_tag else ""
        logger.info(
            f"{prefix}✓ Sent {result['flows_ingested']} → "
            f"{result['threats_found']} threats, "
            f"{result.get('flows_demoted', 0)} demoted, "
            f"{result.get('flows_benign', 0)} benign → "
            f"{result['clients_notified']} client(s) notified"
        )
        return result
    except requests.exceptions.ConnectionError:
        logger.error(f"✗ Cannot connect to FastAPI at {API_URL}")
    except requests.exceptions.HTTPError as e:
        logger.error(f"✗ HTTP {e.response.status_code}: {e.response.text}")
    except Exception as e:
        logger.error(f"✗ Unexpected error: {e}")
    return None


# ── CSV file parsing (watch mode) ─────────────────────────────────────────────
def parse_csv(filepath: str) -> tuple[list[dict], dict[str, int]]:

    flows: list[dict] = []
    label_counts: dict[str, int] = {}

    try:
        with open(filepath, newline="") as f:
            reader = csv.DictReader(f)
            header = reader.fieldnames or []
            header_map = {col.strip().lower(): col for col in header}

            # -- Schema validation ------------------------------------------
            matched_cols = [c for c in FEATURE_COLS if c in header or c in header_map]
            if len(matched_cols) < 8:
                logger.error(
                    f"Invalid schema in {Path(filepath).name}: "
                    f"only {len(matched_cols)}/{len(FEATURE_COLS)} required columns found. "
                    f"File rejected."
                )
                return [], {}
            # ----------------------------------------------------------------------
            src_col = next((header_map[k] for k in SRC_IP_COLS if k in header_map), None)
            dst_col = next((header_map[k] for k in DST_IP_COLS if k in header_map), None)

            ts_col = None
            for cand in TIMESTAMP_COLS_CANDIDATES:
                if cand in header:
                    ts_col = cand
                    break
                if cand.lower() in header_map:
                    ts_col = header_map[cand.lower()]
                    break

            if ts_col:
                logger.info(f"  Using '{ts_col}' as the event-time column")
            else:
                logger.info(f"  No timestamp column — backend will use detection time")

            for row in reader:
                if "Label" in row and row["Label"]:
                    lbl = row["Label"].strip()
                    label_counts[lbl] = label_counts.get(lbl, 0) + 1

                flow: dict = {}
                if ts_col:
                    raw_ts = (row.get(ts_col) or "").strip()
                    if raw_ts:
                        flow["timestamp"] = raw_ts

                if src_col:
                    v = (row.get(src_col) or "").strip()
                    if v:
                        flow["src_ip"] = v
                if dst_col:
                    v = (row.get(dst_col) or "").strip()
                    if v:
                        flow["dst_ip"] = v

                for col in FEATURE_COLS:
                    val = row.get(col) or row.get(col.lower()) or "0"
                    try:
                        flow[col] = float(val)
                    except (ValueError, TypeError):
                        flow[col] = 0.0
                flows.append(flow)

        logger.info(f"Parsed {len(flows):,} flows from {Path(filepath).name}")
        if label_counts:
            logger.info("  Ground-truth label distribution:")
            for lbl, n in sorted(label_counts.items(), key=lambda kv: -kv[1]):
                logger.info(f"    {lbl:40s}  {n:>8,}")
    except Exception as e:
        logger.error(f"Failed to parse {filepath}: {e}")
    return flows, label_counts


# ── Watchdog handler ──────────────────────────────────────────────────────────
class CSVDropHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory:
            return
        if not event.src_path.endswith(".csv"):
            return
        if "_processed_" in event.src_path:
            return

        logger.info(f"📂 New file detected: {Path(event.src_path).name}")
        time.sleep(0.3)  # let the file write settle
        process_file(event.src_path)


def process_file(csv_path: str):
    """Parse, batch-post, and archive a single CSV."""
    flows, _label_counts = parse_csv(csv_path)
    if not flows:
        logger.error(f"Rejected {Path(csv_path).name} � no valid flows parsed. File will not be sent to /ingest.")
        done_path = csv_path.replace(".csv", f"_rejected_{int(time.time())}.csv")
        try:
            os.rename(csv_path, done_path)
            logger.info(f"  archived as rejected -> {Path(done_path).name}")
        except OSError as e:
            logger.warning(f"  archive failed: {e}")
        return

    source_tag = Path(csv_path).stem
    n_batches = (len(flows) + BATCH_SIZE - 1) // BATCH_SIZE
    aggregate = {"threats": 0, "demoted": 0, "benign": 0}

    t0 = time.time()
    for i in range(0, len(flows), BATCH_SIZE):
        batch = flows[i:i + BATCH_SIZE]
        result = send_flows(batch, source_tag=source_tag)
        if result:
            aggregate["threats"] += result.get("threats_found", 0)
            aggregate["demoted"] += result.get("flows_demoted", 0)
            aggregate["benign"]  += result.get("flows_benign", 0)
        if BATCH_DELAY > 0 and i + BATCH_SIZE < len(flows):
            time.sleep(BATCH_DELAY)
    elapsed = time.time() - t0

    logger.info(
        f"✓ Finished {Path(csv_path).name}: "
        f"{len(flows):,} flows in {n_batches} batches, "
        f"{elapsed:.1f}s — "
        f"threats={aggregate['threats']:,}, "
        f"demoted={aggregate['demoted']:,}, "
        f"benign={aggregate['benign']:,}"
    )

    done_path = csv_path.replace(".csv", f"_processed_{int(time.time())}.csv")
    try:
        os.rename(csv_path, done_path)
        logger.info(f"  archived → {Path(done_path).name}")
    except OSError as e:
        logger.warning(f"  archive failed: {e}")


def run_watch_mode():
    ingest_path = Path(INGEST_DIR).resolve()
    ingest_path.mkdir(parents=True, exist_ok=True)
    logger.info(f"👁  Watching {ingest_path}")
    logger.info(f"    Batch size: {BATCH_SIZE}, batch delay: {BATCH_DELAY}s "
                f"(0 = stream as fast as possible)")

    existing = sorted(p for p in ingest_path.glob("*.csv")
                      if "_processed_" not in p.name)
    if existing:
        logger.info(f"Found {len(existing)} existing CSV(s) — processing now")
        for p in existing:
            process_file(str(p))
    else:
        logger.info("    No existing CSVs — waiting for new files...")

    observer = PollingObserver()
    observer.schedule(CSVDropHandler(), path=str(ingest_path), recursive=False)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Stopping agent...")
        observer.stop()
    observer.join()


# ── Simulate mode (testing only) ───────────────────────────────────
ATTACK_PROFILES = {
    "DoS": {
        "flow_duration": (100, 5000),
        "fwd_pkts_tot": (1000, 50000), "bwd_pkts_tot": (10, 500),
        "fwd_data_pkts_tot": (800, 45000), "bwd_data_pkts_tot": (5, 300),
        "payload_bytes_per_second": (50000, 500000),
        "flow_pkts_per_sec": (500, 5000),
        "fwd_pkts_per_sec": (400, 4000), "bwd_pkts_per_sec": (10, 100),
        "down_up_ratio": (0.01, 0.1),
        "fwd_header_size_tot": (20000, 1000000), "bwd_header_size_tot": (200, 10000),
        "flow_FIN_flag_count": (0, 2), "flow_SYN_flag_count": (0, 5),
        "flow_RST_flag_count": (5, 50), "flow_ACK_flag_count": (100, 5000),
    },
    "BruteForce": {
        "flow_duration": (1, 200),
        "fwd_pkts_tot": (2, 20), "bwd_pkts_tot": (1, 10),
        "fwd_data_pkts_tot": (1, 15), "bwd_data_pkts_tot": (1, 8),
        "payload_bytes_per_second": (100, 2000),
        "flow_pkts_per_sec": (5, 50),
        "fwd_pkts_per_sec": (3, 30), "bwd_pkts_per_sec": (1, 20),
        "down_up_ratio": (0.5, 2.0),
        "fwd_header_size_tot": (40, 400), "bwd_header_size_tot": (20, 200),
        "flow_FIN_flag_count": (1, 3), "flow_SYN_flag_count": (1, 5),
        "flow_RST_flag_count": (0, 3), "flow_ACK_flag_count": (2, 20),
    },
    "Portscan": {
        "flow_duration": (0.5, 50),
        "fwd_pkts_tot": (1, 5), "bwd_pkts_tot": (0, 2),
        "fwd_data_pkts_tot": (0, 1), "bwd_data_pkts_tot": (0, 1),
        "payload_bytes_per_second": (0, 200),
        "flow_pkts_per_sec": (1, 10),
        "fwd_pkts_per_sec": (1, 10), "bwd_pkts_per_sec": (0, 2),
        "down_up_ratio": (0.0, 0.5),
        "fwd_header_size_tot": (20, 100), "bwd_header_size_tot": (0, 40),
        "flow_FIN_flag_count": (0, 1), "flow_SYN_flag_count": (1, 3),
        "flow_RST_flag_count": (0, 2), "flow_ACK_flag_count": (0, 2),
    },
    "Benign": {
        "flow_duration": (500, 30000),
        "fwd_pkts_tot": (10, 200), "bwd_pkts_tot": (8, 180),
        "fwd_data_pkts_tot": (8, 180), "bwd_data_pkts_tot": (6, 160),
        "payload_bytes_per_second": (500, 8000),
        "flow_pkts_per_sec": (1, 20),
        "fwd_pkts_per_sec": (0.5, 10), "bwd_pkts_per_sec": (0.5, 10),
        "down_up_ratio": (0.8, 1.2),
        "fwd_header_size_tot": (200, 4000), "bwd_header_size_tot": (160, 3600),
        "flow_FIN_flag_count": (1, 2), "flow_SYN_flag_count": (1, 2),
        "flow_RST_flag_count": (0, 1), "flow_ACK_flag_count": (10, 200),
    },
}


def _generate_flow(profile_name: str) -> dict:
    profile = ATTACK_PROFILES[profile_name]
    return {col: round(random.uniform(*profile[col]), 4) for col in FEATURE_COLS}


def run_simulate_mode():
    logger.warning("⚠ SIMULATE MODE — synthetic flows only for testing.")
    logger.warning("  DoS profile is NOT a trained class — expect Active_Exploitation or UNKNOWN.")
    logger.info(f"Sending synthetic batches every {INTERVAL}s ...")

    while True:
        flows = []
        for _ in range(BATCH_SIZE):
            profile = random.choices(
                ["Benign", "DoS", "BruteForce", "Portscan"],
                weights=[0.60, 0.20, 0.10, 0.10],
            )[0]
            flows.append(_generate_flow(profile))
        send_flows(flows, source_tag="simulate")
        time.sleep(INTERVAL)


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ThreatMatrix Network Flow Agent")
    parser.add_argument(
        "--simulate", action="store_true",
        help="Generate synthetic flows and not the primary demo path.",
    )
    args = parser.parse_args()

    try:
        r = requests.get(f"{API_URL}/health", timeout=5)
        h = r.json()
        if h.get("status") == "ok":
            logger.info(
                f"✓ FastAPI reachable — "
                f"Phase1: {h['phase1_ready']} | "
                f"Phase2: {h['phase2_ready']} | "
                f"Phase3: {h.get('phase3_ready', False)}"
            )
        else:
            logger.warning("⚠ FastAPI responded but models may not be ready")
    except Exception:
        logger.warning(f"⚠ FastAPI not reachable at {API_URL} — agent will retry on send")

    if args.simulate:
        run_simulate_mode()
    else:
        run_watch_mode()