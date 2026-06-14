import matplotlib
matplotlib.use("Agg")

import os
import gc
import json
import time
import warnings
import joblib

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import seaborn as sns

from sklearn.model_selection    import train_test_split, StratifiedKFold
from sklearn.preprocessing      import StandardScaler
from sklearn.ensemble           import RandomForestClassifier
from sklearn.linear_model       import LogisticRegression
from sklearn.impute             import SimpleImputer
from sklearn.metrics            import (
    accuracy_score, precision_score, recall_score,
    f1_score, confusion_matrix, roc_auc_score, roc_curve,
    classification_report, average_precision_score
)

import xgboost as xgb
from imblearn.over_sampling import SMOTE, BorderlineSMOTE, ADASYN
import optuna

optuna.logging.set_verbosity(optuna.logging.WARNING)
warnings.filterwarnings("ignore")
np.random.seed(42)

# ── GPU detection ─────────────────────────────────────────────────────────────
try:
    import torch
    if torch.cuda.is_available():
        XGB_DEVICE = "cuda"
        _gpu_name  = torch.cuda.get_device_name(0)
        _torch_ver = torch.__version__
        print(f"[GPU] PyTorch {_torch_ver} — CUDA available — {_gpu_name}")
        print(f"[GPU] XGBoost will use device='cuda' (hist tree method)")
    else:
        XGB_DEVICE = "cpu"
        print(f"[GPU] PyTorch {torch.__version__} installed but NO CUDA GPU detected.")
        print(f"[GPU] XGBoost will run on CPU.")
except ImportError:
    XGB_DEVICE = "cpu"
    print("[GPU] PyTorch NOT installed — XGBoost will run on CPU.")


# ============================================================
#  ENSEMBLE MODEL WRAPPER
# ============================================================

class EnsembleModel:
    """
    Weighted soft-vote ensemble of RandomForest + XGBoost.

    Routing bands (symmetric):
      LOW_CONF_MAX  = 0.30, P(Attack) <= here then, confident BENIGN
      HIGH_CONF_MIN = 0.70, P(Attack) >= here then, confident ATTACK - Phase 2
      Between bands       , UNCERTAIN goes to Phase 3 RF + Open-Set Recognition
    """

    def __init__(self, rf, xgb_clf, weights=(0.40, 0.60),
                 threshold=0.5, high_conf_min=0.70, low_conf_max=0.30):
        self.rf             = rf
        self.xgb_clf        = xgb_clf
        self.weights        = weights
        self.threshold      = threshold
        self.high_conf_min  = high_conf_min
        self.low_conf_max   = low_conf_max
        self.confidence_min = high_conf_min

    def predict_proba(self, X):
        p_rf  = self.rf.predict_proba(X)
        p_xgb = self.xgb_clf.predict_proba(X)
        return self.weights[0] * p_rf + self.weights[1] * p_xgb

    def predict(self, X):
        prob = self.predict_proba(X)
        return (prob[:, 1] >= self.threshold).astype(np.int8)

    def attack_probability(self, X):
        return self.predict_proba(X)[:, 1]

    def confidence_route(self, X):
        probs  = self.attack_probability(X)
        routes = []
        for p in probs:
            if p <= self.low_conf_max:
                routes.append("BENIGN")
            elif p >= self.high_conf_min:
                routes.append("KNOWN_ATTACK")
            else:
                routes.append("UNCERTAIN")
        return routes, probs

    def __repr__(self):
        return (f"EnsembleModel(rf={self.rf.n_estimators} trees, "
                f"xgb={self.xgb_clf.n_estimators} trees, "
                f"weights={self.weights}, threshold={self.threshold}, "
                f"low_conf_max={self.low_conf_max}, "
                f"high_conf_min={self.high_conf_min})")


# ============================================================
#  CONFIGURATION
# ============================================================

DATASET_DIR = r"C:\Users\yuhan\Documents\UniKL\SEMESTER 6\FYP 2\threatmatrix-26\web-ids23"

OUTPUT_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "threatmatrix_output", "binary"
)
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ── Phase 1 Training Files ────────────────────────────────────────────────────
TARGET_FILES = {
    # ── Benign ───────────────────────────────────────────────────────────────
    "web-ids23_benign.csv"               : "Benign",

    # ── Reconnaissance (Portscan only) ───────────────────────────────────────
    "web-ids23_portscan.csv"             : "Attack",

    # ── Credential Abuse (HTTP + HTTPS BruteForce) ───────────────────────────
    "web-ids23_bruteforce_http.csv"      : "Attack",
    "web-ids23_bruteforce_https.csv"     : "Attack",

    # ── Web Exploitation (SQLi HTTP + HTTPS) ─────────────────────────────────
    "web-ids23_sql_injection_http.csv"   : "Attack",
    "web-ids23_sql_injection_https.csv"  : "Attack",
}

# ── Files withheld from training (Phase 3 RF + OSR evaluation only) ────────
WITHHELD_FILES_P3 = {
    "web-ids23_revshell_http.csv",
    "web-ids23_revshell_https.csv",
    "web-ids23_xss_http.csv",
    "web-ids23_xss_https.csv",
    "web-ids23_ssrf_http.csv",
    "web-ids23_ssrf_https.csv",
    "web-ids23_ssh_login_successful.csv",
}

# ── Forbidden label/file guards, for safety check ───────────────────────────────
FORBIDDEN_LABELS_P1 = {
    "RevShell", "SSRF", "XSS",
    "SSHSuccessful", "ssh_login_successful",
}
FORBIDDEN_FILES_P1 = {
    "revshell", "ssrf", "xss", "ssh_login_successful",
}

LABEL_COLUMN     = "attack_type"
BENIGN_LABEL     = "Benign"
ATTACK_LABEL     = "Attack"
TRAIN_RATIO      = 0.80
TEST_RATIO       = 0.20
XGB_INTERNAL_VAL = 0.10
TARGET_ACCURACY  = 0.90

# Reduced from 30/50 to speed up tuning for Phase 1 (fewer features, smaller dataset).
OPTUNA_TRIALS_RF  = 15
OPTUNA_TRIALS_XGB = 25
OPTUNA_SUBSAMPLE  = 60_000

ENSEMBLE_WEIGHTS = (0.40, 0.60)   # RF | XGB
HIGH_CONF_MIN    = 0.70
LOW_CONF_MAX     = 0.30

ATTACK_CAP_PER_FILE = 200_000
BENIGN_CAP          = 400_000

# SHAP sample bumped from 500 to 2000 for better stability with 16 features (Phase 1 schema)
SHAP_SAMPLE_SIZE = 2000

# ── FEATURE SET — 16 BEHAVIOURAL FEATURES ──────────────────────────────
UNIVERSAL_FEATURES = [
    # ── Flow volume ──────────────────────────────────────────────────────────
    "flow_duration",
    "fwd_pkts_tot",
    "bwd_pkts_tot",
    "fwd_data_pkts_tot",
    "bwd_data_pkts_tot",
    # ── Rate ─────────────────────────────────────────────────────────────────
    "flow_pkts_per_sec",
    "fwd_pkts_per_sec",
    "bwd_pkts_per_sec",
    "payload_bytes_per_second",
    # ── Direction asymmetry ──────────────────────────────────────────────────
    "down_up_ratio",
    # ── Header overhead ──────────────────────────────────────────────────────
    "fwd_header_size_tot",
    "bwd_header_size_tot",
    # ── TCP flags (behavioural) ─────────────────────────────
    "flow_FIN_flag_count",
    "flow_SYN_flag_count",
    "flow_RST_flag_count",
    "flow_ACK_flag_count",
]
# Sanity check — fail if edits the list and miscounts
assert len(UNIVERSAL_FEATURES) == 16, (
    f"UNIVERSAL_FEATURES length = {len(UNIVERSAL_FEATURES)}; "
    f"banner messages expect this count.")
N_FEATURES_EXPECTED = len(UNIVERSAL_FEATURES)  # 16 (incl. fwd/bwd_header_size_tot)

METADATA_COLS = ["uid", "ts", "id.orig_h", "id.resp_h",
                 "traffic_direction", "service"]

NON_FEATURE_COLS = [
    LABEL_COLUMN, "binary_label", "attack",
    "_source_file",
] + METADATA_COLS


# Standardised colours and styles for consistency in all phases
from threatmatrix_theme import (
    apply_theme, MODEL, STATUS, TITLE_KWARGS,
    save_fig, status_color, severity_color,
    SOURCE_FILE_DETAIL,
)
apply_theme()

PAL_RF   = MODEL.rf
PAL_XGB  = MODEL.xgb
PAL_ENS  = MODEL.ensemble
PAL_LR   = MODEL.lr
PAL_OK   = STATUS.good
PAL_WARN = STATUS.warn
PAL_BAD  = STATUS.bad

RECALL_WARN_THRESHOLD = 0.90

# Track XAI status for the saved metrics JSON (no silent failures)
XAI_STATUS = {"ran": False, "error": None}


# ============================================================
#  HELPERS
# ============================================================

def _bar_color(val, threshold=RECALL_WARN_THRESHOLD):
    """Return colour based on recall/F1 value."""
    if val >= threshold:
        return PAL_OK
    if val >= 0.80:
        return PAL_WARN
    return PAL_BAD


# ============================================================
#  PART 1 — DATA LOADING
# ============================================================

def load_data() -> pd.DataFrame:
    print("\n" + "="*60)
    print("  PHASE 1 — BINARY CLASSIFICATION")
    print("  Scope   : Benign vs 3 attack classes (Recon/Cred/Exploit)")
    print("  Training: Portscan + BruteForce HTTP/HTTPS + SQLi HTTP/HTTPS")
    print(f"  Features: {N_FEATURES_EXPECTED} behaviour-based (tool-agnostic)")
    print("  Withheld: RevShell, XSS, SSRF (Phase 3 RF + OSR = novel-class evaluation)")
    print("  Excluded: hostsweep, DoS, FTP, SMTP, SSH (see header)")
    print("="*60)

    # Safety: confirm no forbidden files into training set (RevShell, XSS, SSRF)
    bad_files = [f for f in TARGET_FILES
                 if any(fw in f.lower() for fw in FORBIDDEN_FILES_P1)]
    assert not bad_files, (
        f"[LEAKAGE] Forbidden filename(s) in TARGET_FILES: {bad_files}")

    frames = []

    for filename, label in TARGET_FILES.items():
        path = os.path.join(DATASET_DIR, filename)
        if not os.path.exists(path):
            print(f"  [WARN] Not found, skipping: {filename}")
            continue
        try:
            chunk = pd.read_csv(path, low_memory=False)
            chunk.columns = chunk.columns.str.strip()
            chunk[LABEL_COLUMN]   = label
            chunk["_source_file"] = filename

            if label == BENIGN_LABEL and len(chunk) > BENIGN_CAP:
                chunk = chunk.sample(BENIGN_CAP, random_state=42)
                cap_note = f" [capped {BENIGN_CAP:,}]"
            elif label == ATTACK_LABEL and len(chunk) > ATTACK_CAP_PER_FILE:
                chunk = chunk.sample(ATTACK_CAP_PER_FILE, random_state=42)
                cap_note = f" [capped {ATTACK_CAP_PER_FILE:,}]"
            else:
                cap_note = ""

            frames.append(chunk)
            print(f"  ✓  {filename:<50} → {len(chunk):>8,} rows  [{label}]{cap_note}")
        except Exception as exc:
            print(f"  [ERROR] {filename}: {exc}")

    if not frames:
        raise FileNotFoundError(f"[ERROR] No CSVs found in:\n  {DATASET_DIR}")

    df = pd.concat(frames, axis=0, ignore_index=True)
    df.columns = df.columns.str.strip()
    print(f"\n[INFO] Combined shape before dedup: {df.shape}")

    present_labels = set(df[LABEL_COLUMN].unique())
    leaked = present_labels & FORBIDDEN_LABELS_P1
    assert not leaked, (
        f"[LEAKAGE] Forbidden labels present after load: {leaked}")
    print(f"[CHECK] ✓ No forbidden labels. RevShell/XSS/SSRF withheld.")

    before = len(df)
    df.drop_duplicates(inplace=True)
    df.reset_index(drop=True, inplace=True)
    print(f"[INFO] Removed {before - len(df):,} duplicate rows.")

    df["binary_label"] = (df[LABEL_COLUMN] != BENIGN_LABEL).astype(np.int8)

    benign = int((df["binary_label"] == 0).sum())
    attack = int((df["binary_label"] == 1).sum())
    ratio  = max(benign, attack) / max(min(benign, attack), 1)
    print(f"\n[INFO] Binary — Benign={benign:,}  Attack={attack:,}  "
          f"Ratio={ratio:.1f}:1")

    print(f"\n[INFO] Attack source breakdown:")
    src_counts = (df[df["binary_label"] == 1]
                  .groupby("_source_file").size()
                  .sort_values(ascending=False))
    for src, cnt in src_counts.items():
        print(f"    {src:<50} {cnt:>9,}")

    counts = df["binary_label"].value_counts().rename(
        {0: "Benign", 1: "Attack"})
    _plot_class_distribution(counts)
    return df


def _plot_class_distribution(counts):
    color_map = {"Benign": "#4CAF50", "Attack": "#C62828"}
    colors = [color_map.get(k, "#9E9E9E") for k in counts.index]
    fig, ax = plt.subplots(figsize=(9, 6))
    bars = ax.bar(counts.index, counts.values, color=colors,
                  alpha=0.85, edgecolor="white", width=0.5)
    for bar, val in zip(bars, counts.values):
        ax.text(bar.get_x() + bar.get_width() / 2,
                bar.get_height() + counts.max() * 0.015,
                f"{val:,}", ha="center", va="bottom",
                fontsize=10, fontweight="bold")
    ax.set_ylim(0, counts.max() * 1.18)
    ax.set_title(
        f"Class Distribution — Phase 1: Binary\n"
        f"(Benign vs Portscan + BruteForce + SQLi | "
        f"{N_FEATURES_EXPECTED}-feature behaviour schema)",
        **TITLE_KWARGS)
    ax.set_ylabel("Number of Rows")
    ax.set_xlabel("Traffic Class")
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, "0_class_distribution.png"),
                dpi=150, bbox_inches="tight")
    plt.close()
    print("[GRAPH] 0_class_distribution.png saved.")


# ============================================================
#  PART 2 — PREPROCESSING 
# ============================================================

def preprocess(df: pd.DataFrame):
    """
    This function only:
      1. Parses ts (for time-based split)
      2. Selects feature columns
      3. Replaces inf with NaN (so split can carry NaN through)
    """
    print("\n" + "="*60)
    print(f"  PREPROCESSING — BEHAVIOUR-BASED {N_FEATURES_EXPECTED}-FEATURE SCHEMA")
    print("  Imputer and zero-var drop deferred until after train/test split")
    print("  IPs and ts are metadata only, not model input")
    print("="*60)

    df = df.copy()

    # Parse ts for time-based split 
    ts_series = pd.Series(np.zeros(len(df), dtype=np.float32), index=df.index)
    for col in ["ts", "Timestamp", "timestamp", "Time"]:
        if col in df.columns:
            parsed = pd.to_datetime(df[col], errors="coerce")
            ts_series = (parsed.astype("int64") / 1e9).astype(np.float32)
            ts_series.index = df.index
            print(f"[INFO] ts parsed from '{col}' for split (not a model feature).")
            break
    else:
        print("[WARN] No time column found — ts set to 0.")

    meta_cols_present = [c for c in METADATA_COLS if c in df.columns]
    print(f"[INFO] Metadata preserved for dashboard: {meta_cols_present}")

    available = [c for c in UNIVERSAL_FEATURES if c in df.columns]
    missing   = [c for c in UNIVERSAL_FEATURES if c not in df.columns]
    print(f"\n[INFO] Behaviour features matched: {len(available)}/{len(UNIVERSAL_FEATURES)}")
    if missing:
        print(f"[WARN] Missing features (will skip): {missing}")
    if len(available) < 8:
        raise ValueError(f"[ERROR] Only {len(available)} features found — cannot proceed.")

    X        = df[available].copy()
    y        = df["binary_label"].copy()
    y_detail = df["_source_file"].copy()

    # Replace inf with NaN 
    X.replace([np.inf, -np.inf], np.nan, inplace=True)
    nan_count = int(X.isna().sum().sum())
    if nan_count > 0:
        print(f"[INFO] Found {nan_count:,} NaN/Inf values. Will impute AFTER split (no leakage).")

    X = X.astype(np.float32)
    print(f"\n[INFO] Pre-split feature count: {len(available)} (imputer not yet fit)")
    print(f"[INFO] Features: {available}")
    return X, y, y_detail, available, ts_series


# ============================================================
#  PART 3 — SPLIT (stratified time-based, 80/20)
# ============================================================

def split_data(X, y, y_detail, ts_series):
    print("\n" + "="*60)
    print("  TRAIN / TEST SPLIT  (80/20, STRATIFIED TIME-BASED)")
    print("="*60)

    train_idx_list, test_idx_list = [], []

    for cls in sorted(y_detail.unique()):
        cls_mask      = (y_detail.values == cls)
        cls_idx       = np.where(cls_mask)[0]
        cls_ts        = ts_series.iloc[cls_idx].values
        sorted_within = cls_idx[np.argsort(cls_ts)]
        split_at      = int(len(sorted_within) * TRAIN_RATIO)
        train_idx_list.extend(sorted_within[:split_at])
        test_idx_list.extend(sorted_within[split_at:])
        print(f"  {cls:<50} Total={len(sorted_within):,}  "
              f"Train={split_at:,}  Test={len(sorted_within)-split_at:,}")

    train_idx = np.array(train_idx_list)
    test_idx  = np.array(test_idx_list)

    X_train       = X.iloc[train_idx].reset_index(drop=True)
    X_test        = X.iloc[test_idx].reset_index(drop=True)
    y_train       = y.iloc[train_idx].to_numpy(dtype=np.int8)
    y_test        = y.iloc[test_idx].to_numpy(dtype=np.int8)
    y_test_detail = y_detail.iloc[test_idx].to_numpy()

    overlap = len(set(train_idx.tolist()) & set(test_idx.tolist()))
    print(f"\n[CHECK] Train∩Test overlap = {overlap}  (must be 0)")

    for name, ys in [("Train", y_train), ("Test", y_test)]:
        b = int((ys == 0).sum()); a = int((ys == 1).sum())
        print(f"  {name:<6}: {len(ys):>8,} rows | "
              f"Benign={b:,} ({100*b/max(len(ys),1):.1f}%)  "
              f"Attack={a:,} ({100*a/max(len(ys),1):.1f}%)")

    # Persist split indices for Phase 3 to reuse the same test set
    np.savez_compressed(
        os.path.join(OUTPUT_DIR, "split_indices.npz"),
        train_idx=train_idx, test_idx=test_idx)
    print(f"[INFO] Split indices saved as split_indices.npz")

    return X_train, X_test, y_train, y_test, y_test_detail, train_idx, test_idx


# ============================================================
#  PART 3B — IMPUTER & ZERO-VAR DROP (post-split, train-only fit)
# ============================================================

def fit_imputer_and_drop_zerovar(X_train, X_test, available_features):
    """
    Fit SimpleImputer on train only, transform train + test.
    Drop zero-variance columns based on train data only.
    Returns: X_train_clean, X_test_clean, imputer, kept_features
    """
    print("\n" + "="*60)
    print("  IMPUTATION & ZERO-VAR DROP  (post-split, train-only fit)")
    print("="*60)

    imputer = SimpleImputer(strategy="median")
    X_train_imp = pd.DataFrame(
        imputer.fit_transform(X_train),
        columns=available_features,
        index=X_train.index)
    X_test_imp = pd.DataFrame(
        imputer.transform(X_test),
        columns=available_features,
        index=X_test.index)

    n_imputed_tr = int(X_train.isna().sum().sum())
    n_imputed_te = int(X_test.isna().sum().sum())
    print(f"[INFO] Imputed {n_imputed_tr:,} NaN values in TRAIN (median fitted on train).")
    print(f"[INFO] Imputed {n_imputed_te:,} NaN values in TEST  (using train-fitted medians).")

    # Zero-var check on train only
    zero_var = X_train_imp.columns[X_train_imp.std() == 0].tolist()
    if zero_var:
        print(f"[INFO] Dropping {len(zero_var)} zero-variance cols (train-detected): {zero_var}")
        X_train_imp.drop(columns=zero_var, inplace=True)
        X_test_imp.drop(columns=zero_var,  inplace=True)
    else:
        print(f"[INFO] No zero-variance columns detected.")

    kept_features = list(X_train_imp.columns)
    print(f"\n[INFO] Final feature count after imputation: {len(kept_features)}")
    print(f"[INFO] Final features: {kept_features}")
    return X_train_imp, X_test_imp, imputer, kept_features, zero_var


# ============================================================
#  PART 4 — SCALING
# ============================================================

def fit_scaler(X_train):
    scaler     = StandardScaler()
    X_train_sc = scaler.fit_transform(X_train)
    print(f"\n[INFO] Scaler fitted on {X_train.shape[0]:,} training rows.")
    return scaler, X_train_sc


# ============================================================
#  PART 5 — IMBALANCE HANDLING
# ============================================================

def benchmark_imbalance(X_train_sc, y_train):
    print("\n" + "="*60)
    print("  IMBALANCE STRATEGY BENCHMARK  (5-fold CV, proxy RF)")
    print("  Resampler runs inside each CV fold (ImbPipeline) — no fold leakage.")
    print("="*60)

    # Local import — keeps the canonical evaluation logic in one place.
    from threatmatrix_evaluation import resampled_cv_score

    BENCH_N = 40_000
    if len(X_train_sc) > BENCH_N:
        _, Xs, _, ys = train_test_split(
            X_train_sc, y_train, test_size=BENCH_N/len(X_train_sc),
            stratify=y_train, random_state=42)
    else:
        Xs, ys = X_train_sc, y_train

    strategies = {
        "SMOTE"           : SMOTE(random_state=42, k_neighbors=5),
        "BorderlineSMOTE" : BorderlineSMOTE(random_state=42, k_neighbors=5),
        "ADASYN"          : ADASYN(random_state=42, n_neighbors=5),
    }
    proxy  = RandomForestClassifier(n_estimators=30, max_depth=8,
                                    n_jobs=-1, random_state=42)
    results = {}

    for name, sampler in strategies.items():
        print(f"\n  ▶ {name}...")
        try:
            res = resampled_cv_score(
                Xs, ys, estimator=proxy, sampler=sampler,
                n_splits=5, scoring="f1", average="binary",
                verbose=True,
            )
            results[name] = res["mean"]
        except Exception as exc:
            print(f"    [WARN] {name} failed: {exc}")

    if not results:
        print("[WARN] All resamplers failed — using raw training data.")
        return "None", X_train_sc, y_train

    best_name = max(results, key=results.get)
    print(f"\n[RESULT] Best: {best_name}  (Mean CV F1={results[best_name]:.4f})")
    _plot_benchmark(results)

    print(f"\n[INFO] Applying {best_name} to full training set...")
    sampler = strategies[best_name]
    try:
        n_benign = int((y_train == 0).sum())
        n_attack = int((y_train == 1).sum())
        target   = max(n_benign, n_attack)
        strat    = {0: target, 1: target}
        sampler.set_params(sampling_strategy=strat)
        X_res, y_res = sampler.fit_resample(X_train_sc, y_train)
        y_res = y_res.astype(np.int8)
        print(f"[INFO] After {best_name} — "
              f"Benign={int((y_res==0).sum()):,}  "
              f"Attack={int((y_res==1).sum()):,}")
    except Exception as exc:
        print(f"[WARN] Resample failed ({exc}) — using raw data.")
        X_res, y_res = X_train_sc, y_train.copy()

    return best_name, X_res, y_res


def _plot_benchmark(results):
    fig, ax = plt.subplots(figsize=(9, 5.5))
    colors = [PAL_RF, PAL_ENS, PAL_XGB]
    bars = ax.bar(list(results.keys()), list(results.values()),
                  color=colors[:len(results)], width=0.5, alpha=0.9)
    y_max = max(results.values()); y_min = min(results.values())
    ax.set_ylim(max(0, y_min - 0.05), min(1.05, y_max + 0.08))
    ax.set_title(
        "Imbalance Strategy Benchmark\n"
        "(Proxy RF — 5-Fold CV Mean Binary F1 | train only)",
        **TITLE_KWARGS)
    ax.set_ylabel("Mean F1 Score")
    for bar, score in zip(bars, results.values()):
        ax.text(bar.get_x() + bar.get_width() / 2,
                bar.get_height() + 0.005,
                f"{score:.4f}", ha="center", va="bottom",
                fontweight="bold", fontsize=10)
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, "1_imbalance_benchmark.png"),
                dpi=150, bbox_inches="tight")
    plt.close()
    print("[GRAPH] 1_imbalance_benchmark.png saved.")


# ============================================================
#  PART 5B — LOGISTIC REGRESSION BASELINE
# ============================================================

def train_lr_baseline(X_res, y_res, X_test, y_test, scaler):
    print("\n" + "="*60)
    print("  LOGISTIC REGRESSION BASELINE (leakage diagnostic)")
    print("  If LR ≈ trees, features still linearly separable")
    print("="*60)
    lr = LogisticRegression(max_iter=2000, solver="lbfgs",
                            n_jobs=-1, random_state=42)
    print("[INFO] Training LR...")
    t = time.time()
    lr.fit(X_res, y_res)
    print(f"[INFO] Done in {time.time()-t:.1f}s")

    X_test_sc = scaler.transform(X_test)
    y_pred    = lr.predict(X_test_sc).astype(np.int8)
    y_prob    = lr.predict_proba(X_test_sc)[:, 1]

    metrics = _compute_binary_metrics("LR Baseline", y_test, y_pred, y_prob)
    return lr, metrics


# ============================================================
#  PART 5C — HYPERPARAMETER TUNING
# ============================================================

def _get_tune_sample(X_res, y_res, n=OPTUNA_SUBSAMPLE):
    if len(X_res) <= n:
        return X_res, y_res
    _, Xs, _, ys = train_test_split(
        X_res, y_res, test_size=n/len(X_res),
        stratify=y_res, random_state=42)
    return Xs, ys


def tune_rf(X_res, y_res):
    print("\n" + "="*60)
    print(f"  TUNING — Random Forest  ({OPTUNA_TRIALS_RF} trials | 5-fold CV)")
    print("="*60)
    Xs, ys = _get_tune_sample(X_res, y_res)
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

    def objective(trial):
        params = {
            "n_estimators"     : trial.suggest_int("n_estimators", 100, 500),
            "max_depth"        : trial.suggest_int("max_depth", 10, 30),
            "min_samples_split": trial.suggest_int("min_samples_split", 2, 10),
            "min_samples_leaf" : trial.suggest_int("min_samples_leaf", 1, 5),
            "max_features"     : trial.suggest_categorical(
                                     "max_features", ["sqrt", "log2", 0.3, 0.5]),
            "class_weight"     : None,
            "n_jobs"           : -1,
            "random_state"     : 42,
        }
        model = RandomForestClassifier(**params)
        scores = []
        for tri, vli in cv.split(Xs, ys):
            model.fit(Xs[tri], ys[tri])
            scores.append(f1_score(ys[vli], model.predict(Xs[vli]),
                                   average="binary", zero_division=0))
        return np.mean(scores)

    study = optuna.create_study(direction="maximize",
                                sampler=optuna.samplers.TPESampler(seed=42))
    study.optimize(objective, n_trials=OPTUNA_TRIALS_RF, show_progress_bar=True)
    best = study.best_params
    print(f"\n[TUNE-RF] Best Binary F1: {study.best_value:.4f}  Params: {best}")
    return best


def tune_xgb(X_res, y_res):
    print("\n" + "="*60)
    print(f"  TUNING — XGBoost  ({OPTUNA_TRIALS_XGB} trials | internal val)")
    print("="*60)
    Xs, ys = _get_tune_sample(X_res, y_res)
    Xt, Xv, yt, yv = train_test_split(Xs, ys, test_size=0.10,
                                       stratify=ys, random_state=42)

    def objective(trial):
        params = {
            "n_estimators"         : trial.suggest_int("n_estimators", 200, 800),
            "max_depth"            : trial.suggest_int("max_depth", 4, 12),
            "learning_rate"        : trial.suggest_float("learning_rate",
                                                         0.01, 0.3, log=True),
            "subsample"            : trial.suggest_float("subsample", 0.6, 1.0),
            "colsample_bytree"     : trial.suggest_float("colsample_bytree", 0.5, 1.0),
            "min_child_weight"     : trial.suggest_int("min_child_weight", 1, 10),
            "gamma"                : trial.suggest_float("gamma", 0.0, 1.0),
            "reg_alpha"            : trial.suggest_float("reg_alpha", 1e-4, 10.0, log=True),
            "reg_lambda"           : trial.suggest_float("reg_lambda", 1e-4, 10.0, log=True),
            "objective"            : "binary:logistic",
            "eval_metric"          : "logloss",
            "early_stopping_rounds": 30,
            "tree_method"          : "hist",
            "device"               : XGB_DEVICE,
            "random_state"         : 42,
            "verbosity"            : 0,
        }
        model = xgb.XGBClassifier(**params)
        model.fit(Xt, yt, eval_set=[(Xv, yv)], verbose=False)
        return f1_score(yv, model.predict(Xv), average="binary", zero_division=0)

    study = optuna.create_study(direction="maximize",
                                sampler=optuna.samplers.TPESampler(seed=42))
    study.optimize(objective, n_trials=OPTUNA_TRIALS_XGB, show_progress_bar=True)
    best = study.best_params
    best.pop("early_stopping_rounds", None)
    print(f"\n[TUNE-XGB] Best Binary F1: {study.best_value:.4f}  Params: {best}")
    return best


# ============================================================
#  SHARED — Binary Metrics and Confusion Matrix
# ============================================================

def _compute_binary_metrics(name, y_true, y_pred, y_prob):
    acc  = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec  = recall_score(y_true, y_pred, zero_division=0)
    f1   = f1_score(y_true, y_pred, zero_division=0)
    try:
        auc    = roc_auc_score(y_true, y_prob)
        pr_auc = average_precision_score(y_true, y_prob)
    except Exception:
        auc = pr_auc = float("nan")

    print(f"\n{'─'*55}")
    print(f"  {name}  —  Test Set Results")
    print(f"{'─'*55}")
    print(f"  Accuracy  : {acc*100:.2f}%  "
          f"{'✓' if acc >= TARGET_ACCURACY else '✗'}")
    print(f"  Precision : {prec*100:.2f}%")
    print(f"  Recall    : {rec*100:.2f}%")
    print(f"  F1-Score  : {f1*100:.2f}%")
    print(f"  ROC-AUC   : {auc:.4f}")
    print(f"  PR-AUC    : {pr_auc:.4f}")
    print()
    print(classification_report(y_true, y_pred,
                                target_names=["Benign (0)", "Attack (1)"],
                                zero_division=0))
    return {"name": name, "accuracy": acc, "precision": prec,
            "recall": rec, "f1": f1, "roc_auc": auc, "pr_auc": pr_auc}


def plot_cm(y_true, y_pred, model_name, filename):
    cm      = confusion_matrix(y_true, y_pred)
    cm_pct  = cm.astype(float) / cm.sum(axis=1, keepdims=True) * 100
    tn, fp, fn, tp = cm.ravel()

    fig, ax = plt.subplots(figsize=(7, 6))
    sns.heatmap(cm, annot=False, cmap="Blues", ax=ax,
                xticklabels=["Benign (0)", "Attack (1)"],
                yticklabels=["Benign (0)", "Attack (1)"],
                cbar_kws={"label": "Count", "pad": 0.02},
                linewidths=1.0, linecolor="white")

    for i in range(2):
        for j in range(2):
            count = cm[i, j]
            pct   = cm_pct[i, j]
            cell_color = "white" if cm[i, j] > cm.max() * 0.5 else "black"
            ax.text(j + 0.5, i + 0.38, f"{count:,}",
                    ha="center", va="center",
                    fontsize=14, fontweight="bold", color=cell_color)
            ax.text(j + 0.5, i + 0.62, f"({pct:.1f}% of actual)",
                    ha="center", va="center",
                    fontsize=9, color=cell_color, alpha=0.85)

    fpr = fp / max(fp + tn, 1) * 100
    fnr = fn / max(fn + tp, 1) * 100
    ax.set_title(
        f"Confusion Matrix — {model_name}\n"
        f"TP={tp:,}  TN={tn:,}  FP={fp:,}  FN={fn:,}  "
        f"|  FPR={fpr:.2f}%  FNR={fnr:.2f}%",
        pad=12, fontsize=10, **TITLE_KWARGS)
    ax.set_ylabel("Actual Class", fontsize=11)
    ax.set_xlabel("Predicted Class", fontsize=11)
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, filename),
                dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[GRAPH] {filename} saved.")


# ============================================================
#  PART 6 — RANDOM FOREST
# ============================================================

def train_rf(X_res, y_res, X_test, y_test, scaler,
             feature_names, best_params=None):
    print("\n" + "="*60)
    print("  RANDOM FOREST  (Binary — Benign vs Attack)")
    print("="*60)

    params = best_params.copy() if best_params else {
        "n_estimators": 200, "max_depth": 20,
        "min_samples_split": 5, "min_samples_leaf": 2,
        "max_features": "sqrt",
    }
    params.update({"class_weight": None, "n_jobs": -1,
                   "random_state": 42, "oob_score": True})
    print(f"[INFO] RF params: {params}")

    rf = RandomForestClassifier(**params)
    print("[INFO] Training RF...")
    t = time.time()
    rf.fit(X_res, y_res)
    print(f"[INFO] Done in {time.time()-t:.1f}s  |  OOB: {rf.oob_score_:.4f}")

    X_test_sc = scaler.transform(X_test)
    y_pred    = rf.predict(X_test_sc).astype(np.int8)
    y_prob    = rf.predict_proba(X_test_sc)[:, 1]

    metrics = _compute_binary_metrics("Random Forest", y_test, y_pred, y_prob)
    plot_cm(y_test, y_pred, "Random Forest", "2a_cm_rf.png")
    _plot_feature_importance(rf.feature_importances_, feature_names,
                              "Random Forest", "3_feature_importance_rf.png")
    return rf, metrics, y_pred, y_prob


def _plot_feature_importance(importances, feature_names, model_name, filename):
    idx = np.argsort(importances)
    colors = [PAL_OK if importances[i] >= np.percentile(importances, 66)
              else (PAL_WARN if importances[i] >= np.percentile(importances, 33)
                    else PAL_BAD) for i in idx]
    fig, ax = plt.subplots(figsize=(11, 7))
    ax.barh(range(len(feature_names)), importances[idx],
            color=colors, alpha=0.85, edgecolor="white")
    ax.set_yticks(range(len(feature_names)))
    ax.set_yticklabels([feature_names[i] for i in idx], fontsize=10)
    ax.set_xlabel("Feature Importance (Gini impurity decrease)", fontsize=11)
    ax.set_title(
        f"Feature Importance — {model_name}\n"
        f"Phase 1: {len(feature_names)} Behaviour-based features",
        **TITLE_KWARGS)
    for i, v in enumerate(importances[idx]):
        ax.text(v + 0.001, i, f"{v:.4f}", va="center", fontsize=8.5)
    ax.spines[["top", "right"]].set_visible(False)
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, filename), dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[GRAPH] {filename} saved.")


# ============================================================
#  PART 7 — XGBOOST
# ============================================================

def train_xgb(X_res, y_res, X_test, y_test, scaler, best_params=None):
    print("\n" + "="*60)
    print("  XGBOOST  (Binary — binary:logistic)")
    print("="*60)

    X_tr, X_val_int, y_tr, y_val_int = train_test_split(
        X_res, y_res, test_size=XGB_INTERNAL_VAL,
        stratify=y_res, random_state=42)

    default = {
        "n_estimators": 600, "max_depth": 8, "learning_rate": 0.05,
        "subsample": 0.8, "colsample_bytree": 0.8,
        "min_child_weight": 3, "gamma": 0.1,
        "reg_alpha": 0.5, "reg_lambda": 1.0,
    }
    params = best_params.copy() if best_params else default
    params.update({
        "objective"            : "binary:logistic",
        "eval_metric"          : "logloss",
        "early_stopping_rounds": 30,
        "tree_method"          : "hist",
        "device"               : XGB_DEVICE,
        "random_state"         : 42,
        "verbosity"            : 0,
    })

    clf = xgb.XGBClassifier(**params)
    print(f"[INFO] Device: {XGB_DEVICE.upper()} | Training...")
    t = time.time()
    clf.fit(X_tr, y_tr, eval_set=[(X_val_int, y_val_int)], verbose=50)
    print(f"[INFO] Done in {time.time()-t:.1f}s  |  "
          f"Best iter: {clf.best_iteration}")

    X_test_sc = scaler.transform(X_test)
    y_pred    = clf.predict(X_test_sc).astype(np.int8)
    y_prob    = clf.predict_proba(X_test_sc)[:, 1]

    metrics = _compute_binary_metrics("XGBoost", y_test, y_pred, y_prob)
    plot_cm(y_test, y_pred, "XGBoost", "2b_cm_xgb.png")
    return clf, metrics, y_pred, y_prob


# ============================================================
#  PART 8 — ENSEMBLE
# ============================================================

def build_ensemble_predictions(rf_prob, xgb_prob, y_test):
    w_rf, w_xgb = ENSEMBLE_WEIGHTS
    print("\n" + "="*60)
    print(f"  ENSEMBLE  (RF={w_rf} + XGB={w_xgb}, soft-vote)")
    print("="*60)

    ens_prob = w_rf * rf_prob + w_xgb * xgb_prob
    y_pred   = (ens_prob >= 0.5).astype(np.int8)

    metrics = _compute_binary_metrics("Ensemble (RF + XGB)", y_test, y_pred, ens_prob)
    plot_cm(y_test, y_pred, "Ensemble (RF + XGB)", "2c_cm_ensemble.png")
    return metrics, y_pred, ens_prob


# ============================================================
#  SOURCE FILE - DISPLAY LABEL
# ============================================================

SOURCE_FILE_DETAIL = {
    "web-ids23_benign.csv"               : "Benign (browser/FTP/SMTP/SSH)",
    "web-ids23_portscan.csv"             : "Portscan\n(Nmap -sS)",
    "web-ids23_bruteforce_http.csv"      : "HTTP BruteForce\n(Hydra)",
    "web-ids23_bruteforce_https.csv"     : "HTTPS BruteForce\n(Hydra)",
    "web-ids23_sql_injection_http.csv"   : "SQLi HTTP\n(sqlmap+Selenium)",
    "web-ids23_sql_injection_https.csv"  : "SQLi HTTPS\n(sqlmap+Selenium)",
}

_RECON_FILES   = {"portscan"}
_CRED_FILES    = {"bruteforce_http", "bruteforce_https"}
_EXPLOIT_FILES = {"sql_injection_http", "sql_injection_https"}

def _attack_category_color(filename):
    stem = filename.replace("web-ids23_", "").replace(".csv", "")
    if stem in _RECON_FILES:   return "#7B1FA2"   # purple — recon
    if stem in _CRED_FILES:    return "#1565C0"   # blue — credential
    if stem in _EXPLOIT_FILES: return "#C62828"   # red — exploitation
    return "#37474F"                              # grey — benign


# ============================================================
#  PART 9 — PER-ATTACK-TYPE GENERALISATION
# ============================================================

def run_cross_attack_generalization(ensemble, scaler, X_test,
                                    y_test, y_test_detail):
    print("\n" + "="*60)
    print("  PER-ATTACK-TYPE GENERALISATION EVALUATION")
    print("="*60)

    X_test_sc = scaler.transform(X_test)
    y_prob    = ensemble.attack_probability(X_test_sc)
    y_pred    = ensemble.predict(X_test_sc)

    unique_classes = sorted(set(y_test_detail))
    results = {}
    scenario_data = {}

    print(f"\n  {'Source file':<50} {'N':>8} {'Acc':>8} "
          f"{'Prec':>8} {'Recall':>8} {'F1':>8}")
    print("  " + "─"*95)

    for cls in unique_classes:
        mask = (y_test_detail == cls)
        n    = int(mask.sum())
        if n < 10:
            continue
        yt   = y_test[mask]
        yp   = y_pred[mask]
        acc  = accuracy_score(yt, yp)
        prec = precision_score(yt, yp, zero_division=0)
        rec  = recall_score(yt, yp, zero_division=0)
        f1   = f1_score(yt, yp, zero_division=0)
        tag  = "FPR" if cls == "web-ids23_benign.csv" else ""
        note = "LOW" if rec < RECALL_WARN_THRESHOLD \
                            and cls != "web-ids23_benign.csv" else ""

        print(f"  {cls:<50} {n:>8,} {acc*100:>7.2f}%"
              f" {prec*100:>7.2f}% {rec*100:>7.2f}%"
              f" {f1*100:>7.2f}%  {tag}{note}")

        results[cls] = {"n": n, "accuracy": acc, "precision": prec,
                        "recall": rec, "f1": f1}
        scenario_data[cls] = {"f1": f1*100, "recall": rec*100,
                              "precision": prec*100, "n": n}

    _plot_cross_attack(scenario_data)
    return results


def _plot_cross_attack(scenario_data):
    if not scenario_data:
        return

    benign_key   = "web-ids23_benign.csv"
    attack_items = [(c, d) for c, d in scenario_data.items() if c != benign_key]
    attack_items.sort(key=lambda t: t[1]["f1"])

    classes = [benign_key] + [c for c, _ in attack_items]
    f1s     = [scenario_data[c]["f1"]        for c in classes]
    recs    = [scenario_data[c]["recall"]    for c in classes]
    precs   = [scenario_data[c]["precision"] for c in classes]
    counts  = [scenario_data[c]["n"]         for c in classes]

    display_labels = []
    for c, n in zip(classes, counts):
        lbl = SOURCE_FILE_DETAIL.get(c, c)
        display_labels.append(f"{lbl}\n(n={n:,})")

    x = np.arange(len(classes)); w = 0.25
    fig, ax = plt.subplots(figsize=(16, 9))

    bar_colors = [_attack_category_color(c) for c in classes]

    ax.bar(x - w, precs, w, color=bar_colors, alpha=0.85,
           hatch="///", edgecolor="white", linewidth=0.8)
    ax.bar(x,     recs,  w, color=bar_colors, alpha=0.85,
           hatch="...", edgecolor="white", linewidth=0.8)
    ax.bar(x + w, f1s,   w, color=bar_colors, alpha=0.85,
           hatch="",    edgecolor="white", linewidth=0.8)

    LABEL_OFFSET = 1.5
    for i, (p, r, f) in enumerate(zip(precs, recs, f1s)):
        group_max = max(p, r, f)
        label_y   = group_max + LABEL_OFFSET
        for offset, val in [(-w, p), (0, r), (w, f)]:
            if val > 0.5:
                ax.text(x[i] + offset, label_y,
                        f"{val:.2f}%", ha="center", va="bottom",
                        fontsize=7.5, fontweight="bold", color="#333")

    ax.axhline(90, color="crimson", linestyle="--", lw=1.5,
               label="90% target", zorder=5)

    for i, (c, r) in enumerate(zip(classes, recs)):
        if r < RECALL_WARN_THRESHOLD * 100 and c != benign_key:
            ax.axvspan(x[i] - 0.45, x[i] + 0.45,
                       alpha=0.08, color="crimson", zorder=0)
            ax.text(x[i], 10, "⚠", ha="center", va="bottom",
                    fontsize=13, color="crimson")

    ax.set_xticks(x)
    ax.set_xticklabels(display_labels, rotation=30, ha="right", fontsize=8)
    ax.set_ylim(0, 128)
    ax.set_ylabel("Score (%)", fontsize=11)
    ax.set_title(
        "Per-Attack-Type Generalisation — Ensemble (RF + XGB)\n"
        "Phase 1 · Sorted by F1 (worst to best)\n"
        "Colour: purple=Reconnaissance | blue=Credential Abuse | red=Exploitation",
        fontsize=12, **TITLE_KWARGS, pad=12)
    ax.yaxis.grid(True, linestyle=":", alpha=0.5)
    ax.set_axisbelow(True)
    ax.spines[["top", "right"]].set_visible(False)

    cat_patches = [
        mpatches.Patch(color="#7B1FA2", alpha=0.8, label="Reconnaissance"),
        mpatches.Patch(color="#1565C0", alpha=0.8, label="Credential Abuse"),
        mpatches.Patch(color="#C62828", alpha=0.8, label="Exploitation"),
        mpatches.Patch(color="#37474F", alpha=0.8, label="Benign (FPR)"),
    ]
    metric_patches = [
        mpatches.Patch(facecolor="grey", hatch="///", edgecolor="white",
                       alpha=0.85, label="Precision"),
        mpatches.Patch(facecolor="grey", hatch="...", edgecolor="white",
                       alpha=0.85, label="Recall"),
        mpatches.Patch(facecolor="grey", hatch="",   edgecolor="white",
                       alpha=0.85, label="F1-Score"),
        plt.Line2D([0], [0], color="crimson", linestyle="--",
                   lw=1.5, label="90% target"),
    ]
    legend1 = ax.legend(handles=cat_patches, title="Attack Category",
                        loc="upper left", fontsize=9, frameon=True)
    ax.add_artist(legend1)
    fig.legend(handles=metric_patches,
               loc="lower center", bbox_to_anchor=(0.5, -0.01),
               ncol=4, fontsize=9, frameon=True)

    plt.subplots_adjust(bottom=0.28, top=0.88)
    plt.savefig(os.path.join(OUTPUT_DIR, "5b_cross_attack_generalization.png"),
                dpi=150, bbox_inches="tight")
    plt.close()
    print("[GRAPH] 5b_cross_attack_generalization.png saved.")


# ============================================================
#  PART 9B — CONFIDENCE ROUTING ANALYSIS
# ============================================================

def run_confidence_routing_analysis(ensemble, scaler, X_test,
                                    y_test, y_test_detail):
    print("\n" + "="*60)
    print("  CONFIDENCE-BASED ROUTING ANALYSIS")
    print(f"  Benign band : P(Attack) <= {ensemble.low_conf_max}")
    print(f"  Attack band : P(Attack) >= {ensemble.high_conf_min}")
    print(f"  Uncertain   : Phase 3 RF + OSR (novel-attack rejection)")
    print("="*60)

    X_test_sc     = scaler.transform(X_test)
    routes, probs = ensemble.confidence_route(X_test_sc)
    routes        = np.array(routes)

    route_labels = ["BENIGN", "KNOWN_ATTACK", "UNCERTAIN"]
    print(f"\n  Overall routing distribution ({len(routes):,} test flows):")
    routing_stats = {}
    for rl in route_labels:
        n   = int((routes == rl).sum())
        pct = 100 * n / max(len(routes), 1)
        routing_stats[rl] = {"n": n, "pct": pct}
        print(f"    {rl:<15} {n:>8,}  ({pct:.2f}%)")

    print(f"\n  Per-attack-type routing breakdown:")
    print(f"  {'Class':<40} {'BENIGN':>9} {'KNOWN_ATK':>12} {'UNCERTAIN':>12}")
    print("  " + "─"*76)
    for cls in sorted(set(y_test_detail)):
        mask  = (y_test_detail == cls)
        r_cls = routes[mask]
        n_b   = int((r_cls == "BENIGN").sum())
        n_k   = int((r_cls == "KNOWN_ATTACK").sum())
        n_u   = int((r_cls == "UNCERTAIN").sum())
        print(f"  {cls:<40} {n_b:>9,}  {n_k:>11,}  {n_u:>11,}")

    _plot_confidence_routing(routing_stats, probs, y_test,
                             ensemble.low_conf_max, ensemble.high_conf_min)
    return routing_stats


def _plot_confidence_routing(routing_stats, probs, y_true,
                             low_conf_max, high_conf_min):
    fig, axes = plt.subplots(1, 2, figsize=(16, 6.5))

    ax = axes[0]
    labels = list(routing_stats.keys())
    sizes  = [routing_stats[l]["n"] for l in labels]
    colors = [PAL_ENS, PAL_XGB, "#E53935"]
    bars   = ax.bar(labels, sizes, color=colors, alpha=0.88, width=0.5)
    for bar, n in zip(bars, sizes):
        pct = 100 * n / max(sum(sizes), 1)
        ax.text(bar.get_x() + bar.get_width()/2,
                bar.get_height() + sum(sizes)*0.010,
                f"{n:,}\n({pct:.1f}%)", ha="center", va="bottom",
                fontsize=10, fontweight="bold")
    ax.set_ylim(0, max(sizes) * 1.22)
    ax.set_title(
        f"Pipeline Routing Distribution\n"
        f"Confidence band = [{low_conf_max:.2f}, {high_conf_min:.2f}]",
        **TITLE_KWARGS)
    ax.set_ylabel("Number of Flows")
    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(["BENIGN\n(stop)",
                         "KNOWN ATTACK\n(Phase 2)",
                         "UNCERTAIN\n(Phase 3 RF + OSR)"], fontsize=10)
    ax.spines[["top", "right"]].set_visible(False)

    ax2 = axes[1]
    benign_mask = (y_true == 0)
    attack_mask = (y_true == 1)
    ax2.hist(probs[benign_mask], bins=60, alpha=0.6, color=PAL_ENS,
             label="Benign", density=True)
    ax2.hist(probs[attack_mask], bins=60, alpha=0.6, color=PAL_BAD,
             label="Attack", density=True)
    ax2.axvline(0.5, color="black", linestyle="-", lw=2,
                label="Decision threshold = 0.5")
    ax2.axvspan(low_conf_max, high_conf_min, alpha=0.15, color="orange",
                label=f"Uncertain band [{low_conf_max:.2f}, {high_conf_min:.2f}]")
    ax2.axvline(low_conf_max,  color="orange", linestyle="--", lw=1.5)
    ax2.axvline(high_conf_min, color="orange", linestyle="--", lw=1.5)
    ax2.set_xlabel("P(Attack) from Ensemble", fontsize=11)
    ax2.set_ylabel("Density", fontsize=11)
    ax2.set_title(
        "P(Attack) Distribution — Benign vs Attack\n"
        "Shaded band = flows routed to Phase 3 RF + OSR (novel-attack rejection)",
        **TITLE_KWARGS)
    ax2.legend(loc="upper center", bbox_to_anchor=(0.5, -0.15),
               fontsize=9, ncol=2, frameon=True)
    ax2.spines[["top", "right"]].set_visible(False)

    plt.suptitle(
        "Confidence-Based Routing — ThreatMatrix Phase 1\n"
        "Uncertain P(Attack) flows are deferred to Phase 3 RF + OSR (novel-attack rejection)",
        fontsize=12, **TITLE_KWARGS)
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, "6_confidence_routing_analysis.png"),
                dpi=150, bbox_inches="tight")
    plt.close()
    print("[GRAPH] 6_confidence_routing_analysis.png saved.")


# ============================================================
#  PART 9C — PER-ATTACK RECALL HEATMAP
# ============================================================

def run_per_model_attack_breakdown(rf, xgb_clf, ensemble_model,
                                    scaler, X_test, y_test, y_test_detail,
                                    feature_names):
    print("\n" + "="*60)
    print("  PER-ATTACK-TYPE RECALL HEATMAP")
    print("="*60)

    X_test_sc = scaler.transform(X_test)
    rf_pred   = rf.predict(X_test_sc).astype(np.int8)
    xgb_pred  = xgb_clf.predict(X_test_sc).astype(np.int8)
    ens_pred  = ensemble_model.predict(X_test_sc)

    unique_classes = sorted(set(y_test_detail))
    attack_classes = [c for c in unique_classes if c != "web-ids23_benign.csv"]

    model_pred_map = {
        "RF"      : rf_pred,
        "XGBoost" : xgb_pred,
        "Ensemble": ens_pred,
    }
    model_names = list(model_pred_map.keys())

    recall_matrix = np.zeros((len(attack_classes), len(model_names)))
    n_per_class   = []

    for i, cls in enumerate(attack_classes):
        mask = (y_test_detail == cls)
        n    = int(mask.sum())
        n_per_class.append(n)
        if n < 10:
            recall_matrix[i, :] = np.nan
            continue
        yt = y_test[mask]
        for j, mname in enumerate(model_names):
            yp = model_pred_map[mname][mask]
            recall_matrix[i, j] = recall_score(yt, yp, zero_division=0) * 100

    sort_order = np.argsort(recall_matrix[:, model_names.index("Ensemble")])
    recall_matrix   = recall_matrix[sort_order]
    attack_classes  = [attack_classes[i] for i in sort_order]
    n_per_class     = [n_per_class[i]    for i in sort_order]

    display_labels = [
        f"{SOURCE_FILE_DETAIL.get(c, c).replace(chr(10),' ')}  (n={n:,})"
        for c, n in zip(attack_classes, n_per_class)
    ]

    fig_h = max(8, 0.5 * len(attack_classes) + 3)
    fig, ax = plt.subplots(figsize=(10, fig_h))
    sns.heatmap(
        recall_matrix,
        annot=True, fmt=".1f",
        cmap="RdYlGn", vmin=70, vmax=100,
        xticklabels=model_names, yticklabels=display_labels,
        cbar_kws={"label": "Recall (%)", "pad": 0.02},
        linewidths=0.8, linecolor="white", ax=ax,
        annot_kws={"size": 10, "weight": "bold"},
    )
    ax.set_title(
        "Per-Attack-Type Recall — RF vs XGBoost vs Ensemble\n"
        "Phase 1 · Sorted worst to best recall · Green=good, Red=poor",
        fontsize=12, **TITLE_KWARGS, pad=12)
    ax.set_xlabel("Model", fontsize=11, fontweight="bold")
    ax.set_ylabel("Attack type · tool used", fontsize=11, fontweight="bold")
    ax.tick_params(axis="x", labelsize=11)
    ax.tick_params(axis="y", labelsize=9)

    plt.subplots_adjust(left=0.42, right=0.96, top=0.92, bottom=0.06)
    plt.savefig(os.path.join(OUTPUT_DIR, "5d_per_attack_recall_heatmap.png"),
                dpi=150, bbox_inches="tight")
    plt.close()
    print("[GRAPH] 5d_per_attack_recall_heatmap.png saved.")


# ============================================================
#  PART 10 — OVERALL PLOTS
# ============================================================

def plot_roc(y_test, all_probs):
    fig, ax = plt.subplots(figsize=(9, 7))
    colors  = [PAL_RF, PAL_XGB, PAL_ENS, PAL_LR]
    for (name, prob), color in zip(all_probs.items(), colors):
        try:
            fpr, tpr, _ = roc_curve(y_test, prob)
            auc         = roc_auc_score(y_test, prob)
            ax.plot(fpr, tpr, label=f"{name}  (AUC={auc:.4f})",
                    color=color, lw=2)
        except Exception:
            pass
    ax.plot([0, 1], [0, 1], "k--", lw=1, label="Random Classifier")
    ax.set_title(
        "ROC Curves — Phase 1: Binary (Benign vs All Attacks)\n",
        **TITLE_KWARGS)
    ax.set_xlabel("False Positive Rate", fontsize=11)
    ax.set_ylabel("True Positive Rate", fontsize=11)
    ax.legend(loc="lower right", fontsize=10)
    ax.spines[["top", "right"]].set_visible(False)
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, "4_roc_curves.png"),
                dpi=150, bbox_inches="tight")
    plt.close()
    print("[GRAPH] 4_roc_curves.png saved.")


def plot_comparison(all_metrics):
    df   = pd.DataFrame(all_metrics).set_index("name")
    mts  = ["accuracy", "precision", "recall", "f1"]
    pct  = df[mts] * 100

    fig, ax = plt.subplots(figsize=(16, 8))
    n_models = len(pct)
    x = np.arange(n_models)
    w = 0.20

    colors = ["#1565C0", "#2E7D32", "#FF8F00", "#C62828"]
    labels = ["Accuracy", "Precision", "Recall", "F1-Score"]
    for i, (col, col_, lbl) in enumerate(zip(mts, colors, labels)):
        bar_offset = (i - (len(mts) - 1) / 2) * w
        bars = ax.bar(x + bar_offset, pct[col], w, label=lbl,
                      color=col_, alpha=0.85, edgecolor="white", linewidth=0.6)
        for bar in bars:
            h = bar.get_height()
            ax.text(bar.get_x() + bar.get_width() / 2,
                    h + 0.4,
                    f"{h:.2f}%", ha="center", va="bottom",
                    fontsize=8.5, fontweight="bold", color="#222")

    ax.axhline(90, color="crimson", linestyle="--",
               lw=1.5, label="90% Target", zorder=5)
    ax.set_xticks(x)
    ax.set_xticklabels(pct.index, fontsize=11, fontweight="bold")
    ax.set_ylim(80, 115)
    ax.set_ylabel("Score (%)", fontsize=11)
    ax.set_title(
        f"ThreatMatrix — Phase 1 Model Comparison\n"
        f"Benign vs Portscan + BruteForce + SQLi | "
        f"{N_FEATURES_EXPECTED}-Feature Behaviour Schema",
        fontsize=12, **TITLE_KWARGS, pad=14)
    ax.yaxis.grid(True, linestyle=":", alpha=0.5)
    ax.set_axisbelow(True)
    ax.spines[["top", "right"]].set_visible(False)
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.09),
              ncol=5, fontsize=10, frameon=True, edgecolor="#cccccc")

    plt.subplots_adjust(bottom=0.16, top=0.86)
    plt.savefig(os.path.join(OUTPUT_DIR, "5_model_comparison.png"),
                dpi=150, bbox_inches="tight")
    plt.close()
    print("[GRAPH] 5_model_comparison.png saved.")


def plot_radar_comparison(all_metrics):
    metrics_keys   = ["accuracy", "precision", "recall", "f1", "roc_auc", "pr_auc"]
    metrics_labels = ["Accuracy", "Precision", "Recall", "F1", "ROC-AUC", "PR-AUC"]

    model_names  = [m["name"] for m in all_metrics]
    model_colors = [PAL_RF, PAL_XGB, PAL_ENS, PAL_LR][:len(all_metrics)]

    def safe(v):
        return 0.0 if (v is None or (isinstance(v, float)
                                     and np.isnan(v))) else v * 100

    data = np.array([[safe(m.get(k, 0)) for k in metrics_keys]
                     for m in all_metrics])

    n_metrics = len(metrics_keys); n_models = len(all_metrics)
    x = np.arange(n_metrics); total_w = 0.72
    bar_w = total_w / n_models
    offsets = np.linspace(-total_w/2 + bar_w/2, total_w/2 - bar_w/2, n_models)

    fig, (ax, ax_table) = plt.subplots(
        2, 1, figsize=(17, 12),
        gridspec_kw={"height_ratios": [3, 1], "hspace": 0.45},
    )
    ax_table.axis("off")

    y_min_display = 85.0
    y_max_display = 105.0

    for i, (name, color, row) in enumerate(zip(model_names, model_colors, data)):
        bars = ax.bar(x + offsets[i], row, bar_w, label=name, color=color,
                      alpha=0.88, edgecolor="white", linewidth=0.6)
        for bar, val in zip(bars, row):
            display = f"{val:.2f}%" if val > 0 else "nan"
            ax.text(bar.get_x() + bar.get_width() / 2,
                    bar.get_height() + 0.3,
                    display, ha="center", va="bottom",
                    fontsize=7.5, fontweight="bold", color="#222")

    ax.axhline(90, color="crimson", linestyle="--", lw=1.5,
               label="90% Target", zorder=5)
    ax.set_xticks(x)
    ax.set_xticklabels(metrics_labels, fontsize=12, fontweight="bold")
    ax.set_ylim(y_min_display, y_max_display)
    ax.set_ylabel("Score (%)", fontsize=11)
    ax.set_title(
        f"ThreatMatrix — Phase 1 Full Metric Comparison\n"
        f"Behaviour-based {N_FEATURES_EXPECTED}-Feature Schema",
        fontsize=13, **TITLE_KWARGS, pad=14)
    ax.yaxis.grid(True, linestyle=":", alpha=0.5, color="#aaaaaa")
    ax.set_axisbelow(True)
    ax.spines[["top", "right"]].set_visible(False)
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.07),
              ncol=len(model_names) + 1, fontsize=10,
              frameon=True, edgecolor="#cccccc")

    def fmt(m, k):
        v = m.get(k, 0)
        if v is None or (isinstance(v, float) and np.isnan(v)):
            return "nan"
        return f"{v*100:.2f}%"

    table_data = [[fmt(m, k) for k in metrics_keys] for m in all_metrics]
    tbl = ax_table.table(
        cellText=table_data, rowLabels=model_names,
        colLabels=metrics_labels, cellLoc="center",
        rowLoc="right", loc="center",
        bbox=[0.05, 0.0, 0.9, 1.0])
    tbl.auto_set_font_size(False)
    tbl.set_fontsize(10)
    tbl.scale(1.0, 1.6)

    for j in range(n_metrics):
        tbl[(0, j)].set_facecolor("#1565C0")
        tbl[(0, j)].set_text_props(color="white", fontweight="bold")
    for i, color in enumerate(model_colors):
        tbl[(i+1, -1)].set_facecolor(color)
        tbl[(i+1, -1)].set_text_props(color="white", fontweight="bold")
        for j in range(n_metrics):
            tbl[(i+1, j)].set_facecolor("#f5f5f5" if i % 2 == 0 else "white")

    plt.subplots_adjust(left=0.08, right=0.96, top=0.92, bottom=0.04)
    plt.savefig(os.path.join(OUTPUT_DIR, "5c_model_comparison_plot.png"),
                dpi=150, bbox_inches="tight")
    plt.close()
    print("[GRAPH] 5c_model_comparison_plot.png saved.")


# ============================================================
#  PART 11 — SHAP XAI  (sample bumped to 2000)
# ============================================================

def run_shap(rf, xgb_clf, X_test_sc, y_test, feature_names):
    global XAI_STATUS
    try:
        import shap
    except ImportError:
        msg = "shap not installed — skipping SHAP analysis."
        print(f"[WARN] {msg}")
        XAI_STATUS = {"ran": False, "error": "shap_not_installed"}
        return

    print("\n" + "="*60)
    print(f"  SHAP XAI — Binary Explainability ({len(feature_names)} features)")
    print(f"  Sample size: {SHAP_SAMPLE_SIZE} (bumped from 500)")
    print("="*60)

    try:
        n_shap = min(SHAP_SAMPLE_SIZE, len(X_test_sc))
        idx    = np.random.choice(len(X_test_sc), n_shap, replace=False)
        X_shap = X_test_sc[idx]
        y_shap = np.array(y_test)[idx]

        def _shap_summary(model, label, prefix):
            exp = shap.TreeExplainer(model)
            sv  = exp.shap_values(X_shap)
            if isinstance(sv, list):
                vals = sv[1]
            elif len(sv.shape) == 3:
                vals = sv[:, :, 1]
            else:
                vals = sv

            for ptype, suffix in [("bar", f"{prefix}_shap_bar.png"),
                                   ("dot", f"{prefix}_shap_dot.png")]:
                plt.close("all")
                shap.summary_plot(vals, X_shap, feature_names=feature_names,
                                  plot_type=ptype, show=False,
                                  plot_size=(13, 7.5), max_display=18)
                plt.title(f"SHAP — {label} (Attack class)",
                          fontsize=14, pad=20, **TITLE_KWARGS)
                plt.xlabel("SHAP value", fontsize=11, labelpad=10)
                plt.tight_layout()
                plt.savefig(os.path.join(OUTPUT_DIR, suffix),
                            dpi=150, pad_inches=0.4, bbox_inches="tight")
                plt.close()
                print(f"[GRAPH] {suffix} saved.")
            return exp, vals

        print("\n[INFO] RF SHAP..."); _shap_summary(rf, "Random Forest", "7a")
        print("\n[INFO] XGBoost SHAP...")
        xgb_exp, xgb_vals = _shap_summary(xgb_clf, "XGBoost", "7b")

        attack_idx = np.where(y_shap == 1)[0]
        if len(attack_idx) > 0:
            i        = attack_idx[0]
            base_val = (xgb_exp.expected_value[1]
                        if isinstance(xgb_exp.expected_value, (list, np.ndarray))
                        else xgb_exp.expected_value)
            try:
                xgb_expl = shap.Explanation(
                    values=xgb_vals[i], base_values=base_val,
                    data=X_shap[i], feature_names=feature_names)
                plt.figure(figsize=(11, 6.5))
                shap.plots.waterfall(xgb_expl, show=False, max_display=18)
                plt.title("SHAP Waterfall — Single Attack Flow (XGBoost)",
                          fontsize=12, **TITLE_KWARGS)
                plt.tight_layout()
                plt.savefig(os.path.join(OUTPUT_DIR, "7c_shap_waterfall_attack.png"),
                            dpi=150, pad_inches=0.3, bbox_inches="tight")
                plt.close()
                print("[GRAPH] 7c_shap_waterfall_attack.png saved.")
            except Exception as exc:
                print(f"  [WARN] Waterfall failed: {exc}")

        XAI_STATUS = {"ran": True, "error": None, "n_samples": n_shap}
    except Exception as exc:
        msg = f"SHAP failed: {exc}"
        print(f"[ERROR] {msg}")
        XAI_STATUS = {"ran": False, "error": str(exc)}


# ============================================================
#  PART 12 — SAVE
# ============================================================

def save_models(rf, xgb_clf, scaler, imputer, feature_names, all_metrics,
                ensemble_model, lr_metrics=None, best_resampler="SMOTE",
                zero_var_dropped=None):
    print("\n" + "="*60)
    print("  SAVING MODELS")
    print("="*60)

    joblib.dump(rf,             os.path.join(OUTPUT_DIR, "model_rf.pkl"),       compress=3)
    joblib.dump(xgb_clf,        os.path.join(OUTPUT_DIR, "model_xgb.pkl"),      compress=3)
    joblib.dump(ensemble_model, os.path.join(OUTPUT_DIR, "model_ensemble.pkl"), compress=3)
    joblib.dump(scaler,         os.path.join(OUTPUT_DIR, "scaler.pkl"),         compress=3)
    joblib.dump(imputer,        os.path.join(OUTPUT_DIR, "imputer.pkl"),        compress=3)
    joblib.dump(feature_names,  os.path.join(OUTPUT_DIR, "feature_names.pkl"),  compress=3)

    attack_files = [f for f, lbl in TARGET_FILES.items() if lbl == ATTACK_LABEL]

    payload = {
        "phase"             : "binary",
        "scope"             : "Benign vs Portscan + BruteForce HTTP/HTTPS + SQLi HTTP/HTTPS",
        "feature_schema"    : f"behaviour_based_{N_FEATURES_EXPECTED}_tool_agnostic",
        "feature_design"    : {
            "removed_tool_fingerprints": [
                "fwd_init_window_size", "bwd_init_window_size",
                "fwd_last_window_size", "bwd_last_window_size",
                "fwd_PSH_flag_count", "bwd_PSH_flag_count",
                "fwd_URG_flag_count", "bwd_URG_flag_count",
                "flow_CWR_flag_count", "flow_ECE_flag_count",
                "fwd_header_size_min", "fwd_header_size_max",
                "bwd_header_size_min", "bwd_header_size_max",
            ],
            "kept_tcp_flags_with_justification": {
                "flow_SYN_flag_count": (
                    "Portscan (Nmap -sS) sends SYN-only half-open scans. "
                    "Presence of SYN without matching ACK is ATTACK BEHAVIOUR."
                ),
                "flow_ACK_flag_count": (
                    "Absence of ACK distinguishes incomplete handshake (portscan) "
                    "from completed TCP sessions (brute-force, SQLi)."
                ),
                "flow_FIN_flag_count": (
                    "Graceful teardown pattern differs across attack types."
                ),
                "flow_RST_flag_count": (
                    "RST on auth failure is characteristic of brute-force."
                ),
            },
            "excluded_attack_files_justification": {
                "hostsweep_sn / hostsweep_Pn": "Redundant with portscan in Phase 2",
                "dos_http / dos_https": "Same tool (sqlmap) as SQLi",
                "ftp_login / ftp_version": "Small sample, protocol-specific",
                "smtp_enum / smtp_version": "Tiny sample (smtp_enum=7 rows)",
                "ssh_login": "Small sample, protocol-specific",
            },
            "zero_var_dropped_post_split": zero_var_dropped or [],
        },
        "n_features"        : len(feature_names),
        "feature_names"     : feature_names,
        "binary_classes"    : {"0": "Benign", "1": "Attack"},
        "attack_types_trained_on": attack_files,
        "withheld_phase3"   : {
            "classes": [
                "revshell_http", "revshell_https",
                "xss_http", "xss_https",
                "ssrf_http", "ssrf_https",
                "ssh_login_successful",
            ],
            "reason": (
                "RevShell + SSRF: novel unknown attack classes for Phase 3 RF + OSR evaluation. "
                "XSS: Selenium mimics real browser, genuinely undetectable at "
                "flow level (per WEB-IDS23 paper Section V). "
                "ssh_login_successful: post-auth signal invisible at flow level."
            ),
        },
        "imbalance_policy"  : {
            "method"             : "single_correction_smote",
            "best_resampler"     : best_resampler,
            "attack_cap_per_file": ATTACK_CAP_PER_FILE,
            "benign_cap"         : BENIGN_CAP,
        },
        "ensemble_weights"  : {"rf": ENSEMBLE_WEIGHTS[0], "xgb": ENSEMBLE_WEIGHTS[1]},
        "decision_threshold": 0.5,
        "high_conf_min"     : HIGH_CONF_MIN,
        "low_conf_max"      : LOW_CONF_MAX,
        "routing_logic"     : {
            "BENIGN"       : f"P(Attack) <= {LOW_CONF_MAX} stop",
            "KNOWN_ATTACK" : f"P(Attack) >= {HIGH_CONF_MIN} Phase 2 severity classification",
            "UNCERTAIN"    : (
                f"{LOW_CONF_MAX} < P(Attack) < {HIGH_CONF_MIN} Phase 3 RF + OSR"
            ),
        },
        "models"            : all_metrics,
        "lr_baseline"       : lr_metrics,
        "xai_status"        : XAI_STATUS,
        "mitre_nist_mapping": {
            "_source": "threatmatrix_mitre_nist_mapping.py",
            "_note":   "Import PHASE_2_TIER_MAPPING / PHASE_3_CLASS_MAPPING from "
                       "threatmatrix_mitre_nist_mapping for enrichment.",
        },
        "preprocessing_order": [
            "1. Load CSVs and apply caps",
            "2. Replace inf/-inf with NaN (no imputation yet)",
            "3. Stratified time-based 80/20 split",
            "4. Save split indices to split_indices.npz",
            "5. Fit imputer on TRAIN only, transform train+test",
            "6. Drop zero-variance columns (TRAIN-detected) from both",
            "7. Fit scaler on imputed TRAIN, transform train+test",
            "8. SMOTE on scaled training data only",
        ],
    }
    with open(os.path.join(OUTPUT_DIR, "binary_metrics.json"), "w") as f:
        json.dump(payload, f, indent=4, default=str)

    for fname in ["model_rf.pkl", "model_xgb.pkl", "model_ensemble.pkl",
                  "scaler.pkl", "imputer.pkl", "feature_names.pkl",
                  "split_indices.npz", "binary_metrics.json"]:
        fpath = os.path.join(OUTPUT_DIR, fname)
        if os.path.exists(fpath):
            size = os.path.getsize(fpath) / 1024
            print(f"  ✓  {fname:<46} {size:>8.1f} KB")

    print(f"\n[NEXT] Run  threatmatrix_multiclass.py  for Phase 2.")


# ============================================================
#  MAIN
# ============================================================

def main():
    print("\n" + "="*60)
    print("  ThreatMatrix — Phase 1: Binary Classification")
    print(f"  Scope    : Benign vs 3 attack classes")
    print(f"  Training : Portscan + BruteForce HTTP/HTTPS + SQLi HTTP/HTTPS")
    print(f"  Features : {N_FEATURES_EXPECTED} behaviour-based (tool-agnostic)")
    print()
    print(f"  PIPELINE:")
    print(f"    Phase 1 = Binary  gatekeeper (Benign vs Attack)")
    print(f"    Phase 2 = Multiclass: Recon / CredAbuse / Exploit")
    print(f"    Phase 3 = RF + Open-Set Recognition (Unknown attack rejection + novel-attack detection)")
    print()
    print(f"  WITHHELD = Phase 3:")
    print(f"    RevShell, XSS, SSRF — novel/browser-like attack classes")
    print(f"    ssh_login_successful — no flow-level post-auth signal")
    print()
    print(f"  Uncertainty band [{LOW_CONF_MAX:.2f}, {HIGH_CONF_MIN:.2f}] Phase 3 RF + OSR")
    print("="*60)
    t_start = time.time()

    df = load_data()
    X, y, y_detail, available_features, ts_series = preprocess(df)
    del df; gc.collect()

    X_train, X_test, y_train, y_test, y_test_detail, train_idx, test_idx = split_data(
        X, y, y_detail, ts_series)
    del X; gc.collect()

    # imputer + zero-var drop AFTER split (no leakage)
    X_train, X_test, imputer, feature_names, zero_var_dropped = \
        fit_imputer_and_drop_zerovar(X_train, X_test, available_features)

    scaler, X_train_sc = fit_scaler(X_train)
    X_test_sc          = scaler.transform(X_test)

    best_resampler, X_res, y_res = benchmark_imbalance(X_train_sc, y_train)

    lr_model, m_lr = train_lr_baseline(X_res, y_res, X_test, y_test, scaler)

    print("\n" + "="*60)
    print("  HYPERPARAMETER TUNING")
    print("="*60)
    rf_params  = tune_rf(X_res, y_res)
    xgb_params = tune_xgb(X_res, y_res)

    rf, m_rf, rf_pred, rf_prob = train_rf(
        X_res, y_res, X_test, y_test,
        scaler, feature_names, best_params=rf_params)
    xgb_clf, m_xgb, xgb_pred, xgb_prob = train_xgb(
        X_res, y_res, X_test, y_test,
        scaler, best_params=xgb_params)
    m_ens, ens_pred, ens_prob = build_ensemble_predictions(
        rf_prob, xgb_prob, y_test)

    ensemble_model = EnsembleModel(
        rf, xgb_clf, weights=ENSEMBLE_WEIGHTS,
        threshold=0.5, high_conf_min=HIGH_CONF_MIN, low_conf_max=LOW_CONF_MAX)
    print(f"\n[INFO] EnsembleModel created: {ensemble_model}")

    all_metrics = [m_rf, m_xgb, m_ens]
    all_probs   = {
        "Random Forest"    : rf_prob,
        "XGBoost"          : xgb_prob,
        "Ensemble (RF + XGB)": ens_prob,
    }

    plot_roc(y_test, all_probs)
    plot_comparison(all_metrics)
    plot_radar_comparison(all_metrics)

    print("\n" + "─"*95)
    print(f"  {'Model':<35} {'Acc':>8} {'Prec':>8} "
          f"{'Recall':>8} {'F1':>8} {'AUC':>8} {'PR-AUC':>8}")
    print("─"*95)
    print(f"  {m_lr['name']:<35} "
          f"{m_lr['accuracy']*100:>7.2f}%  "
          f"{m_lr['precision']*100:>7.2f}%  "
          f"{m_lr['recall']*100:>7.2f}%  "
          f"{m_lr['f1']*100:>7.2f}%  "
          f"{m_lr['roc_auc']:>7.4f}  "
          f"{m_lr['pr_auc']:>7.4f}  (diagnostic / leakage check)")
    print("─"*95)
    for m in all_metrics:
        flag = "✓" if m["accuracy"] >= TARGET_ACCURACY else "✗"
        print(f"  {m['name']:<35} "
              f"{m['accuracy']*100:>7.2f}%  "
              f"{m['precision']*100:>7.2f}%  "
              f"{m['recall']*100:>7.2f}%  "
              f"{m['f1']*100:>7.2f}%  "
              f"{m['roc_auc']:>7.4f}  "
              f"{m['pr_auc']:>7.4f}  {flag}")
    print("─"*95)

    lr_f1     = m_lr.get("f1", 0)
    tree_best = max(m.get("f1", 0) for m in all_metrics)
    if lr_f1 >= tree_best - 0.02:
        print(f"\n  DIAGNOSTIC WARNING:")
        print(f"     LR F1 ({lr_f1*100:.2f}%) within 2pp of best tree "
              f"({tree_best*100:.2f}%).")
        print(f"     Features may still be linearly separable.")
    else:
        gap = (tree_best - lr_f1) * 100
        print(f"\n  ✓ LR-to-tree gap = {gap:.1f}pp  "
              f"(tree models leverage non-linear behaviour patterns)")

    best = max(all_metrics, key=lambda m: m["f1"])
    print(f"\n  ★  Best by F1: {best['name']}  "
          f"(F1={best['f1']*100:.2f}%  AUC={best['roc_auc']:.4f})")

    run_cross_attack_generalization(
        ensemble_model, scaler, X_test, y_test, y_test_detail)
    run_confidence_routing_analysis(
        ensemble_model, scaler, X_test, y_test, y_test_detail)
    run_per_model_attack_breakdown(
        rf, xgb_clf, ensemble_model, scaler,
        X_test, y_test, y_test_detail, feature_names)

    run_shap(rf, xgb_clf, X_test_sc, y_test, feature_names)
    save_models(rf, xgb_clf, scaler, imputer, feature_names, all_metrics,
                ensemble_model, lr_metrics=m_lr,
                best_resampler=best_resampler,
                zero_var_dropped=zero_var_dropped)

    elapsed = (time.time() - t_start) / 60
    print(f"\n{'='*60}")
    print(f"  [DONE] Binary pipeline complete in {elapsed:.1f} min")
    print(f"  Features     : {len(feature_names)} behaviour-based (tool-agnostic)")
    print(f"  Resampler    : {best_resampler}")
    print(f"  Routing band : [{LOW_CONF_MAX:.2f}, {HIGH_CONF_MIN:.2f}] Phase 3 RF + OSR")
    print(f"  Withheld     : RevShell, XSS, SSRF, ssh_login_successful Phase 3")
    print(f"  Output       : {OUTPUT_DIR}")
    print(f"  XAI status   : ran={XAI_STATUS['ran']}  error={XAI_STATUS.get('error')}")
    print(f"  [NEXT] Run   threatmatrix_multiclass.py  for Phase 2.")
    print("="*60)


if __name__ == "__main__":
    main()