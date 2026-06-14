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

from sklearn.model_selection    import (train_test_split,
                                        StratifiedShuffleSplit, StratifiedKFold)
from sklearn.preprocessing      import (StandardScaler, LabelEncoder,
                                        label_binarize)
from sklearn.ensemble           import RandomForestClassifier
from sklearn.linear_model       import LogisticRegression
from sklearn.impute             import SimpleImputer
from sklearn.metrics            import (
    accuracy_score, precision_score, recall_score,
    f1_score, confusion_matrix, roc_auc_score,
    classification_report, roc_curve, average_precision_score
)

import xgboost as xgb
from imblearn.over_sampling     import SMOTE, BorderlineSMOTE, ADASYN
import optuna

# ── Shared theme + evaluation modules ────────────────────────────────────────
from threatmatrix_theme import (
    apply_theme, MODEL, SEVERITY, STATUS,
    TITLE_KWARGS, save_fig, severity_color, status_color,
    SOURCE_FILE_DETAIL as THEME_SOURCE_FILE_DETAIL, source_label,
)
from threatmatrix_evaluation import resampled_cv_score

apply_theme()

optuna.logging.set_verbosity(optuna.logging.WARNING)
warnings.filterwarnings("ignore")
np.random.seed(42)



try:
    import torch
    if torch.cuda.is_available():
        XGB_DEVICE = "cuda"
        print(f"[GPU] CUDA available - {torch.cuda.get_device_name(0)}")
    else:
        XGB_DEVICE = "cpu"
        print("[GPU] No CUDA GPU - running on CPU.")
except ImportError:
    XGB_DEVICE = "cpu"
    print("[GPU] PyTorch not found - XGBoost on CPU.")


# ============================================================
#  ENSEMBLE WRAPPER
# ============================================================

class EnsembleModelMulticlass:
    """
    Weighted soft-vote ensemble of RandomForest + XGBoost.
    Returns predictions in ORIGINAL label space (uses LabelCompressor
    to re-expand probabilities for held-out classes).
    """
    def __init__(self, rf, xgb_clf, class_names, lc,
                 weights=(0.40, 0.60), confidence_min=0.70):
        self.rf             = rf
        self.xgb_clf        = xgb_clf
        self.class_names    = class_names
        self.lc             = lc
        self.weights        = weights
        self.confidence_min = confidence_min
        self.n_orig_classes = len(class_names)

    def predict_proba(self, X):
        p_rf_c  = self.rf.predict_proba(X)
        p_xgb_c = self.xgb_clf.predict_proba(X)
        p_c     = self.weights[0] * p_rf_c + self.weights[1] * p_xgb_c
        return self.lc.expand_proba(p_c, self.n_orig_classes)

    def predict(self, X):
        return np.argmax(self.predict_proba(X), axis=1).astype(np.int8)

    def predict_with_confidence(self, X):
        proba       = self.predict_proba(X)
        predictions = self.predict(X)
        max_probs   = proba.max(axis=1)
        labels      = [self.class_names[i] for i in predictions]
        uncertain   = max_probs < self.confidence_min
        return predictions, max_probs, labels, uncertain

    def confidence_route(self, X):
        proba     = self.predict_proba(X)
        max_probs = proba.max(axis=1)
        preds     = self.predict(X)
        routes    = []
        for p, max_p in zip(preds, max_probs):
            if max_p >= self.confidence_min:
                routes.append(self.class_names[int(p)])
            else:
                routes.append("UNCERTAIN")
        return routes, max_probs

    def __repr__(self):
        return (
            f"EnsembleModelMulticlass(\n"
            f"  classes        = {self.class_names}\n"
            f"  train_classes  = {self.lc.train_class_names}\n"
            f"  weights        = RF={self.weights[0]}, XGB={self.weights[1]}\n"
            f"  confidence_min = {self.confidence_min}\n"
            f")"
        )


# ============================================================
#  CONFIGURATION
# ============================================================

DATASET_DIR = os.environ.get(
    "THREATMATRIX_DATASET_DIR",
    r"C:\Users\yuhan\Documents\UniKL\SEMESTER 6\FYP 2\threatmatrix-26\web-ids23",
)

OUTPUT_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "threatmatrix_output", "multiclass"
)
os.makedirs(OUTPUT_DIR, exist_ok=True)

TARGET_FILES = {
    "web-ids23_portscan.csv"             : "Reconnaissance",
    "web-ids23_bruteforce_http.csv"      : "Credential_Abuse",
    "web-ids23_bruteforce_https.csv"     : "Credential_Abuse",
    "web-ids23_sql_injection_http.csv"   : "Active_Exploitation",
    "web-ids23_sql_injection_https.csv"  : "Active_Exploitation",
}

FORBIDDEN_LABELS_P2 = {"Benign", "RevShell", "SSHSuccessful",
                       "SSRF", "ssh_login_successful", "XSS"}

CLASS_NAMES  = ["Reconnaissance", "Credential_Abuse", "Active_Exploitation"]
# Canonical severity palette — same colours used in Phase 1 per-attack chart
# and Phase 3 anomaly visualisations, based on NIST 800-61 severity.
CLASS_COLORS = [
    SEVERITY.reconnaissance,       # green  — Low
    SEVERITY.credential_abuse,     # orange — Medium
    SEVERITY.active_exploitation,  # red    — High
]

SOURCE_FILE_DETAIL = {
    "web-ids23_portscan.csv"             : "Portscan\n(Nmap -sS)",
    "web-ids23_bruteforce_http.csv"      : "BruteForce HTTP\n(Hydra)",
    "web-ids23_bruteforce_https.csv"     : "BruteForce HTTPS\n(Hydra)",
    "web-ids23_sql_injection_http.csv"   : "SQLi HTTP\n(sqlmap)",
    "web-ids23_sql_injection_https.csv"  : "SQLi HTTPS\n(sqlmap)",
}

LABEL_COLUMN     = "attack_type"
N_CLASSES        = 3
TRAIN_RATIO      = 0.80
TEST_RATIO       = 0.20
XGB_INTERNAL_VAL = 0.10
CALIB_VAL_RATIO  = 0.15
TARGET_MACRO_F1  = 0.90
TARGET_ACCURACY  = 0.90

# Optuna tuning parameters
OPTUNA_TRIALS_RF  = 15
OPTUNA_TRIALS_XGB = 25
OPTUNA_SUBSAMPLE  = 60_000

ENSEMBLE_WEIGHTS  = (0.40, 0.60)
CONFIDENCE_MIN    = 0.70

# Recon cap reduced to 100K to mitigate extreme imbalance and overfitting to recon class
RECON_CAP = 100_000

# SMOTE strategy set to "match_largest_real" to avoid extreme synthetic inflation of minority classes
SMOTE_TARGET_STRATEGY = "match_largest_real"

# Coverage penalty alpha for better evaluation as 0.5 is a balanced choice
COVERAGE_PENALTY_ALPHA = 0.5

# LR diagnostic gap — the expected performance gap between the LR baseline and the RF/XGB/Ensemble models
LR_DIAGNOSTIC_GAP_PP = 5.0

# Track XAI status for the saved metrics JSON (no silent failures)
XAI_STATUS = {"ran": False, "error": None}

# PROTOCOL-AGNOSTIC FEATURE SET (14 features).
UNIVERSAL_FEATURES = [
    # ── Flow volume ─────────────────────────────────────────
    "flow_duration",
    "fwd_pkts_tot",
    "bwd_pkts_tot",
    "fwd_data_pkts_tot",
    "bwd_data_pkts_tot",
    # ── Rate ────────────────────────────────────────────────
    "flow_pkts_per_sec",
    "fwd_pkts_per_sec",
    "bwd_pkts_per_sec",
    "payload_bytes_per_second",
    # ── Direction asymmetry ─────────────────────────────────
    "down_up_ratio",
    # ── TCP flags (attack behaviour, not tool fingerprint) ──
    "flow_FIN_flag_count",
    "flow_SYN_flag_count",
    "flow_RST_flag_count",
    "flow_ACK_flag_count",
]
N_FEATURES_EXPECTED = len(UNIVERSAL_FEATURES)  # 14

METADATA_COLS = ["uid", "ts", "id.orig_h", "id.resp_h",
                 "traffic_direction", "service"]
NON_FEATURE_COLS = [LABEL_COLUMN, "attack", "_source_file"] + METADATA_COLS


# ── Plot styling ──────────────────────────────────────────────────────────────
PAL_RF  = MODEL.rf       # blue   — Random Forest
PAL_XGB = MODEL.xgb      # orange — XGBoost
PAL_ENS = MODEL.ensemble # green  — Ensemble
PAL_LR  = MODEL.lr       # purple — LR diagnostic baseline


# ============================================================
#  PART 1 — DATA LOADING
# ============================================================

def load_data() -> pd.DataFrame:
    print("\n" + "="*60)
    print("  PHASE 2 — SEVERITY CLASSIFICATION (MULTICLASS)")
    print(f"  Classes: {' / '.join(CLASS_NAMES)}")
    print(f"  Features: {N_FEATURES_EXPECTED} flow-behaviour (protocol-agnostic)")
    print(f"  Recon cap: {RECON_CAP:,} rows")
    print(f"  SMOTE strategy: {SMOTE_TARGET_STRATEGY}")
    print(f"  Coverage penalty alpha: {COVERAGE_PENALTY_ALPHA}")
    print("="*60)

    EXCLUDED_FILES_P2 = {
        "hostsweep", "dos", "ftp_login", "ftp_version",
        "smtp_enum", "smtp_version", "ssh_login",
        "xss", "revshell", "ssrf", "ssh_login_successful", "benign",
    }
    bad_files = [f for f in TARGET_FILES
                 if any(w in f.lower() for w in EXCLUDED_FILES_P2)]
    assert not bad_files, (
        f"[LEAKAGE] Excluded/withheld file(s) in TARGET_FILES: {bad_files}.")
    bad_labels = [lbl for lbl in TARGET_FILES.values()
                  if lbl in FORBIDDEN_LABELS_P2]
    assert not bad_labels, (
        f"[LEAKAGE] Forbidden label(s) in TARGET_FILES: {bad_labels}")

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

            cap_note = ""
            if label == "Reconnaissance" and len(chunk) > RECON_CAP:
                chunk = chunk.sample(RECON_CAP, random_state=42)
                cap_note = f" [capped at {RECON_CAP:,}]"

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
    leaked = present_labels & FORBIDDEN_LABELS_P2
    assert not leaked, f"[LEAKAGE] Forbidden labels after load: {leaked}."
    withheld = sorted(FORBIDDEN_LABELS_P2 - {"Benign"})
    print(f"[CHECK] ✓ No forbidden labels. Withheld for Phase 3: {withheld}")

    print(f"\n[INFO] Tier composition (after caps):")
    for tier in CLASS_NAMES:
        tier_files = [f for f, lbl in TARGET_FILES.items() if lbl == tier]
        tier_total = int((df[LABEL_COLUMN] == tier).sum())
        print(f"  {tier:<22} ({tier_total:>10,} rows) ← {len(tier_files)} source file(s)")
        for f in tier_files:
            n = int((df["_source_file"] == f).sum())
            if n > 0:
                print(f"      {f:<40} {n:>9,}")

    before = len(df)
    df.drop_duplicates(inplace=True)
    df.reset_index(drop=True, inplace=True)
    print(f"[INFO] Removed {before - len(df):,} duplicate rows.")

    counts = df[LABEL_COLUMN].value_counts()
    print(f"\n[INFO] Per-class row counts (post-cap, post-dedup):")
    for lbl, cnt in counts.items():
        pct = 100 * cnt / len(df)
        print(f"  {lbl:<25} {cnt:>10,}  ({pct:.1f}%)")

    max_cls = counts.max(); min_cls = counts.min()
    ratio = max_cls / max(min_cls, 1)
    print(f"\n[INFO] Class imbalance ratio: {ratio:.1f}:1  "
          f"({'acceptable' if ratio < 5 else 'high — SMOTE will correct'})")

    _plot_class_distribution(counts)
    return df


def _plot_class_distribution(counts):
    color_map = dict(zip(CLASS_NAMES, CLASS_COLORS))
    colors    = [color_map.get(k, "#9E9E9E") for k in counts.index]
    fig, ax   = plt.subplots(figsize=(11, 6))
    bars      = ax.bar(counts.index, counts.values, color=colors,
                       alpha=0.85, edgecolor="white")
    for bar, val in zip(bars, counts.values):
        ax.text(bar.get_x() + bar.get_width() / 2,
                bar.get_height() + counts.max() * 0.015,
                f"{val:,}", ha="center", va="bottom",
                fontsize=9, fontweight="bold")
    ax.set_ylim(0, counts.max() * 1.22)
    ax.set_title(
        f"Class Distribution — Phase 2)\n"
        f"({' / '.join(CLASS_NAMES)} | "
        f"{N_FEATURES_EXPECTED}-feature protocol-agnostic schema)",
        **TITLE_KWARGS)
    ax.set_ylabel("Number of Rows"); ax.set_xlabel("Class")
    plt.xticks(rotation=25, ha="right"); plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, "0_class_distribution.png"),
                dpi=150, bbox_inches="tight")
    plt.close()
    print("[GRAPH] 0_class_distribution.png saved.")


# ============================================================
#  PART 2 — PREPROCESSING
# ============================================================

def preprocess(df: pd.DataFrame):
    """
    Imputer is no longer fit here:
      1. Parse ts (for time-based split)
      2. Build label index
      3. Select feature columns
      4. Replace inf with NaN — actual imputation happens after split.
    """
    print("\n" + "="*60)
    print(f"  PREPROCESSING — {N_FEATURES_EXPECTED}-FEATURE PROTOCOL-AGNOSTIC SCHEMA")
    print("  Imputer + zero-var drop deferred until after train/test split")
    print("="*60)

    df = df.copy()
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

    label_to_idx = {cls: i for i, cls in enumerate(CLASS_NAMES)}
    unknown = set(df[LABEL_COLUMN].unique()) - set(CLASS_NAMES)
    assert not unknown, f"[ENCODER] Unknown labels in data: {unknown}"
    y = pd.Series(df[LABEL_COLUMN].map(label_to_idx).astype(np.int8),
                  index=df.index)

    le = LabelEncoder()
    le.fit(CLASS_NAMES)
    le.classes_ = np.array(CLASS_NAMES)
    print(f"[CHECK] ✓ LabelEncoder fixed order: {CLASS_NAMES}")

    print(f"\n[INFO] Label mapping:")
    for i, cls in enumerate(CLASS_NAMES):
        n = int((y == i).sum())
        print(f"  {i} → {cls:<22} ({n:,} samples, {100*n/len(y):.1f}%)")

    available = [c for c in UNIVERSAL_FEATURES if c in df.columns]
    missing   = [c for c in UNIVERSAL_FEATURES if c not in df.columns]

    header_cols_in_data = [c for c in ["fwd_header_size_tot", "bwd_header_size_tot"]
                           if c in df.columns]
    if header_cols_in_data:
        print(f"[AUDIT] Header size cols present in raw data but EXCLUDED: "
              f"{header_cols_in_data}")

    print(f"\n[INFO] Behaviour features matched: {len(available)}/{len(UNIVERSAL_FEATURES)}")
    if missing:
        print(f"[WARN] Missing features (will skip): {missing}")
    if len(available) < 8:
        raise ValueError(f"[ERROR] Only {len(available)} features found.")

    X = df[available].copy()
    X.replace([np.inf, -np.inf], np.nan, inplace=True)
    nan_count = int(X.isna().sum().sum())
    if nan_count > 0:
        print(f"[INFO] Found {nan_count:,} NaN/Inf values. Will impute AFTER split (no leakage).")

    X = X.astype(np.float32)
    print(f"\n[INFO] Pre-split feature count: {len(available)} (imputer not yet fit)")
    print(f"[INFO] Features: {available}")
    source_files = df["_source_file"].copy()
    return X, y, available, le, ts_series, source_files


# ============================================================
#  PART 3 — SPLIT (stratified time-based, 80/20)
#  persists split indices for Phase 3 reproducibility
# ============================================================

def split_data(X, y, ts_series, source_files):
    print("\n" + "="*60)
    print("  TRAIN / TEST SPLIT  (80/20, STRATIFIED TIME-BASED)")
    print("="*60)

    label_names = pd.Series([CLASS_NAMES[i] for i in y], index=y.index)
    train_idx_list, test_idx_list = [], []

    for cls in CLASS_NAMES:
        cls_mask      = (label_names.values == cls)
        cls_idx       = np.where(cls_mask)[0]
        cls_ts        = ts_series.iloc[cls_idx].values
        sorted_within = cls_idx[np.argsort(cls_ts)]
        split_at      = int(len(sorted_within) * TRAIN_RATIO)
        train_idx_list.extend(sorted_within[:split_at])
        test_idx_list.extend(sorted_within[split_at:])
        print(f"\n  {cls:<25}: Total={len(sorted_within):,}  "
              f"Train={split_at:,}  Test={len(sorted_within)-split_at:,}")

    train_idx = np.array(train_idx_list)
    test_idx  = np.array(test_idx_list)

    overlap = len(set(train_idx.tolist()) & set(test_idx.tolist()))
    print(f"\n[CHECK] Train∩Test overlap = {overlap}  (must be 0)")

    # persists split indices for Phase 3 reuse
    np.savez_compressed(
        os.path.join(OUTPUT_DIR, "split_indices_mc.npz"),
        train_idx=train_idx, test_idx=test_idx)
    print(f"[INFO] Split indices saved → split_indices_mc.npz")

    return train_idx, test_idx


def apply_split(X_df, y_series, source_files, train_idx, test_idx):
    """
    Slices the pre-imputation data using train/test indices.
    Then carves a calibration set out of the training portion.
    """
    X_train_full = X_df.iloc[train_idx].reset_index(drop=True)
    X_test       = X_df.iloc[test_idx].reset_index(drop=True)
    y_train_full = y_series.iloc[train_idx].to_numpy(dtype=np.int8)
    y_test       = y_series.iloc[test_idx].to_numpy(dtype=np.int8)

    test_source_files = source_files.iloc[test_idx].to_numpy()

    # Calibration carve-out
    X_train_full_arr = X_train_full.to_numpy()
    X_train_arr, X_calib_arr, y_train, y_calib = train_test_split(
        X_train_full_arr, y_train_full,
        test_size=CALIB_VAL_RATIO,
        stratify=y_train_full, random_state=42)

    # Re-wrap train/calib as DataFrames for imputer fit (column names matter)
    X_train = pd.DataFrame(X_train_arr, columns=X_train_full.columns)
    X_calib = pd.DataFrame(X_calib_arr, columns=X_train_full.columns)

    print(f"\n  Set sizes:")
    for name, ys in [("Train", y_train), ("Calib", y_calib), ("Test", y_test)]:
        print(f"    {name:<10}: {len(ys):>8,} rows | ", end="")
        for i, cls in enumerate(CLASS_NAMES):
            n = int((ys == i).sum())
            if n > 0:
                print(f"{cls}={n:,}  ", end="")
        print()

    return (X_train, X_calib, X_test,
            y_train, y_calib, y_test,
            test_source_files)


# ============================================================
#  PART 3B — IMPUTER AND ZERO-VAR DROP (post-split, train-only fit)
# ============================================================

def fit_imputer_and_drop_zerovar(X_train, X_calib, X_test, available_features):
    """
    Fit SimpleImputer on TRAIN only, transform train + calib + test.
    Drop zero-variance columns based on TRAIN data only, propagate.
    """
    print("\n" + "="*60)
    print("  IMPUTATION & ZERO-VAR DROP  (post-split, train-only fit)")
    print("="*60)

    imputer = SimpleImputer(strategy="median")
    X_train_imp = pd.DataFrame(
        imputer.fit_transform(X_train),
        columns=available_features)
    X_calib_imp = pd.DataFrame(
        imputer.transform(X_calib),
        columns=available_features)
    X_test_imp = pd.DataFrame(
        imputer.transform(X_test),
        columns=available_features)

    n_imp_tr = int(X_train.isna().sum().sum())
    n_imp_cv = int(X_calib.isna().sum().sum())
    n_imp_te = int(X_test.isna().sum().sum())
    print(f"[INFO] Imputed {n_imp_tr:,} NaN in TRAIN (median fitted on train).")
    print(f"[INFO] Imputed {n_imp_cv:,} NaN in CALIB (using train medians).")
    print(f"[INFO] Imputed {n_imp_te:,} NaN in TEST  (using train medians).")

    # Zero-var check on TRAIN only
    zero_var = X_train_imp.columns[X_train_imp.std() == 0].tolist()
    if zero_var:
        print(f"[INFO] Dropping {len(zero_var)} zero-variance cols (train-detected): {zero_var}")
        X_train_imp.drop(columns=zero_var, inplace=True)
        X_calib_imp.drop(columns=zero_var, inplace=True)
        X_test_imp.drop(columns=zero_var,  inplace=True)
    else:
        print(f"[INFO] No zero-variance columns detected.")

    kept_features = list(X_train_imp.columns)
    print(f"\n[INFO] Final feature count after imputation: {len(kept_features)}")
    print(f"[INFO] Final features: {kept_features}")

    return X_train_imp, X_calib_imp, X_test_imp, imputer, kept_features, zero_var


# ============================================================
#  PART 4 — SCALING
# ============================================================

def fit_scaler(X_train):
    scaler     = StandardScaler()
    X_train_sc = scaler.fit_transform(X_train)
    print(f"\n[INFO] Scaler fitted on {X_train.shape[0]:,} training rows.")
    return scaler, X_train_sc


# ===================================================================
#  LABEL COMPRESSION UTILITY
#  Handles cases where some classes may be absent from training data
# ==================================================================

class LabelCompressor:
    def __init__(self, y_train, all_class_names):
        present = sorted(np.unique(y_train).tolist())
        self.orig_to_comp = {orig: comp for comp, orig in enumerate(present)}
        self.comp_to_orig = {comp: orig for comp, orig in enumerate(present)}
        self.n_train_classes      = len(present)
        self.train_class_names    = [all_class_names[i] for i in present]
        self.present_orig_indices = present
        absent = [i for i in range(len(all_class_names)) if i not in present]
        if absent:
            print(f"[COMPRESS] Held-out class(es) absent: "
                  f"{[all_class_names[i] for i in absent]}")
        print(f"[COMPRESS] Training label map orig→compressed: {self.orig_to_comp}")
        print(f"[COMPRESS] n_train_classes = {self.n_train_classes}")

    def compress(self, y):
        return np.array([self.orig_to_comp[int(v)] for v in y], dtype=np.int8)

    def expand(self, y_comp):
        return np.array([self.comp_to_orig[int(v)] for v in y_comp], dtype=np.int8)

    def expand_proba(self, proba_comp, n_orig_classes):
        out = np.zeros((len(proba_comp), n_orig_classes), dtype=np.float32)
        for comp_idx, orig_idx in self.comp_to_orig.items():
            out[:, orig_idx] = proba_comp[:, comp_idx]
        return out


# ============================================================
#  PART 5 — IMBALANCE BENCHMARK  (SMOTE target = max real)
# ============================================================

def _f1_average(n_classes):
    return "binary" if n_classes == 2 else "macro"


def _xgb_objective_params(n_train_classes):
    if n_train_classes == 2:
        return {"objective": "binary:logistic", "eval_metric": "logloss"}
    return {"objective": "multi:softprob", "eval_metric": "mlogloss",
            "num_class": n_train_classes}


def benchmark_imbalance(X_train_sc, y_train):
    print("\n" + "="*60)
    print("  IMBALANCE STRATEGY BENCHMARK  (5-fold CV via ImbPipeline)")
    print(f"  SMOTE target = max real class count ")
    print("="*60)

    lc = LabelCompressor(y_train, CLASS_NAMES)
    y_train_c = lc.compress(y_train)

    BENCH_N = 40_000
    if len(X_train_sc) > BENCH_N:
        _, Xs, _, ys = train_test_split(
            X_train_sc, y_train_c,
            test_size=BENCH_N/len(X_train_sc),
            stratify=y_train_c, random_state=42)
    else:
        Xs, ys = X_train_sc, y_train_c

    # SMOTE target = max REAL class count (per-class data dict)
    counts_bench = {i: int((ys == i).sum())
                    for i in range(lc.n_train_classes)}
    target_bench = max(counts_bench.values())
    strat_bench  = {i: max(target_bench, counts_bench[i])
                    for i in range(lc.n_train_classes) if counts_bench[i] > 0}

    strategies = {
        "SMOTE"           : SMOTE(random_state=42, k_neighbors=5,
                                  sampling_strategy=strat_bench),
        "BorderlineSMOTE" : BorderlineSMOTE(random_state=42, k_neighbors=5,
                                            sampling_strategy=strat_bench),
        "ADASYN"          : ADASYN(random_state=42, n_neighbors=5,
                                   sampling_strategy=strat_bench),
    }
    proxy = RandomForestClassifier(n_estimators=30, max_depth=8,
                                   n_jobs=-1, random_state=42)
    results = {}
    f1_avg  = _f1_average(lc.n_train_classes)

    for name, sampler in strategies.items():
        print(f"\n  ▶ {name} (5-fold CV — sampler cloned per fold):")
        try:
            cv_result = resampled_cv_score(
                np.asarray(Xs), np.asarray(ys),
                estimator=proxy,
                sampler=sampler,
                n_splits=5,
                scoring="f1",
                average=f1_avg,
                verbose=True,
            )
            results[name] = cv_result["mean"]
        except Exception as exc:
            print(f"    [WARN] {name} failed: {exc}")

    if not results:
        print("[WARN] All resamplers failed — using raw training data.")
        return "None", X_train_sc, y_train_c, lc

    best_name = max(results, key=results.get)
    print(f"\n[RESULT] Best: {best_name}  (Mean CV Macro-F1={results[best_name]:.4f})")
    _plot_benchmark(results)

    print(f"\n[INFO] Applying {best_name} to full training set...")
    try:
        # SMOTE target = = max real class count (based on full training data)
        counts = {i: int((y_train_c == i).sum()) for i in range(lc.n_train_classes)}
        target_per_class = max(counts.values())
        strat = {i: max(target_per_class, counts[i])
                 for i in range(lc.n_train_classes) if counts[i] > 0}

        print(f"\n  Real-data class counts (compressed):")
        for comp_i, orig_i in lc.comp_to_orig.items():
            print(f"    {CLASS_NAMES[orig_i]:<25} {counts[comp_i]:>9,}  "
                  f"({'TARGET' if counts[comp_i] == target_per_class else 'will up-sample'})")
        print(f"\n  SMOTE target per class: {target_per_class:,}  "
              f"(= max real class count)")

        # Build a fresh sampler with the final sampling_strategy.
        SamplerCls = type(strategies[best_name])
        final_params = {**strategies[best_name].get_params(),
                        "sampling_strategy": strat}
        sampler_final = SamplerCls(**final_params)
        X_res, y_res_c = sampler_final.fit_resample(X_train_sc, y_train_c)
        y_res_c = y_res_c.astype(np.int8)

        print(f"\n[INFO] After {best_name} — class counts (compressed):")
        for comp_i, orig_i in lc.comp_to_orig.items():
            n_real = counts[comp_i]
            n_now  = int((y_res_c == comp_i).sum())
            n_synth = max(n_now - n_real, 0)
            synth_pct = 100 * n_synth / max(n_now, 1)
            note = f"({n_real:,} real + {n_synth:,} synth = {synth_pct:.1f}% synth)"
            print(f"    {CLASS_NAMES[orig_i]:<25} {n_now:>9,}  {note}")

        new_counts = [int((y_res_c==i).sum()) for i in range(lc.n_train_classes)]
        new_ratio  = max(new_counts) / max(min(new_counts), 1)
        print(f"\n[INFO] Post-SMOTE imbalance ratio: {new_ratio:.2f}:1  "
              f"({'✓ balanced' if new_ratio < 2 else '⚠ still imbalanced'})")
    except Exception as exc:
        print(f"[WARN] Resample failed ({exc}) — using raw compressed data.")
        X_res, y_res_c = X_train_sc, y_train_c.copy()

    return best_name, X_res, y_res_c, lc


def _plot_benchmark(results):
    fig, ax = plt.subplots(figsize=(9, 5.5))
    colors  = [PAL_RF, PAL_ENS, PAL_XGB]
    bars    = ax.bar(list(results.keys()), list(results.values()),
                     color=colors[:len(results)], width=0.5, alpha=0.9)
    y_max = max(results.values()); y_min = min(results.values())
    ax.set_ylim(max(0, y_min - 0.05), min(1.05, y_max + 0.08))
    ax.set_title("Imbalance Strategy Benchmark\n"
                 "(Proxy RF — 5-Fold CV Mean Macro-F1)",
                 **TITLE_KWARGS)
    ax.set_ylabel("Mean Macro-F1 Score")
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
#  PART 5B — HYPERPARAMETER TUNING
# ============================================================

def _get_tune_sample(X_res, y_res, n=OPTUNA_SUBSAMPLE):
    if len(X_res) <= n:
        return X_res, y_res
    sss = StratifiedShuffleSplit(n_splits=1, train_size=n, random_state=42)
    idx, _ = next(sss.split(X_res, y_res))
    return X_res[idx], y_res[idx]


def tune_rf(X_res, y_res, lc):
    print("\n" + "="*60)
    print(f"  TUNING — Random Forest  ({OPTUNA_TRIALS_RF} trials | 5-fold CV)")
    print("="*60)
    Xs, ys = _get_tune_sample(X_res, y_res)
    cv     = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    f1_avg = _f1_average(lc.n_train_classes)

    def objective(trial):
        params = {
            "n_estimators"     : trial.suggest_int("n_estimators", 100, 500),
            "max_depth"        : trial.suggest_int("max_depth", 10, 30),
            "min_samples_split": trial.suggest_int("min_samples_split", 2, 10),
            "min_samples_leaf" : trial.suggest_int("min_samples_leaf", 1, 5),
            "max_features"     : trial.suggest_categorical(
                                     "max_features", ["sqrt", "log2", 0.3, 0.5]),
            "class_weight": None, "n_jobs": -1, "random_state": 42,
        }
        model = RandomForestClassifier(**params)
        scores = []
        for tri, vli in cv.split(Xs, ys):
            model.fit(Xs[tri], ys[tri])
            scores.append(f1_score(ys[vli], model.predict(Xs[vli]),
                                   average=f1_avg, zero_division=0))
        return np.mean(scores)

    study = optuna.create_study(direction="maximize",
                                sampler=optuna.samplers.TPESampler(seed=42))
    study.optimize(objective, n_trials=OPTUNA_TRIALS_RF, show_progress_bar=True)
    best = study.best_params
    print(f"\n[TUNE-RF] Best F1 ({f1_avg}): {study.best_value:.4f}  Params: {best}")
    return best


def tune_xgb(X_res, y_res, lc):
    print("\n" + "="*60)
    print(f"  TUNING — XGBoost  ({OPTUNA_TRIALS_XGB} trials | internal val)")
    obj_info = _xgb_objective_params(lc.n_train_classes)
    print(f"  objective = {obj_info['objective']}  (n_train_classes={lc.n_train_classes})")
    print("="*60)
    Xs, ys = _get_tune_sample(X_res, y_res)
    Xt, Xv, yt, yv = train_test_split(Xs, ys, test_size=0.10,
                                       stratify=ys, random_state=42)
    f1_avg = _f1_average(lc.n_train_classes)

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
            "early_stopping_rounds": 30,
            "tree_method": "hist", "device": XGB_DEVICE,
            "random_state": 42, "verbosity": 0,
        }
        params.update(obj_info)
        model = xgb.XGBClassifier(**params)
        model.fit(Xt, yt, eval_set=[(Xv, yv)], verbose=False)
        return f1_score(yv, model.predict(Xv), average=f1_avg, zero_division=0)

    study = optuna.create_study(direction="maximize",
                                sampler=optuna.samplers.TPESampler(seed=42))
    study.optimize(objective, n_trials=OPTUNA_TRIALS_XGB, show_progress_bar=True)
    best = study.best_params
    best.pop("early_stopping_rounds", None)
    print(f"\n[TUNE-XGB] Best F1 ({f1_avg}): {study.best_value:.4f}  Params: {best}")
    return best


# ============================================================
#  SHARED — Metrics & Confusion Matrix
# ============================================================

def compute_metrics(name, y_true, y_pred, y_prob=None, present_classes=None):
    if present_classes is None:
        present_classes = list(range(N_CLASSES))

    acc  = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, average="macro",
                           zero_division=0, labels=present_classes)
    rec  = recall_score(y_true, y_pred, average="macro",
                        zero_division=0, labels=present_classes)
    f1   = f1_score(y_true, y_pred, average="macro",
                    zero_division=0, labels=present_classes)
    per_f1  = f1_score(y_true, y_pred, average=None, zero_division=0,
                       labels=list(range(N_CLASSES)))
    per_rec = recall_score(y_true, y_pred, average=None, zero_division=0,
                           labels=list(range(N_CLASSES)))
    per_pre = precision_score(y_true, y_pred, average=None, zero_division=0,
                              labels=list(range(N_CLASSES)))

    auc, pr_auc = float("nan"), float("nan")
    try:
        if y_prob is not None and len(np.unique(y_true)) > 1:
            y_bin_present = label_binarize(y_true, classes=present_classes)
            prob_present  = y_prob[:, present_classes]
            if y_bin_present.shape[1] > 1:
                auc    = roc_auc_score(y_bin_present, prob_present,
                                       average="macro", multi_class="ovr")
                pr_auc = average_precision_score(y_bin_present, prob_present,
                                                  average="macro")
    except Exception as exc:
        print(f"  [WARN] AUC computation failed: {exc}")

    print(f"\n{'─'*60}")
    print(f"  {name}  —  Test Set Results")
    print(f"{'─'*60}")
    print(f"  Accuracy        : {acc*100:.2f}%  {'✓' if acc >= TARGET_ACCURACY else '✗'}")
    print(f"  Macro Precision : {prec*100:.2f}%")
    print(f"  Macro Recall    : {rec*100:.2f}%")
    print(f"  Macro F1        : {f1*100:.2f}%  "
          f"{'✓' if f1 >= TARGET_MACRO_F1 else f'✗ — below {TARGET_MACRO_F1*100:.0f}%'}")
    print(f"  ROC-AUC (OvR)   : {auc:.4f}")
    print(f"  PR-AUC  (macro) : {pr_auc:.4f}")
    print(f"\n  Per-class results:")
    print(f"  {'Class':<25} {'Precision':>10} {'Recall':>8} {'F1':>8}")
    print(f"  {'─'*55}")
    for i, cls in enumerate(CLASS_NAMES):
        f1_i  = per_f1[i]  if i < len(per_f1)  else 0.0
        rec_i = per_rec[i] if i < len(per_rec) else 0.0
        pre_i = per_pre[i] if i < len(per_pre) else 0.0
        note  = ("LOW" if rec_i < 0.80 else "") if i in present_classes \
                else "  (not in y_true)"
        print(f"  {cls:<25} {pre_i*100:>9.2f}%  {rec_i*100:>7.2f}%  {f1_i*100:>7.2f}%{note}")
    print()
    print(classification_report(y_true, y_pred, labels=list(range(N_CLASSES)),
                                target_names=CLASS_NAMES, zero_division=0))

    result = {"name": name, "accuracy": acc, "precision": prec,
              "recall": rec, "f1": f1, "roc_auc": auc, "pr_auc": pr_auc}
    for i, cls in enumerate(CLASS_NAMES):
        result[f"{cls}_f1"]        = float(per_f1[i])  if i < len(per_f1)  else 0.0
        result[f"{cls}_recall"]    = float(per_rec[i]) if i < len(per_rec) else 0.0
        result[f"{cls}_precision"] = float(per_pre[i]) if i < len(per_pre) else 0.0
    return result


def plot_cm(y_true, y_pred, model_name, filename):
    cm      = confusion_matrix(y_true, y_pred, labels=list(range(N_CLASSES)))
    row_sum = cm.sum(axis=1, keepdims=True)
    cm_norm = np.divide(cm.astype(float), row_sum,
                        out=np.zeros_like(cm, dtype=float), where=row_sum > 0)
    short_names = [n.replace("_", "\n") for n in CLASS_NAMES]

    fig, axes = plt.subplots(1, 2, figsize=(16, 6))
    for ax, data, fmt, suffix in [
        (axes[0], cm,      "d",    "Raw Counts"),
        (axes[1], cm_norm, ".2f",  "Normalised (Row %)"),
    ]:
        sns.heatmap(data, annot=True, fmt=fmt, cmap="Blues", ax=ax,
                    xticklabels=short_names, yticklabels=short_names,
                    cbar_kws={"pad": 0.03, "shrink": 0.85},
                    linewidths=0.5, linecolor="white")
        ax.set_title(f"{model_name}\n{suffix}", pad=12, **TITLE_KWARGS)
        ax.set_ylabel("Actual Tier", fontsize=10, fontweight="bold")
        ax.set_xlabel("Predicted Tier", fontsize=10, fontweight="bold")
        ax.tick_params(axis="x", rotation=20, labelsize=9)
        ax.tick_params(axis="y", rotation=0,  labelsize=9)

    fig.suptitle(f"Confusion Matrix — {model_name}",
                 fontsize=13, **TITLE_KWARGS, y=1.01)
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, filename),
                dpi=150, bbox_inches="tight")
    plt.close()
    print(f"[GRAPH] {filename} saved.")


# ============================================================
#  PART 5C — LOGISTIC REGRESSION BASELINE
# ============================================================

def train_lr_baseline(X_res, y_res, X_test, y_test, scaler, lc):
    print("\n" + "="*60)
    print("  LOGISTIC REGRESSION BASELINE (linear separability diagnostic)")
    print(f"  Warning fires if LR within {LR_DIAGNOSTIC_GAP_PP}pp of best tree model")
    print("="*60)
    lr = LogisticRegression(max_iter=2000, solver="lbfgs",
                            n_jobs=-1, random_state=42)
    print("[INFO] Training LR...")
    t = time.time()
    lr.fit(X_res, y_res)
    print(f"[INFO] Done in {time.time()-t:.1f}s")
    X_test_sc = scaler.transform(X_test)
    y_pred_c  = lr.predict(X_test_sc).astype(np.int8)
    y_prob_c  = lr.predict_proba(X_test_sc)
    y_pred = lc.expand(y_pred_c)
    y_prob = lc.expand_proba(y_prob_c, N_CLASSES)
    metrics = compute_metrics("LR Baseline", y_test, y_pred, y_prob,
                              present_classes=lc.present_orig_indices)
    return lr, metrics


# ============================================================
#  PART 6 — RANDOM FOREST
# ============================================================

def train_rf(X_res, y_res, X_test, y_test, scaler,
             feature_names, lc, best_params=None):
    print("\n" + "="*60)
    print(f"  RANDOM FOREST  ({lc.n_train_classes}-Class, compressed labels)")
    print("="*60)
    params = best_params.copy() if best_params else {
        "n_estimators": 200, "max_depth": 20,
        "min_samples_split": 5, "min_samples_leaf": 2, "max_features": "sqrt",
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
    y_pred_c  = rf.predict(X_test_sc).astype(np.int8)
    y_prob_c  = rf.predict_proba(X_test_sc)
    y_pred = lc.expand(y_pred_c)
    y_prob = lc.expand_proba(y_prob_c, N_CLASSES)
    metrics = compute_metrics("Random Forest", y_test, y_pred, y_prob,
                              present_classes=lc.present_orig_indices)
    plot_cm(y_test, y_pred, "Random Forest", "2a_cm_rf.png")

    imp = rf.feature_importances_
    idx = np.argsort(imp)
    fig, ax = plt.subplots(figsize=(11, 6.5))
    ax.barh(range(len(feature_names)), imp[idx],
            color="#1565C0", alpha=0.85, edgecolor="white")
    ax.set_yticks(range(len(feature_names)))
    ax.set_yticklabels([feature_names[i] for i in idx], fontsize=10)
    ax.set_xlabel("Feature Importance (Gini impurity decrease)", fontsize=11)
    ax.set_title(
        f"Feature Importance — Random Forest\n"
        f"Phase 2: {len(feature_names)} Behaviour-based features",
        **TITLE_KWARGS)
    for i, v in enumerate(imp[idx]):
        ax.text(v + 0.001, i, f"{v:.4f}", va="center", fontsize=8.5)
    ax.spines[["top", "right"]].set_visible(False)
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, "3_feature_importance_rf.png"),
                dpi=150, bbox_inches="tight")
    plt.close()
    print("[GRAPH] 3_feature_importance_rf.png saved.")
    return rf, metrics, y_pred, y_prob


# ============================================================
#  PART 7 — XGBOOST
# ============================================================

def train_xgb(X_res, y_res, X_test, y_test, scaler, lc, best_params=None):
    print("\n" + "="*60)
    print(f"  XGBOOST  ({lc.n_train_classes}-Class — multi:softprob, compressed)")
    print("="*60)
    X_tr, X_val_int, y_tr, y_val_int = train_test_split(
        X_res, y_res, test_size=XGB_INTERNAL_VAL,
        stratify=y_res, random_state=42)
    default = {
        "n_estimators": 600, "max_depth": 8, "learning_rate": 0.05,
        "subsample": 0.8, "colsample_bytree": 0.8, "min_child_weight": 3,
        "gamma": 0.1, "reg_alpha": 0.5, "reg_lambda": 1.0,
    }
    params = best_params.copy() if best_params else default
    obj_info = _xgb_objective_params(lc.n_train_classes)
    params.update({**obj_info, "early_stopping_rounds": 30,
                   "tree_method": "hist", "device": XGB_DEVICE,
                   "random_state": 42, "verbosity": 0})
    clf = xgb.XGBClassifier(**params)
    print(f"[INFO] Device: {XGB_DEVICE.upper()} | Training...")
    t = time.time()
    clf.fit(X_tr, y_tr, eval_set=[(X_val_int, y_val_int)], verbose=50)
    print(f"[INFO] Done in {time.time()-t:.1f}s  |  Best iter: {clf.best_iteration}")
    X_test_sc = scaler.transform(X_test)
    y_prob_c  = clf.predict_proba(X_test_sc)
    y_pred_c  = clf.predict(X_test_sc).astype(np.int8)
    y_pred = lc.expand(y_pred_c)
    y_prob = lc.expand_proba(y_prob_c, N_CLASSES)
    metrics = compute_metrics("XGBoost", y_test, y_pred, y_prob,
                              present_classes=lc.present_orig_indices)
    plot_cm(y_test, y_pred, "XGBoost", "2b_cm_xgb.png")
    return clf, metrics, y_pred, y_prob


# ============================================================
#  PART 8 — ENSEMBLE
# ============================================================

def build_ensemble_predictions(rf_prob, xgb_prob, y_test, lc):
    w_rf, w_xgb = ENSEMBLE_WEIGHTS
    print("\n" + "="*60)
    print(f"  ENSEMBLE  (RF={w_rf} + XGB={w_xgb}, soft-vote)")
    print("="*60)
    ens_prob = w_rf * rf_prob + w_xgb * xgb_prob
    y_pred   = np.argmax(ens_prob, axis=1).astype(np.int8)
    metrics  = compute_metrics("Ensemble (RF + XGB)", y_test, y_pred, ens_prob,
                               present_classes=lc.present_orig_indices)
    plot_cm(y_test, y_pred, "Ensemble (RF + XGB)", "2c_cm_ensemble.png")
    return metrics, y_pred, ens_prob


# ============================================================
#  PART 9 — CONFIDENCE CALIBRATION  (alpha=0.5)
# ============================================================

def calibrate_confidence(ensemble, X_calib_sc, y_calib, lc):
    print("\n" + "="*60)
    print("  CONFIDENCE CALIBRATION  (coverage-aware sweep)")
    print(f"  Score = MacroF1 × (1 - {COVERAGE_PENALTY_ALPHA}·uncertain_frac)")
    print(f"  alpha={COVERAGE_PENALTY_ALPHA} (back to standard, was 0.7)")
    print("="*60)
    present = lc.present_orig_indices
    proba   = ensemble.predict_proba(X_calib_sc)
    sweep   = np.round(np.arange(0.50, 0.99, 0.01), 3)
    best_score = -1.0; best_conf = CONFIDENCE_MIN
    results = []

    for conf in sweep:
        max_probs = proba.max(axis=1)
        mask      = max_probs >= conf
        if mask.sum() < 10:
            continue
        preds    = np.argmax(proba, axis=1)
        macro_f1 = f1_score(y_calib[mask], preds[mask],
                            average=_f1_average(len(present)),
                            zero_division=0, labels=present)
        uncertain_frac = (~mask).sum() / len(mask)
        combined = macro_f1 * (1.0 - COVERAGE_PENALTY_ALPHA * uncertain_frac)
        results.append((conf, macro_f1, 100*uncertain_frac, combined))
        if combined > best_score:
            best_score = combined; best_conf = conf

    if not results:
        print("[WARN] Sweep produced no usable thresholds — keeping default.")
        return CONFIDENCE_MIN

    best_row = next((r for r in results if abs(r[0] - best_conf) < 0.001), None)
    if best_row:
        print(f"\n  Best confidence_min : {best_conf:.3f}")
        print(f"  Macro-F1 (classified) = {best_row[1]:.4f}")
        print(f"  Uncertain (routed to Phase 3)  = {best_row[2]:.1f}%")
        print(f"  Coverage-aware score  = {best_row[3]:.4f}")

    confs    = [r[0] for r in results]
    mac_f1s  = [r[1]*100 for r in results]
    unc_pcts = [r[2] for r in results]
    combos   = [r[3]*100 for r in results]

    fig, axes = plt.subplots(1, 3, figsize=(18, 5.5))
    axes[0].plot(confs, mac_f1s, color=PAL_RF, lw=2)
    axes[0].axvline(best_conf, color="green", ls="--", lw=1.5,
                    label=f"Best={best_conf:.3f}")
    axes[0].axhline(90, color="red", ls=":", lw=1.2, label="90% target")
    axes[0].set_xlabel("Confidence Min"); axes[0].set_ylabel("Macro F1 (%)")
    axes[0].set_title("Macro F1 vs Threshold", **TITLE_KWARGS)
    axes[0].legend(fontsize=9); axes[0].set_ylim(0, 105)

    axes[1].plot(confs, unc_pcts, color=PAL_XGB, lw=2)
    axes[1].axvline(best_conf, color="green", ls="--", lw=1.5,
                    label=f"Best={best_conf:.3f}")
    axes[1].set_xlabel("Confidence Min"); axes[1].set_ylabel("% Flows = route to Phase 3 RF + OSR")
    axes[1].set_title("Uncertain Routing Volume", **TITLE_KWARGS)
    axes[1].legend(fontsize=9); axes[1].set_ylim(0, 105)

    axes[2].plot(confs, combos, color=PAL_ENS, lw=2)
    axes[2].axvline(best_conf, color="green", ls="--", lw=1.5,
                    label=f"Best={best_conf:.3f}")
    axes[2].set_xlabel("Confidence Min"); axes[2].set_ylabel("Coverage-aware Score (%)")
    axes[2].set_title(f"Combined Score (α={COVERAGE_PENALTY_ALPHA})", **TITLE_KWARGS)
    axes[2].legend(fontsize=9); axes[2].set_ylim(0, 105)

    plt.suptitle(f"Confidence Calibration — Phase 2 ({' vs '.join(CLASS_NAMES)})",
                 fontsize=12, **TITLE_KWARGS)
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, "4_confidence_calibration.png"),
                dpi=150, bbox_inches="tight")
    plt.close()
    print("[GRAPH] 4_confidence_calibration.png saved.")
    return float(best_conf)


# ============================================================
#  PART 10 — ROC CURVES
# ============================================================

def plot_roc(y_test, all_probs, lc):
    present = lc.present_orig_indices
    if len(present) < 2:
        print("[WARN] ROC skipped — fewer than 2 classes present.")
        return
    y_bin        = label_binarize(y_test, classes=present)
    model_colors = [PAL_RF, PAL_XGB, PAL_ENS]
    fig, axes    = plt.subplots(1, 2, figsize=(15, 6))

    ax = axes[0]
    for (name, prob), color in zip(all_probs.items(), model_colors):
        try:
            prob_present = prob[:, present]
            fpr, tpr, _ = roc_curve(y_bin.ravel(), prob_present.ravel())
            auc = roc_auc_score(y_bin, prob_present, average="macro", multi_class="ovr")
            ax.plot(fpr, tpr, color=color, lw=2, label=f"{name}  AUC={auc:.4f}")
        except Exception as exc:
            print(f"  [WARN] ROC skipped for {name}: {exc}")
    ax.plot([0, 1], [0, 1], "k--", lw=1, label="Random Classifier")
    ax.set_xlabel("False Positive Rate"); ax.set_ylabel("True Positive Rate")
    ax.set_title("ROC — Macro-OvR (all models)", **TITLE_KWARGS)
    ax.legend(loc="lower right", fontsize=8)
    ax.spines[["top", "right"]].set_visible(False)

    ax = axes[1]
    ens_name = "Ensemble (RF + XGB)"
    if ens_name in all_probs:
        prob = all_probs[ens_name]
        for i in present:
            try:
                y_bin_i = (y_test == i).astype(int)
                if y_bin_i.sum() == 0:
                    continue
                fpr_i, tpr_i, _ = roc_curve(y_bin_i, prob[:, i])
                auc_i = roc_auc_score(y_bin_i, prob[:, i])
                ax.plot(fpr_i, tpr_i, color=CLASS_COLORS[i], lw=1.8,
                        label=f"{CLASS_NAMES[i]}  AUC={auc_i:.4f}")
            except Exception:
                pass
    ax.plot([0, 1], [0, 1], "k--", lw=1, label="Random Classifier")
    ax.set_xlabel("False Positive Rate"); ax.set_ylabel("True Positive Rate")
    ax.set_title("ROC per Severity Tier — Ensemble", **TITLE_KWARGS)
    ax.legend(loc="lower right", fontsize=9)
    ax.spines[["top", "right"]].set_visible(False)

    plt.suptitle(f"ROC Curves — Phase 2 ({' vs '.join(CLASS_NAMES)})",
                 fontsize=12, **TITLE_KWARGS)
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, "4_roc_curves.png"),
                dpi=150, bbox_inches="tight")
    plt.close()
    print("[GRAPH] 4_roc_curves.png saved.")


# ============================================================
#  PART 11 — MODEL COMPARISON
# ============================================================

def plot_comparison(all_metrics, lc):
    df  = pd.DataFrame(all_metrics).set_index("name")
    mts = ["accuracy", "precision", "recall", "f1"]
    pct = df[[m for m in mts if m in df.columns]] * 100

    fig, ax = plt.subplots(figsize=(16, 8))
    x = np.arange(len(pct)); w = 0.20
    colors = [PAL_RF, PAL_ENS, PAL_XGB, "#E91E63"]
    labels = ["Accuracy", "Macro Precision", "Macro Recall", "Macro F1"]

    for i, (col, col_, lbl) in enumerate(zip(mts, colors, labels)):
        if col not in pct.columns:
            continue
        bar_offset = (i - (len(mts) - 1) / 2) * w
        bars = ax.bar(x + bar_offset, pct[col], w, label=lbl,
                      color=col_, alpha=0.85, edgecolor="white", linewidth=0.6)
        for bar in bars:
            h = bar.get_height()
            ax.text(bar.get_x() + bar.get_width() / 2,
                    h + 0.4,
                    f"{h:.2f}%", ha="center", va="bottom",
                    fontsize=8.5, fontweight="bold", color="#222")

    ax.axhline(TARGET_MACRO_F1 * 100, color="crimson", linestyle="--",
               lw=1.5, label=f"{TARGET_MACRO_F1*100:.0f}% Target", zorder=5)
    ax.set_xticks(x)
    ax.set_xticklabels(pct.index, fontsize=11, fontweight="bold")
    ax.set_ylim(0, 107)
    ax.set_ylabel("Score (%)", fontsize=11)
    ax.set_title(f"ThreatMatrix — Phase 2 Model Comparison \n"
                 f"{' / '.join(CLASS_NAMES)} | "
                 f"{N_FEATURES_EXPECTED}-Feature Protocol-Agnostic Schema",
                 fontsize=13, **TITLE_KWARGS, pad=14)
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


def plot_radar_comparison(all_metrics, lc):
    metrics_keys   = ["accuracy", "precision", "recall", "f1", "roc_auc", "pr_auc"]
    metrics_labels = ["Accuracy", "Macro Prec", "Macro Rec",
                      "Macro F1", "ROC-AUC*", "PR-AUC*"]
    model_names    = [m["name"] for m in all_metrics]
    model_colors   = [PAL_RF, PAL_XGB, PAL_ENS, PAL_LR, "#E53935"][:len(all_metrics)]

    def safe(v):
        return 0.0 if (v is None or (isinstance(v, float) and np.isnan(v))) else v * 100

    data    = np.array([[safe(m.get(k, 0)) for k in metrics_keys] for m in all_metrics])
    n_metrics = len(metrics_keys); n_models = len(all_metrics)
    x         = np.arange(n_metrics)
    total_w   = 0.72; bar_w = total_w / n_models
    offsets   = np.linspace(-total_w/2 + bar_w/2, total_w/2 - bar_w/2, n_models)

    fig, (ax, ax_table) = plt.subplots(
        2, 1, figsize=(17, 12),
        gridspec_kw={"height_ratios": [3, 1], "hspace": 0.45})
    ax_table.axis("off")

    for i, (name, color, row) in enumerate(zip(model_names, model_colors, data)):
        bars = ax.bar(x + offsets[i], row, bar_w, label=name, color=color,
                      alpha=0.88, edgecolor="white", linewidth=0.6)
        for bar, val in zip(bars, row):
            display = f"{val:.2f}%" if val > 0 else "nan"
            ax.text(bar.get_x() + bar.get_width() / 2,
                    bar.get_height() + 0.3,
                    display, ha="center", va="bottom",
                    fontsize=7.5, fontweight="bold", color="#222")

    ax.axhline(90, color="crimson", linestyle="--", lw=1.5, label="90% Target", zorder=5)
    ax.set_xticks(x)
    ax.set_xticklabels(metrics_labels, fontsize=12, fontweight="bold")
    ax.set_ylim(0, 107)
    ax.set_ylabel("Score (%)", fontsize=11)
    ax.set_title("ThreatMatrix — Phase 2 Full Metric Comparison\n"
                 f"{N_FEATURES_EXPECTED}-Feature Protocol-Agnostic Schema",
                 fontsize=13, **TITLE_KWARGS, pad=14)
    ax.yaxis.grid(True, linestyle=":", alpha=0.5, color="#aaaaaa")
    ax.set_axisbelow(True)
    ax.spines[["top", "right"]].set_visible(False)
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.07),
              ncol=n_models + 1, fontsize=10, frameon=True, edgecolor="#cccccc")

    def fmt(m, k):
        v = m.get(k, 0)
        if v is None or (isinstance(v, float) and np.isnan(v)):
            return "nan"
        return f"{v*100:.2f}%"

    table_data = [[fmt(m, k) for k in metrics_keys] for m in all_metrics]
    tbl = ax_table.table(
        cellText=table_data, rowLabels=model_names, colLabels=metrics_labels,
        cellLoc="center", rowLoc="right", loc="center",
        bbox=[0.05, 0.0, 0.90, 1.0])
    tbl.auto_set_font_size(False); tbl.set_fontsize(10); tbl.scale(1.0, 1.6)

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
#  PART 12 — CROSS-SUB-TYPE GENERALISATION
# ============================================================

def run_cross_subtype_generalization(ensemble, scaler, X_test, y_test, lc):
    print("\n" + "="*60)
    print("  PER-CLASS GENERALISATION (standard test set)")
    print("="*60)
    X_test_sc = scaler.transform(X_test)
    y_pred    = ensemble.predict(X_test_sc)
    per_pre = precision_score(y_test, y_pred, average=None, zero_division=0,
                              labels=list(range(N_CLASSES)))
    per_rec = recall_score(y_test, y_pred, average=None, zero_division=0,
                           labels=list(range(N_CLASSES)))
    per_f1  = f1_score(y_test, y_pred, average=None, zero_division=0,
                       labels=list(range(N_CLASSES)))

    results = {}; scenario_data = {}
    print(f"\n  {'Class':<25} {'N':>8} {'Precision':>11} {'Recall':>8} {'F1':>8}")
    print("  " + "─"*65)
    for i, cls in enumerate(CLASS_NAMES):
        n = int((y_test == i).sum())
        if n == 0:
            continue
        prec = float(per_pre[i]); rec = float(per_rec[i]); f1 = float(per_f1[i])
        note = "  ⚠ LOW" if rec < 0.80 else ""
        print(f"  {cls:<25} {n:>8,} {prec*100:>10.2f}% {rec*100:>7.2f}% "
              f"{f1*100:>7.2f}%{note}")
        results[cls]       = {"n": n, "precision": prec, "recall": rec, "f1": f1}
        scenario_data[cls] = {"precision": prec*100, "recall": rec*100,
                              "f1": f1*100, "n": n}

    _plot_cross_subtype(scenario_data, lc)
    return results


def _plot_cross_subtype(scenario_data, lc):
    if not scenario_data:
        return
    classes = list(scenario_data.keys())
    f1s     = [scenario_data[c]["f1"]        for c in classes]
    recs    = [scenario_data[c]["recall"]    for c in classes]
    precs   = [scenario_data[c]["precision"] for c in classes]
    counts  = [scenario_data[c]["n"]         for c in classes]
    display_labels = [f"{c}\n(n={n:,})" for c, n in zip(classes, counts)]

    x = np.arange(len(classes)); w = 0.25
    fig, ax = plt.subplots(figsize=(14, 8))
    bar_colors = [CLASS_COLORS[CLASS_NAMES.index(c)]
                  if c in CLASS_NAMES else "#9E9E9E" for c in classes]

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
            if val > 1:
                ax.text(x[i] + offset, label_y,
                        f"{val:.2f}%", ha="center", va="bottom",
                        fontsize=9, fontweight="bold", color="#333")

    absent_names = [CLASS_NAMES[i] for i in range(N_CLASSES)
                    if i not in lc.present_orig_indices]
    absent_note  = f"\n(absent: {absent_names})" if absent_names else ""

    ax.axhline(90, color="crimson", linestyle="--", lw=1.5, zorder=5)
    ax.set_xticks(x)
    ax.set_xticklabels(display_labels, rotation=20, ha="right", fontsize=10)
    ax.set_ylim(0, 128)
    ax.set_ylabel("Score (%)", fontsize=11)
    ax.set_title(f"Per-Class Generalisation — Ensemble (RF + XGB)\n"
                 f"Phase 2: {' vs '.join(CLASS_NAMES)}{absent_note}",
                 **TITLE_KWARGS, pad=12)
    ax.yaxis.grid(True, linestyle=":", alpha=0.5)
    ax.set_axisbelow(True)
    ax.spines[["top", "right"]].set_visible(False)

    tier_patches = [mpatches.Patch(color=CLASS_COLORS[i], alpha=0.85,
                                   label=CLASS_NAMES[i]) for i in range(N_CLASSES)]
    metric_patches = [
        mpatches.Patch(facecolor="grey", hatch="///", edgecolor="white",
                       alpha=0.85, label="Precision"),
        mpatches.Patch(facecolor="grey", hatch="...", edgecolor="white",
                       alpha=0.85, label="Recall"),
        mpatches.Patch(facecolor="grey", hatch="",   edgecolor="white",
                       alpha=0.85, label="F1-Score"),
        plt.Line2D([0], [0], color="crimson", linestyle="--", lw=1.5, label="90% target"),
    ]
    fig.legend(handles=tier_patches + metric_patches,
               loc="lower center",
               bbox_to_anchor=(0.5, -0.01),
               ncol=7, fontsize=9, frameon=True, edgecolor="#cccccc",
               title="Severity Tier / Metric",
               title_fontsize=9)

    plt.subplots_adjust(left=0.09, right=0.97, top=0.90, bottom=0.28)
    plt.savefig(os.path.join(OUTPUT_DIR, "5b_cross_subtype_generalization.png"),
                dpi=150, bbox_inches="tight")
    plt.close()
    print("[GRAPH] 5b_cross_subtype_generalization.png saved.")

    


# ============================================================
#  PART 12B — PROTOCOL HOLDOUT EVALUATION (HTTP vs HTTPS)
# ============================================================

def run_protocol_holdout_evaluation(ensemble, scaler, test_source_files, X_test, y_test, lc):
    print("\n" + "="*60)
    print("  PROTOCOL HOLDOUT EVALUATION (HTTP vs HTTPS)")
    print("="*60)
    
    X_test_sc = scaler.transform(X_test)
    y_pred    = ensemble.predict(X_test_sc)
    
    target_evals = {
        "web-ids23_bruteforce_http.csv": ("Credential_Abuse", "HTTP"),
        "web-ids23_bruteforce_https.csv": ("Credential_Abuse", "HTTPS"),
        "web-ids23_sql_injection_http.csv": ("Active_Exploitation", "HTTP"),
        "web-ids23_sql_injection_https.csv": ("Active_Exploitation", "HTTPS"),
    }
    
    results = []
    for src, (tier, proto) in target_evals.items():
        if tier not in CLASS_NAMES:
            continue
            
        tier_idx = CLASS_NAMES.index(tier)
        mask = (test_source_files == src)
        n = mask.sum()
        
        if n > 0:
            y_true_sub = y_test[mask]
            y_pred_sub = y_pred[mask]
            
            # Using micro average on the isolated label calculates true subset metrics
            prec = precision_score(y_true_sub, y_pred_sub, labels=[tier_idx], average="micro", zero_division=0)
            rec  = recall_score(y_true_sub, y_pred_sub, labels=[tier_idx], average="micro", zero_division=0)
            f1   = f1_score(y_true_sub, y_pred_sub, labels=[tier_idx], average="micro", zero_division=0)
            
            results.append({
                "tier": tier,
                "protocol": proto,
                "precision": float(prec),
                "recall": float(rec),
                "f1": float(f1),
                "n": int(n)
            })
            print(f"  {tier:<22} {proto:<7} n={n:>7,}  recall={rec*100:.2f}%")
            
    _plot_protocol_holdout(results)
    return results

def _plot_protocol_holdout(results):
    if not results:
        return

    labels     = [f"{r['tier'].replace('_',' ')}\n{r['protocol']}" for r in results]
    recalls    = [r["recall"]    * 100 for r in results]
    precisions = [r["precision"] * 100 for r in results]
    f1s        = [r["f1"]        * 100 for r in results]
    tier_colors = [CLASS_COLORS[CLASS_NAMES.index(r["tier"])]
                   if r["tier"] in CLASS_NAMES else "#9E9E9E" for r in results]

    x = np.arange(len(results)); w = 0.25
    fig, ax = plt.subplots(figsize=(max(10, len(results)*2.5), 7))

    ax.bar(x - w, precisions, w, color=tier_colors, alpha=0.85,
           hatch="///", edgecolor="white", linewidth=0.8, label="Precision")
    ax.bar(x,     recalls,   w, color=tier_colors, alpha=0.85,
           hatch="...", edgecolor="white", linewidth=0.8, label="Recall")
    ax.bar(x + w, f1s,       w, color=tier_colors, alpha=0.85,
           hatch="",    edgecolor="white", linewidth=0.8, label="F1-Score")

    for i, (p, r, f) in enumerate(zip(precisions, recalls, f1s)):
        group_max = max(p, r, f)
        label_y   = group_max + 1.5
        for offset, val in [(-w, p), (0, r), (w, f)]:
            if val > 1:
                ax.text(x[i] + offset, label_y, f"{val:.2f}%",
                        ha="center", va="bottom", fontsize=9,
                        fontweight="bold", color="#333")

    ax.axhline(85, color="crimson", linestyle="--", lw=1.5,
               label="85% behaviour threshold", zorder=5)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=10, ha="center")
    ax.set_ylim(0, 128)
    ax.set_ylabel("Score (%)", fontsize=11)
    ax.set_title(
        "Protocol Holdout — Full Ensemble, Test Set Evaluation\n"
        "HTTP-only vs HTTPS-only subsets from test split\n"
        f"{N_FEATURES_EXPECTED} protocol-agnostic features",
        **TITLE_KWARGS, pad=12)
    ax.yaxis.grid(True, linestyle=":", alpha=0.5)
    ax.set_axisbelow(True)
    ax.spines[["top", "right"]].set_visible(False)

    tier_patches = [mpatches.Patch(color=CLASS_COLORS[i], alpha=0.85,
                                   label=CLASS_NAMES[i])
                    for i in range(N_CLASSES) if CLASS_NAMES[i] != "Reconnaissance"]
    metric_patches = [
        mpatches.Patch(facecolor="grey", hatch="///", edgecolor="white",
                       alpha=0.85, label="Precision"),
        mpatches.Patch(facecolor="grey", hatch="...", edgecolor="white",
                       alpha=0.85, label="Recall"),
        mpatches.Patch(facecolor="grey", hatch="",   edgecolor="white",
                       alpha=0.85, label="F1-Score"),
        plt.Line2D([0], [0], color="crimson", linestyle="--", lw=1.5,
                   label="85% threshold"),
    ]
    fig.legend(handles=tier_patches + metric_patches,
               loc="lower center", bbox_to_anchor=(0.5, -0.01),
               ncol=6, fontsize=9, frameon=True, edgecolor="#cccccc")
    plt.subplots_adjust(left=0.09, right=0.97, top=0.88, bottom=0.22)
    plt.savefig(os.path.join(OUTPUT_DIR, "5g_protocol_holdout.png"),
                dpi=150, bbox_inches="tight")
    plt.close()
    print("[GRAPH] 5g_protocol_holdout.png saved.")


# ============================================================
#  PART 13 — CONFIDENCE ROUTING ANALYSIS
# ============================================================

def run_confidence_routing_analysis(ensemble, scaler, X_test, y_test):
    print("\n" + "="*60)
    print("  CONFIDENCE-BASED ROUTING ANALYSIS")
    print(f"  confidence_min={ensemble.confidence_min:.3f} Phase 3 RF + OSR (novel-attack rejection)")
    print("="*60)
    X_test_sc     = scaler.transform(X_test)
    routes, probs = ensemble.confidence_route(X_test_sc)
    routes        = np.array(routes)
    route_labels  = CLASS_NAMES + ["UNCERTAIN"]
    print(f"\n  Overall routing distribution ({len(routes):,} test flows):")
    routing_stats = {}
    for rl in route_labels:
        n   = int((routes == rl).sum())
        pct = 100 * n / max(len(routes), 1)
        routing_stats[rl] = {"n": n, "pct": pct}
        print(f"    {rl:<25} {n:>8,}  ({pct:.2f}%)")

    uncertain_pct = routing_stats.get("UNCERTAIN", {}).get("pct", 0)
    if uncertain_pct < 0.5:
        print(f"\n PHASE 3 VOLUME WARNING: Only {uncertain_pct:.2f}% of flows "
              f"routed to Phase 3 RF + OSR.")
    else:
        print(f"\n  ✓ Phase 3 RF + OSR receives {uncertain_pct:.2f}% of flows — adequate volume.")

    _plot_confidence_routing(routing_stats, probs, y_test, ensemble.confidence_min)
    return routing_stats


def _plot_confidence_routing(routing_stats, probs, y_true, confidence_min):
    fig, axes = plt.subplots(1, 2, figsize=(16, 6.5))
    ax = axes[0]
    labels = list(routing_stats.keys())
    sizes  = [routing_stats[l]["n"] for l in labels]
    colors = CLASS_COLORS + ["#9E9E9E"]
    bars   = ax.bar(labels, sizes, color=colors[:len(labels)], alpha=0.88, width=0.55)
    total  = max(sum(sizes), 1)
    for bar, n in zip(bars, sizes):
        pct = 100 * n / total
        ax.text(bar.get_x() + bar.get_width()/2,
                bar.get_height() + total*0.010,
                f"{n:,}\n({pct:.2f}%)", ha="center", va="bottom",
                fontsize=10, fontweight="bold")
    ax.set_ylim(0, max(sizes) * 1.22 if max(sizes) > 0 else 1)
    ax.set_title(f"Pipeline Routing Distribution\n"
                 f"confidence_min = {confidence_min:.2f}", **TITLE_KWARGS)
    ax.set_ylabel("Number of Flows")
    xlabels = [f"{c}" for c in CLASS_NAMES] + ["→ UNCERTAIN\n(Phase 3 RF + OSR)"]
    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(xlabels, fontsize=9, rotation=15, ha="right")
    ax.spines[["top", "right"]].set_visible(False)

    ax2 = axes[1]
    for i, cls in enumerate(CLASS_NAMES):
        mask = (y_true == i)
        if mask.sum() == 0:
            continue
        ax2.hist(probs[mask], bins=60, alpha=0.55, color=CLASS_COLORS[i],
                 label=cls, density=True)
    ax2.axvline(confidence_min, color="orange", linestyle="--", lw=2,
                label=f"confidence_min={confidence_min:.2f}")
    ax2.axvspan(0, confidence_min, alpha=0.10, color="orange",
                label="Uncertain = Phase 3 RF + OSR")
    ax2.set_xlabel("Max Class Probability"); ax2.set_ylabel("Density")
    ax2.set_title("Max-Probability Distribution per Severity Tier", **TITLE_KWARGS)
    ax2.legend(loc="upper center", bbox_to_anchor=(0.5, -0.18),
               fontsize=9, ncol=2, frameon=True)
    ax2.spines[["top", "right"]].set_visible(False)

    plt.suptitle("Confidence Routing — ThreatMatrix Pipeline\n"
                 "Uncertain flows = Route to Phase 3 RF + OSR (novel-attack rejection)", fontsize=12, **TITLE_KWARGS)
    plt.tight_layout()
    plt.savefig(os.path.join(OUTPUT_DIR, "6_confidence_routing_analysis.png"),
                dpi=150, bbox_inches="tight")
    plt.close()
    print("[GRAPH] 6_confidence_routing_analysis.png saved.")

# ============================================================
#  PART 14 — PER-MODEL CLASS COMPARISON 
# ============================================================

def run_per_subtype_model_comparison(rf, xgb_clf, ensemble_model,
                                      scaler, X_test, y_test, feature_names):
    print("\n" + "="*60)
    print("  PER-CLASS MODEL COMPARISON (RF vs XGB vs Ensemble)")
    print("="*60)
    X_test_sc = scaler.transform(X_test)
    rf_pred   = rf.predict(X_test_sc).astype(np.int8)
    xgb_pred  = xgb_clf.predict(X_test_sc).astype(np.int8)
    ens_pred  = ensemble_model.predict(X_test_sc)

    model_results = {"Random Forest": {}, "XGBoost": {}, "Ensemble": {}}
    for model_name, y_pred in [
        ("Random Forest", rf_pred), ("XGBoost", xgb_pred), ("Ensemble", ens_pred)]:
        per_pre = precision_score(y_test, y_pred, average=None, zero_division=0,
                                  labels=list(range(N_CLASSES)))
        per_rec = recall_score(y_test, y_pred, average=None, zero_division=0,
                               labels=list(range(N_CLASSES)))
        per_f1  = f1_score(y_test, y_pred, average=None, zero_division=0,
                           labels=list(range(N_CLASSES)))
        for i, cls in enumerate(CLASS_NAMES):
            model_results[model_name][cls] = {
                "precision": float(per_pre[i])*100 if i < len(per_pre) else 0.0,
                "recall"   : float(per_rec[i])*100 if i < len(per_rec) else 0.0,
                "f1"       : float(per_f1[i]) *100 if i < len(per_f1)  else 0.0,
                "n"        : int((y_test == i).sum()),
            }

    sorted_classes = sorted(CLASS_NAMES,
                            key=lambda c: model_results["Ensemble"][c]["f1"])
    display_labels = [f"{c.replace('_',' ')}\n(n={model_results['Ensemble'][c]['n']:,})"
                      for c in sorted_classes]

    y_pos  = np.arange(len(sorted_classes))
    bar_h  = 0.25
    metric_styles = [("precision", "///"), ("recall", "..."), ("f1", "")]

    fig, axes = plt.subplots(
        1, 3,
        figsize=(22, max(8, 0.55 * len(sorted_classes) + 3)),
        sharey=True)

    for ax, mname in zip(axes, ["Random Forest", "XGBoost", "Ensemble"]):
        bar_colors = [CLASS_COLORS[CLASS_NAMES.index(c)] for c in sorted_classes]
        for i, (metric, hatch) in enumerate(metric_styles):
            offset = (i - 1) * bar_h
            vals   = [model_results[mname][c][metric] for c in sorted_classes]
            bars   = ax.barh(y_pos + offset, vals, bar_h,
                             color=bar_colors, alpha=0.85,
                             hatch=hatch, edgecolor="white", linewidth=0.6)
            for bar, val in zip(bars, vals):
                ax.text(min(val + 0.8, 106), bar.get_y() + bar.get_height() / 2,
                        f"{val:.0f}", va="center", fontsize=8, color="#333")

        ax.axvline(90, color="crimson", linestyle="--", lw=1.2, alpha=0.8)
        ax.set_yticks(y_pos)
        ax.set_yticklabels(display_labels, fontsize=9)
        ax.set_xlim(0, 110)
        ax.set_xlabel("Score (%)", fontsize=10)
        ax.set_title(mname, fontsize=13, **TITLE_KWARGS, pad=18)
        ax.invert_yaxis()
        ax.grid(axis="x", linestyle=":", alpha=0.5)
        ax.set_axisbelow(True)
        ax.spines[["top", "right"]].set_visible(False)

    tier_patches = [mpatches.Patch(color=CLASS_COLORS[i], alpha=0.85, label=CLASS_NAMES[i])
                    for i in range(N_CLASSES)]
    metric_patches = [
        mpatches.Patch(facecolor="grey", hatch="///", edgecolor="white",
                       alpha=0.85, label="Precision"),
        mpatches.Patch(facecolor="grey", hatch="...", edgecolor="white",
                       alpha=0.85, label="Recall"),
        mpatches.Patch(facecolor="grey", hatch="",   edgecolor="white",
                       alpha=0.85, label="F1-Score"),
        plt.Line2D([0], [0], color="crimson", linestyle="--", lw=1.2, label="90% target"),
    ]
    fig.legend(handles=tier_patches + metric_patches,
               loc="lower center", bbox_to_anchor=(0.5, -0.01),
               ncol=7, fontsize=9, frameon=True, edgecolor="#cccccc")

    fig.suptitle(
        "Per-Class Model Comparison — Phase 2\n"
        "Sorted worst to best (by Ensemble F1)",
        fontsize=13, **TITLE_KWARGS, y=1.02)
    plt.subplots_adjust(left=0.10, right=0.97, top=0.88, bottom=0.13, wspace=0.10)
    plt.savefig(os.path.join(OUTPUT_DIR, "5d_per_class_model_comparison.png"),
                dpi=150, bbox_inches="tight")
    plt.close()
    print("[GRAPH] 5d_per_class_model_comparison.png saved.")


# ============================================================
#  PART 14B — CONFUSION MATRICES
# ============================================================

def run_confusion_matrices(rf, xgb_clf, ensemble_model,
                            scaler, X_test, y_test):
    print("\n" + "="*60)
    print("  3-PANEL CONFUSION MATRICES (RF / XGB / Ensemble)")
    print("="*60)
    X_test_sc = scaler.transform(X_test)
    models = {
        "Random Forest"    : rf.predict(X_test_sc).astype(np.int8),
        "XGBoost"          : xgb_clf.predict(X_test_sc).astype(np.int8),
        "Ensemble (RF + XGB)": ensemble_model.predict(X_test_sc),
    }
    model_colors_map = {"Random Forest": PAL_RF,
                        "XGBoost": PAL_XGB,
                        "Ensemble (RF + XGB)": PAL_ENS}

    fig, axes = plt.subplots(1, 3, figsize=(20, 7))
    fig.suptitle("Confusion Matrices — Phase 2 Severity Router\n"
                 "Misclassifications (counts + row %)",
                 fontsize=13, **TITLE_KWARGS, y=1.04)

    present_labels = sorted(set(y_test.tolist()))
    present_names  = [CLASS_NAMES[i] for i in present_labels if i < len(CLASS_NAMES)]
    short_names    = [n.replace("_", "\n") for n in present_names]

    for ax, (mname, y_pred) in zip(axes, models.items()):
        cm     = confusion_matrix(y_test, y_pred, labels=present_labels)
        cm_pct = cm.astype(float) / cm.sum(axis=1, keepdims=True) * 100
        annot  = np.array([[f"{cnt}\n({pct:.2f}%)"
                            for cnt, pct in zip(row_c, row_p)]
                           for row_c, row_p in zip(cm, cm_pct)])
        cmap = sns.light_palette(model_colors_map[mname], as_cmap=True)
        sns.heatmap(cm_pct, annot=annot, fmt="", cmap=cmap, vmin=0, vmax=100,
                    xticklabels=short_names, yticklabels=short_names,
                    cbar_kws={"label": "Row %", "pad": 0.03, "shrink": 0.85},
                    linewidths=0.5, linecolor="white", ax=ax,
                    annot_kws={"size": 9})
        f1 = f1_score(y_test, y_pred, average=_f1_average(len(present_labels)),
                      zero_division=0)
        ax.set_title(f"{mname}\nMacro F1 = {f1*100:.2f}%",
                     fontsize=11, **TITLE_KWARGS, pad=10)
        ax.set_xlabel("Predicted Tier", fontsize=10, fontweight="bold")
        ax.set_ylabel("Actual Tier" if ax == axes[0] else "",
                      fontsize=10, fontweight="bold")
        ax.tick_params(axis="x", rotation=20, labelsize=9)
        ax.tick_params(axis="y", rotation=0,  labelsize=9)

    plt.subplots_adjust(left=0.07, right=0.97, top=0.85, bottom=0.08, wspace=0.40)
    plt.savefig(os.path.join(OUTPUT_DIR, "5e_confusion_matrices.png"),
                dpi=150, bbox_inches="tight")
    plt.close()
    print("[GRAPH] 5e_confusion_matrices.png saved.")


# ============================================================
#  PART 14C — PER-TIER SOURCE-FILE BREAKDOWN
# ============================================================

def run_per_tier_source_breakdown(ensemble_model, scaler,
                                   X_test, y_test, test_source_files, lc):
    print("\n" + "="*60)
    print("  PER-TIER SOURCE-FILE RECALL BREAKDOWN")
    print("="*60)
    X_test_sc = scaler.transform(X_test)
    y_pred    = ensemble_model.predict(X_test_sc)

    tier_map = {}
    for tier_idx, tier_name in enumerate(CLASS_NAMES):
        tier_map[tier_name] = {}
        tier_mask = (y_test == tier_idx)
        if tier_mask.sum() == 0:
            continue
        for src in np.unique(test_source_files[tier_mask]):
            src_mask = tier_mask & (test_source_files == src)
            n = src_mask.sum()
            if n < 5:
                continue
            rec = recall_score(y_test[src_mask], y_pred[src_mask],
                               labels=[tier_idx], average="micro", zero_division=0)
            display = SOURCE_FILE_DETAIL.get(src, src)
            tier_map[tier_name][display] = (rec * 100, int(n))
            print(f"  {tier_name:<22} {display:<40} n={n:>7,}  recall={rec*100:.2f}%")

    n_tiers = len([t for t in tier_map if tier_map[t]])
    if n_tiers == 0:
        print("[WARN] No per-tier data to plot.")
        return

    fig, axes = plt.subplots(1, n_tiers, figsize=(7 * n_tiers, 7), sharey=False)
    if n_tiers == 1:
        axes = [axes]

    ax_i = 0
    for tier_name in CLASS_NAMES:
        data = tier_map.get(tier_name, {})
        if not data:
            continue
        ax = axes[ax_i]; ax_i += 1
        sorted_items = sorted(data.items(), key=lambda t: t[1][0])
        labels_list  = [item[0] for item in sorted_items]
        recalls      = [item[1][0] for item in sorted_items]
        counts       = [item[1][1] for item in sorted_items]
        y_labels     = [f"{lbl}\n(n={n:,})" for lbl, n in zip(labels_list, counts)]
        y_pos  = np.arange(len(labels_list))
        color  = CLASS_COLORS[CLASS_NAMES.index(tier_name)]
        bars   = ax.barh(y_pos, recalls, color=color, alpha=0.82,
                         edgecolor="white", linewidth=0.5)
        for bar, val in zip(bars, recalls):
            ax.text(min(val + 1, 103), bar.get_y() + bar.get_height() / 2,
                    f"{val:.2f}%", va="center", fontsize=9,
                    fontweight="bold", color="#333")
        ax.axvline(90, color="crimson", linestyle="--", lw=1.2, alpha=0.8,
                   label="90% target")
        ax.set_xlim(0, 112); ax.set_yticks(y_pos)
        ax.set_yticklabels(y_labels, fontsize=8.5)
        ax.set_xlabel("Recall (%)", fontsize=10)
        ax.set_title(f"{tier_name}\n(Ensemble recall per attack source)",
                     fontsize=11, **TITLE_KWARGS, pad=8, color=color)
        ax.invert_yaxis(); ax.grid(axis="x", linestyle=":", alpha=0.5)
        ax.set_axisbelow(True); ax.spines[["top", "right"]].set_visible(False)

    fig.suptitle("Per-Tier Source-File Recall — Phase 2 Ensemble\n"
                 "Each bar = one attack tool/protocol within the severity tier",
                 fontsize=13, **TITLE_KWARGS, y=1.01)
    plt.subplots_adjust(left=0.22, right=0.97, top=0.88, bottom=0.08, wspace=0.50)
    plt.savefig(os.path.join(OUTPUT_DIR, "5f_per_tier_source_breakdown.png"),
                dpi=150, bbox_inches="tight")
    plt.close()
    print("[GRAPH] 5f_per_tier_source_breakdown.png saved.")


# ============================================================
#  PART 15 — SHAP XAI
# ============================================================

def run_shap(rf, xgb_clf, X_test_sc, y_test, feature_names, worst_class_idx=None):
    global XAI_STATUS
    try:
        import shap
    except ImportError:
        msg = "shap not installed — skipping SHAP analysis."
        print(f"[WARN] {msg}")
        XAI_STATUS = {"ran": False, "error": "shap_not_installed"}
        return

    print("\n" + "="*60)
    print(f"  SHAP XAI — Explainability ({len(feature_names)} features)")
    print("="*60)

    try:
        n_shap = min(2000, len(X_test_sc))  #bumped from 500
        idx    = np.random.choice(len(X_test_sc), n_shap, replace=False)
        X_shap = X_test_sc[idx]; y_shap = np.array(y_test)[idx]
        if worst_class_idx is None:
            worst_class_idx = 0
        worst_cls = CLASS_NAMES[worst_class_idx]

        def _get_sv(sv, class_idx):
            if isinstance(sv, list):
                return np.array(sv[class_idx])
            sv = np.array(sv)
            return sv[:, :, class_idx] if sv.ndim == 3 else sv

        def _get_base(ev, class_idx):
            if isinstance(ev, (list, np.ndarray)):
                arr = np.array(ev)
                return float(arr.flat[class_idx]) if arr.size > class_idx else float(arr.flat[0])
            return float(ev)

        def _global_summary(model, label, fname_prefix):
            exp = shap.TreeExplainer(model)
            sv  = exp.shap_values(X_shap)
            if isinstance(sv, list):
                global_imp = np.stack([np.abs(np.array(s)) for s in sv], axis=0).mean(axis=0)
            else:
                sv_arr = np.array(sv)
                global_imp = np.abs(sv_arr).mean(axis=2) if sv_arr.ndim == 3 else np.abs(sv_arr)

            plt.close("all")
            shap.summary_plot(global_imp, X_shap, feature_names=feature_names,
                              plot_type="bar", show=False, plot_size=(13, 7.5),
                              max_display=18)
            plt.title(f"SHAP — {label} (avg over classes)",
                      fontsize=14, pad=20, **TITLE_KWARGS)
            plt.xlabel("Mean |SHAP value|", fontsize=11, labelpad=10)
            plt.tight_layout()
            out = f"{fname_prefix}_shap_global.png"
            plt.savefig(os.path.join(OUTPUT_DIR, out), dpi=150,
                        bbox_inches="tight", pad_inches=0.4)
            plt.close()
            print(f"[GRAPH] {out} saved.")

            sv_cls = _get_sv(sv, worst_class_idx)
            plt.close("all")
            shap.summary_plot(sv_cls, X_shap, feature_names=feature_names,
                              plot_type="dot", show=False, plot_size=(13, 7.5),
                              max_display=18)
            plt.title(f"SHAP Summary — {label} | {worst_cls} (worst class)",
                      fontsize=14, pad=20, **TITLE_KWARGS)
            plt.xlabel("SHAP value", fontsize=11, labelpad=10)
            plt.tight_layout()
            out = f"{fname_prefix}_shap_worst_{worst_cls.lower()}.png"
            plt.savefig(os.path.join(OUTPUT_DIR, out), dpi=150,
                        bbox_inches="tight", pad_inches=0.4)
            plt.close()
            print(f"[GRAPH] {out} saved.")
            return exp, sv

        print("\n[INFO] RF SHAP..."); _global_summary(rf, "Random Forest", "7a")
        print("\n[INFO] XGBoost SHAP...")
        xgb_exp, xgb_sv = _global_summary(xgb_clf, "XGBoost", "7b")

        cls_idx_arr = np.where(y_shap == worst_class_idx)[0]
        if len(cls_idx_arr) > 0:
            sample_i = cls_idx_arr[0]
            sv_cls   = _get_sv(xgb_sv, worst_class_idx)
            try:
                xgb_expl = shap.Explanation(
                    values=sv_cls[sample_i],
                    base_values=_get_base(xgb_exp.expected_value, worst_class_idx),
                    data=X_shap[sample_i], feature_names=feature_names)
                fig = plt.figure(figsize=(15, 8))
                shap.plots.waterfall(xgb_expl, show=False, max_display=16)
                plt.title(f"SHAP Waterfall — {worst_cls} (XGBoost, worst class)",
                          fontsize=12, **TITLE_KWARGS, pad=14)
                plt.tight_layout()
                out = f"7c_shap_waterfall_{worst_cls.lower()}.png"
                plt.savefig(os.path.join(OUTPUT_DIR, out), dpi=150,
                            bbox_inches="tight", pad_inches=0.5)
                plt.close()
                print(f"[GRAPH] {out} saved.")
            except Exception as exc:
                print(f"  [WARN] Waterfall failed: {exc}")

        XAI_STATUS = {"ran": True, "error": None, "n_samples": n_shap}
    except Exception as exc:
        msg = f"SHAP failed: {exc}"
        print(f"[ERROR] {msg}")
        XAI_STATUS = {"ran": False, "error": str(exc)}


# ============================================================
#  PART 16 — SAVE
# ============================================================

def save_models(rf, xgb_clf, scaler, imputer, feature_names, all_metrics,
                le, ensemble_model, lc, lr_metrics=None,
                best_resampler="SMOTE",
                protocol_holdout_results=None,
                zero_var_dropped=None,
                smote_target_per_class=None):
    print("\n" + "="*60)
    print("  SAVING MODELS")
    print("="*60)

    joblib.dump(rf,             os.path.join(OUTPUT_DIR, "model_rf.pkl"),         compress=3)
    joblib.dump(xgb_clf,        os.path.join(OUTPUT_DIR, "model_xgb.pkl"),        compress=3)
    joblib.dump(ensemble_model, os.path.join(OUTPUT_DIR, "model_ensemble.pkl"),   compress=3)
    joblib.dump(scaler,         os.path.join(OUTPUT_DIR, "scaler.pkl"),           compress=3)
    joblib.dump(imputer,        os.path.join(OUTPUT_DIR, "imputer.pkl"),          compress=3)
    joblib.dump(feature_names,  os.path.join(OUTPUT_DIR, "feature_names.pkl"),    compress=3)
    joblib.dump(le,             os.path.join(OUTPUT_DIR, "label_encoder.pkl"),    compress=3)
    joblib.dump(lc,             os.path.join(OUTPUT_DIR, "label_compressor.pkl"), compress=3)

    proto_pass = None
    if protocol_holdout_results:
        recalls = [r["recall"] for r in protocol_holdout_results]
        proto_pass = all(r >= 0.85 for r in recalls)

    payload = {
        "phase"          : "multiclass",
        "scope"          : "Severity Classification: Reconnaissance / Credential_Abuse / Active_Exploitation",
        "feature_schema" : f"behaviour_based_{N_FEATURES_EXPECTED}_protocol_agnostic",
        "feature_changes": {
            "removed_features": ["fwd_header_size_tot", "bwd_header_size_tot"],
            "removed_reason": (
                "TLS handshake adds ~5-20 bytes to header overhead, creating a "
                "systematic HTTP vs HTTPS difference. Protocol fingerprint, not behaviour."
            ),
            "smote_strategy": {
                "old": "TARGET_CLASS_COUNT = 200_000 (fixed for all classes)",
                "new": "match_largest_real (only up-sample minorities to max real count)",
                "target_per_class_used": smote_target_per_class,
            },
            "recon_cap": {
                "old": 200_000,
                "new": RECON_CAP,
                "reason": (
                    "previously cap of 200K still over-balanced relative to other classes. "
                    "now cap of 100K maintains balance without artificially trivialising "
                    "the problem."
                ),
            },
            "coverage_penalty": {
                "old": 0.7,
                "new": COVERAGE_PENALTY_ALPHA,
            },
            "imputer_leakage": (
                "must not fitted SimpleImputer before train/test split. "
                "must fits on train only, transforms test separately."
            ),
            "zero_var_drop_post_split": zero_var_dropped or [],
            "optuna_trials": {"rf": OPTUNA_TRIALS_RF, "xgb": OPTUNA_TRIALS_XGB,
                                 "old_v2": {"rf": 30, "xgb": 50}},
        },
        "n_features"     : len(feature_names),
        "feature_names"  : feature_names,
        "classes"        : CLASS_NAMES,
        "class_map"      : {str(i): c for i, c in enumerate(CLASS_NAMES)},
        "n_classes"      : N_CLASSES,
        "withheld_phase3": {
            "classes": ["revshell_http", "revshell_https", "ssrf_http", "ssrf_https",
                        "xss_http", "xss_https", "ssh_login_successful"],
            "reason" : (
                "revshell + ssrf: novel unknown for Phase 3 RF + OSR novelty evaluation. "
                "xss: Selenium mimics real browser (withheld in Phase 1 too). "
                "ssh_login_successful: post-auth signal invisible at flow level."
            ),
        },
        "label_compression": {
            "orig_to_comp"     : {str(k): v for k, v in lc.orig_to_comp.items()},
            "comp_to_orig"     : {str(k): v for k, v in lc.comp_to_orig.items()},
            "n_train_classes"  : lc.n_train_classes,
            "train_class_names": lc.train_class_names,
        },
        "protocol_holdout": {
            "description": (
                "Full ensemble evaluated on HTTP-only and HTTPS-only subsets "
                "of the test split. Tests whether removing header_size_tot "
                "yielded protocol-agnostic learning."
            ),
            "pass_threshold_pct": 85.0,
            "passed": proto_pass,
            "results": protocol_holdout_results,
        },
        "imbalance_policy"  : {
            "method"       : "single_correction_smote_match_largest_real",
            "best_resampler": best_resampler,
            "smote_strategy": SMOTE_TARGET_STRATEGY,
            "smote_target_per_class": smote_target_per_class,
            "recon_cap"    : RECON_CAP,
        },
        "ensemble_weights"  : {"rf": ENSEMBLE_WEIGHTS[0], "xgb": ENSEMBLE_WEIGHTS[1]},
        "confidence_min"    : ensemble_model.confidence_min,
        "coverage_penalty_alpha": COVERAGE_PENALTY_ALPHA,
        "routing_logic"     : {
            "CLASSIFIED": f"max_prob >= {ensemble_model.confidence_min:.3f} goes to tier label",
            "UNCERTAIN" : f"max_prob < {ensemble_model.confidence_min:.3f} goes to Phase 3 RF + OSR",
        },
        "models"            : all_metrics,
        "lr_baseline"       : lr_metrics,
        "lr_diagnostic_gap_pp": LR_DIAGNOSTIC_GAP_PP,
        "xai_status"        : XAI_STATUS,
        "mitre_nist_mapping": {
            "_source": "threatmatrix_mitre_nist_mapping.py",
            "_note":   "Import PHASE_2_TIER_MAPPING from threatmatrix_mitre_nist_mapping "
                       "for enrichment.",
        },
        "preprocessing_order": [
            "1. Load CSVs and apply Recon cap",
            "2. Replace inf/-inf with NaN (no imputation yet)",
            "3. Stratified time-based 80/20 split → save split_indices_mc.npz",
            "4. Carve calibration set (15%) out of training set",
            "5. Fit imputer on TRAIN only, transform train+calib+test",
            "6. Drop zero-variance columns (TRAIN-detected) from all sets",
            "7. Fit scaler on imputed TRAIN, transform calib+test",
            "8. SMOTE on scaled training data (target = max real class)",
        ],
    }
    with open(os.path.join(OUTPUT_DIR, "multiclass_metrics.json"), "w") as f:
        json.dump(payload, f, indent=4, default=str)

    for fname in ["model_rf.pkl", "model_xgb.pkl", "model_ensemble.pkl",
                  "scaler.pkl", "imputer.pkl", "feature_names.pkl",
                  "label_encoder.pkl", "label_compressor.pkl",
                  "split_indices_mc.npz", "multiclass_metrics.json"]:
        fpath = os.path.join(OUTPUT_DIR, fname)
        if os.path.exists(fpath):
            size = os.path.getsize(fpath) / 1024
            print(f"  ✓  {fname:<46} {size:>8.1f} KB")
    print(f"\n[NEXT] Run  threatmatrix_anomaly.py  for Phase 3 RF + OSR.")


# ============================================================
#  MAIN
# ============================================================

def main():
    print("\n" + "="*60)
    print("  ThreatMatrix — Phase 2: Severity Classification")
    print(f"  Classes ({N_CLASSES}): {' | '.join(CLASS_NAMES)}")
    print(f"  Features: {N_FEATURES_EXPECTED} protocol-agnostic")
    print()
    print(f"  PIPELINE:")
    print(f"    Phase 1 = Binary (Benign vs Attack)")
    print(f"    Phase 2 = Severity tier (this file)")
    print(f"    Phase 3 = RF + Open-Set Recognition (Unknown attack rejection + novel-attack detection)")
    print()
    print(f"  Withheld = Phase 3: RevShell + SSRF + XSS + ssh_login_successful")
    print("="*60)
    t_start = time.time()

    df = load_data()
    X_pre, y, available_features, le, ts_series, source_files = preprocess(df)
    del df; gc.collect()

    train_idx, test_idx = split_data(X_pre, y, ts_series, source_files)

    # apply_split returns DataFrames for X_train / X_calib / X_test
    (X_train_pre, X_calib_pre, X_test_pre,
     y_train, y_calib, y_test,
     test_source_files) = apply_split(
        X_pre, y, source_files, train_idx, test_idx)

    del X_pre; gc.collect()

    # imputer + zero-var drop AFTER split (no leakage)
    (X_train, X_calib, X_test,
     imputer, feature_names, zero_var_dropped) = fit_imputer_and_drop_zerovar(
        X_train_pre, X_calib_pre, X_test_pre, available_features)

    # Convert to numpy arrays for downstream training
    X_train_arr = X_train.to_numpy().astype(np.float32)
    X_calib_arr = X_calib.to_numpy().astype(np.float32)
    X_test_arr  = X_test.to_numpy().astype(np.float32)

    scaler, X_train_sc = fit_scaler(X_train_arr)
    X_calib_sc         = scaler.transform(X_calib_arr)
    X_test_sc          = scaler.transform(X_test_arr)

    best_resampler, X_res, y_res, lc = benchmark_imbalance(X_train_sc, y_train)
    smote_target_per_class = int(max(int((y_res == i).sum())
                                      for i in range(lc.n_train_classes)))

    lr_model, m_lr = train_lr_baseline(X_res, y_res, X_test_arr, y_test, scaler, lc)

    print("\n" + "="*60)
    print("  HYPERPARAMETER TUNING")
    print("="*60)
    rf_params  = tune_rf(X_res, y_res, lc)
    xgb_params = tune_xgb(X_res, y_res, lc)

    rf, m_rf, rf_pred, rf_prob = train_rf(
        X_res, y_res, X_test_arr, y_test, scaler, feature_names, lc,
        best_params=rf_params)
    xgb_clf, m_xgb, xgb_pred, xgb_prob = train_xgb(
        X_res, y_res, X_test_arr, y_test, scaler, lc, best_params=xgb_params)
    m_ens, ens_pred, ens_prob = build_ensemble_predictions(
        rf_prob, xgb_prob, y_test, lc)

    ensemble_model = EnsembleModelMulticlass(
        rf, xgb_clf, CLASS_NAMES, lc,
        weights=ENSEMBLE_WEIGHTS, confidence_min=CONFIDENCE_MIN)

    best_conf = calibrate_confidence(ensemble_model, X_calib_sc, y_calib, lc)
    ensemble_model.confidence_min = best_conf
    print(f"\n[INFO] EnsembleModelMulticlass ready: {ensemble_model}")

    all_metrics = [m_rf, m_xgb, m_ens]
    all_probs   = {
        "Random Forest"    : rf_prob,
        "XGBoost"          : xgb_prob,
        "Ensemble (RF + XGB)": ens_prob,
    }

    plot_roc(y_test, all_probs, lc)
    plot_comparison(all_metrics, lc)
    plot_radar_comparison(all_metrics, lc)

    # Comparison printout including LR diagnostic
    print("\n" + "─"*95)
    print(f"  {'Model':<30} {'Acc':>8} {'M-Prec':>8} "
          f"{'M-Rec':>8} {'M-F1':>8} {'AUC':>8} {'PR-AUC':>8}")
    print("─"*95)
    for m in [m_lr, m_rf, m_xgb, m_ens]:
        flag = "✓" if m["accuracy"] >= TARGET_ACCURACY else "✗"
        tag = "  (diag)" if m["name"] == "LR Baseline" else ""
        print(f"  {m['name']:<30} "
              f"{m['accuracy']*100:>7.2f}%  "
              f"{m['precision']*100:>7.2f}%  "
              f"{m['recall']*100:>7.2f}%  "
              f"{m['f1']*100:>7.2f}%  "
              f"{m['roc_auc']:>7.4f}  "
              f"{m['pr_auc']:>7.4f}  {flag}{tag}")
    print("─"*95)

    # LR-vs-trees diagnostic
    lr_f1     = m_lr.get("f1", 0)
    tree_best = max(m.get("f1", 0) for m in all_metrics)
    if lr_f1 >= tree_best - LR_DIAGNOSTIC_GAP_PP / 100:
        print(f"\n  ⚠ DIAGNOSTIC: LR F1 ({lr_f1*100:.2f}%) within "
              f"{LR_DIAGNOSTIC_GAP_PP}pp of best tree ({tree_best*100:.2f}%)")
        print(f"     Features may still be linearly separable.")
    else:
        gap = (tree_best - lr_f1) * 100
        print(f"\n  ✓ LR-to-tree gap = {gap:.1f}pp  "
              f"(tree models leverage non-linear behaviour patterns)")

    # Identify worst class for SHAP focus
    worst_idx = 0
    worst_f1  = 1.1
    for i, cls in enumerate(CLASS_NAMES):
        cls_f1 = m_ens.get(f"{cls}_f1", 1.0)
        if cls_f1 < worst_f1:
            worst_f1 = cls_f1; worst_idx = i

    # Diagnostics
    run_cross_subtype_generalization(ensemble_model, scaler, X_test_arr, y_test, lc)
    protocol_results = run_protocol_holdout_evaluation(
        ensemble_model, scaler, test_source_files, X_test_arr, y_test, lc)
    run_confidence_routing_analysis(ensemble_model, scaler, X_test_arr, y_test)
    run_per_subtype_model_comparison(
        rf, xgb_clf, ensemble_model, scaler, X_test_arr, y_test, feature_names)
    run_confusion_matrices(rf, xgb_clf, ensemble_model, scaler, X_test_arr, y_test)
    run_per_tier_source_breakdown(
        ensemble_model, scaler, X_test_arr, y_test, test_source_files, lc)

    run_shap(rf, xgb_clf, X_test_sc, y_test, feature_names,
             worst_class_idx=worst_idx)

    save_models(rf, xgb_clf, scaler, imputer, feature_names, all_metrics,
                le, ensemble_model, lc, lr_metrics=m_lr,
                best_resampler=best_resampler,
                protocol_holdout_results=protocol_results,
                zero_var_dropped=zero_var_dropped,
                smote_target_per_class=smote_target_per_class)

    elapsed = (time.time() - t_start) / 60
    print(f"\n{'='*60}")
    print(f"  [DONE] Phase 2 complete in {elapsed:.1f} min")
    print(f"  Features          : {len(feature_names)} protocol-agnostic")
    print(f"  Resampler         : {best_resampler} (target = max real)")
    print(f"  Recon cap         : {RECON_CAP:,}")
    print(f"  Coverage α        : {COVERAGE_PENALTY_ALPHA}")
    print(f"  confidence_min    : {ensemble_model.confidence_min:.3f}")
    print(f"  XAI status        : ran={XAI_STATUS['ran']}  error={XAI_STATUS.get('error')}")
    print(f"  Output            : {OUTPUT_DIR}")
    print(f"  [NEXT] Run threatmatrix_anomaly.py for Phase 3.")
    print("="*60)


if __name__ == "__main__":
    main()