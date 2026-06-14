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

from sklearn.preprocessing import RobustScaler
from sklearn.impute        import SimpleImputer
from sklearn.decomposition import PCA
from sklearn.covariance    import LedoitWolf
from sklearn.ensemble      import RandomForestClassifier
from sklearn.metrics       import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, roc_auc_score, roc_curve,
    average_precision_score, precision_recall_curve,
    classification_report,
)

from threatmatrix_theme import (
    apply_theme, MODEL, SEVERITY, STATUS, TITLE_KWARGS,
    save_fig, severity_color, status_color,
    SOURCE_FILE_DETAIL as THEME_SOURCE_FILE_DETAIL,
)
apply_theme()


def _save_fig(fig, full_path):
    extra = [ax.get_legend() for ax in fig.axes
             if ax.get_legend() is not None and
             ax.get_legend().get_bbox_to_anchor() is not None]
    fig.savefig(full_path, dpi=150, bbox_inches="tight",
                bbox_extra_artists=extra if extra else None)
    plt.close(fig)


warnings.filterwarnings("ignore")
np.random.seed(42)


# ============================================================
#  CONFIG
# ============================================================

DATASET_DIR = os.environ.get(
    "THREATMATRIX_DATASET_DIR",
    r"C:\Users\yuhan\Documents\UniKL\SEMESTER 6\FYP 2\threatmatrix-26\web-ids23",
)
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
PHASE1_DIR   = os.path.join(PROJECT_ROOT, "threatmatrix_output", "binary")
OUTPUT_DIR   = os.path.join(PROJECT_ROOT, "threatmatrix_output", "anomaly")
os.makedirs(OUTPUT_DIR, exist_ok=True)

CLASS_FILES = {
    "Benign":           "web-ids23_benign.csv",
    "Portscan":         "web-ids23_portscan.csv",
    "BruteForce_HTTP":  "web-ids23_bruteforce_http.csv",
    "BruteForce_HTTPS": "web-ids23_bruteforce_https.csv",
    "SQLi_HTTP":        "web-ids23_sql_injection_http.csv",
    "SQLi_HTTPS":       "web-ids23_sql_injection_https.csv",
}
CLASS_NAMES = list(CLASS_FILES.keys())
N_CLASSES   = len(CLASS_NAMES)

PHASE3_NOVEL_FILES = {
    "web-ids23_revshell_http.csv"        : "RevShell",
    "web-ids23_revshell_https.csv"       : "RevShell",
    "web-ids23_xss_http.csv"             : "XSS",
    "web-ids23_xss_https.csv"            : "XSS",
    "web-ids23_ssrf_http.csv"            : "SSRF",
    "web-ids23_ssrf_https.csv"           : "SSRF",
    "web-ids23_ssh_login_successful.csv" : "SSH_Login_Success",
}

UNIVERSAL_FEATURES = [
    "flow_duration",
    "fwd_pkts_tot", "bwd_pkts_tot",
    "fwd_data_pkts_tot", "bwd_data_pkts_tot",
    "flow_pkts_per_sec", "fwd_pkts_per_sec", "bwd_pkts_per_sec",
    "payload_bytes_per_second",
    "down_up_ratio",
    "flow_FIN_flag_count", "flow_SYN_flag_count",
    "flow_RST_flag_count", "flow_ACK_flag_count",
]
N_FEATURES = len(UNIVERSAL_FEATURES)

CLASS_CAPS = {
    "Benign":           400_000,
    "Portscan":         100_000,
    "BruteForce_HTTP":  100_000,
    "BruteForce_HTTPS": 100_000,
    "SQLi_HTTP":        100_000,
    "SQLi_HTTPS":       100_000,
}
NOVEL_CAP = None
TRAIN_RATIO, VAL_RATIO, TEST_RATIO = 0.70, 0.15, 0.15

RF_N_ESTIMATORS     = 300
RF_MAX_DEPTH        = 20
RF_MIN_SAMPLES_LEAF = 5
RF_N_JOBS           = -1

LEAF_PCA_DIM        = 32
OSR_PERCENTILE      = 12.0
TARGET_BENIGN_FPR_MAX       = 0.10
TARGET_NOVEL_DETECTION_RATE = 0.50

SHAP_ENABLED      = True
SHAP_BACKGROUND_N = 500
SHAP_EXPLAIN_N    = 2_000

COL_BENIGN = STATUS.good
COL_KNOWN  = SEVERITY.credential_abuse
COL_NOVEL  = SEVERITY.anomaly
COL_RF     = MODEL.rf

SOURCE_FILE_DETAIL_P3 = {**THEME_SOURCE_FILE_DETAIL, **{
    "web-ids23_revshell_http.csv"        : "RevShell HTTP\n(Metasploit)",
    "web-ids23_revshell_https.csv"       : "RevShell HTTPS\n(Metasploit)",
    "web-ids23_xss_http.csv"             : "XSS HTTP\n(Selenium)",
    "web-ids23_xss_https.csv"            : "XSS HTTPS\n(Selenium)",
    "web-ids23_ssrf_http.csv"            : "SSRF HTTP\n(Burp/curl)",
    "web-ids23_ssrf_https.csv"           : "SSRF HTTPS\n(Burp/curl)",
    "web-ids23_ssh_login_successful.csv" : "SSH Login\n(post-auth)",
}}


# ============================================================
#  PREPROCESSOR
# ============================================================

class TreePreprocessor:
    """Imputer → RobustScaler."""
    def __init__(self, feature_names):
        self.feature_names = list(feature_names)
        self.imputer = SimpleImputer(strategy="median")
        self.scaler  = RobustScaler(quantile_range=(5.0, 95.0))

    def _select(self, df):
        miss = [c for c in self.feature_names if c not in df.columns]
        if miss:
            print(f"  [WARN] missing features: {miss}")
            for c in miss: df[c] = np.nan
        X = df[self.feature_names].copy()
        X.replace([np.inf, -np.inf], np.nan, inplace=True)
        return X.astype(np.float64).to_numpy()

    def fit_transform(self, df):
        X = self._select(df)
        X = self.imputer.fit_transform(X)
        X = self.scaler.fit_transform(X)
        return X.astype(np.float32)

    def transform(self, df):
        if df is None or len(df) == 0:
            return np.empty((0, len(self.feature_names)), dtype=np.float32), 0
        X = self._select(df)
        n_nan = int(np.isnan(X).sum())
        X = self.imputer.transform(X)
        X = self.scaler.transform(X)
        return X.astype(np.float32), n_nan


# ============================================================
#  OPEN-SET CLASSIFIER
# ============================================================

class OpenSetClassifier:
    """Random Forest + dual OSR (max-softmax baseline + Mahalanobis-on-leaves)."""
    def __init__(self, rf, class_names, feature_names,
                 leaf_pca, leaf_class_means, leaf_class_inv_covs,
                 thr_softmax, thr_maha,
                 calibration_metadata=None):
        self.rf                  = rf
        self.class_names         = list(class_names)
        self.feature_names       = list(feature_names)
        self.leaf_pca            = leaf_pca
        self.leaf_class_means    = {c: np.asarray(m, dtype=np.float64)
                                    for c, m in leaf_class_means.items()}
        self.leaf_class_inv_covs = {c: np.asarray(v, dtype=np.float64)
                                    for c, v in leaf_class_inv_covs.items()}
        self.thr_softmax          = float(thr_softmax)
        self.thr_maha             = float(thr_maha)
        self.calibration_metadata = calibration_metadata or {}

    def _leaf_embed(self, X):
        leaves = self.rf.apply(X)
        n, t = leaves.shape
        return self.leaf_pca.transform(leaves.astype(np.float32))

    def softmax_ood_score(self, X):
        proba = self.rf.predict_proba(X)
        return 1.0 - proba.max(axis=1)

    def mahalanobis_ood_score(self, X):
        emb = self._leaf_embed(X).astype(np.float64)
        n = emb.shape[0]
        dists = np.full((n, len(self.class_names)), np.inf, dtype=np.float64)
        for ci, cname in enumerate(self.class_names):
            if cname not in self.leaf_class_means: continue
            mu  = self.leaf_class_means[cname]
            inv = self.leaf_class_inv_covs[cname]
            d = emb - mu
            dists[:, ci] = np.sqrt(
                np.einsum("ij,jk,ik->i", d, inv, d).clip(min=0))
        return dists.min(axis=1).astype(np.float32)

    def predict_with_osr_softmax(self, X):
        cls_idx = self.rf.predict(X)
        ood     = self.softmax_ood_score(X)
        labels  = np.array([self.class_names[i] for i in cls_idx], dtype=object)
        labels[ood > self.thr_softmax] = "UNKNOWN"
        return labels, ood

    def predict_with_osr_maha(self, X):
        cls_idx = self.rf.predict(X)
        ood     = self.mahalanobis_ood_score(X)
        labels  = np.array([self.class_names[i] for i in cls_idx], dtype=object)
        labels[ood > self.thr_maha] = "UNKNOWN"
        return labels, ood

    def predict_proba(self, X):
        return self.rf.predict_proba(X)

    def predict(self, X):
        return self.rf.predict(X)

    def __repr__(self):
        return (f"OpenSetClassifier(n_classes={len(self.class_names)}, "
                f"thr_softmax={self.thr_softmax:.4f}, "
                f"thr_maha={self.thr_maha:.4f})")


# ============================================================
#  DATA LOADING
# ============================================================

def load_csv(filename, label):
    path = os.path.join(DATASET_DIR, filename)
    if not os.path.exists(path):
        return None
    try:
        df = pd.read_csv(path, low_memory=False)
    except Exception as exc:
        print(f"  [ERROR] {filename}: {exc}"); return None
    df.columns = df.columns.str.strip()
    df["attack_type"]  = label
    df["_source_file"] = filename
    return df


def load_phase3_data():
    print("\n" + "="*70)
    print("  PHASE 3 — RF + OSR")
    print(f"  Known classes : {N_CLASSES}  ({', '.join(CLASS_NAMES)})")
    print(f"  Features      : {N_FEATURES} protocol-agnostic flow stats")
    print(f"  RF            : n_est={RF_N_ESTIMATORS}, max_depth={RF_MAX_DEPTH}")
    print(f"  OSR methods   : Max-Softmax (baseline) + Mahalanobis-on-leaves")
    print(f"  SHAP          : {'enabled' if SHAP_ENABLED else 'disabled'}")
    print("="*70)

    print("\n[INFO] Loading KNOWN classes (training set)...")
    known_frames = []
    for cls_name, fname in CLASS_FILES.items():
        chunk = load_csv(fname, cls_name)
        if chunk is None:
            raise FileNotFoundError(f"Required file missing: {fname}")
        cap = CLASS_CAPS.get(cls_name)
        if cap and len(chunk) > cap:
            chunk = chunk.sample(cap, random_state=42).reset_index(drop=True)
        known_frames.append(chunk)
        print(f"  ✓  {cls_name:<18} {fname:<46} → {len(chunk):>9,} rows")
    df_known = pd.concat(known_frames, ignore_index=True)

    print("\n[INFO] Loading NOVEL classes (held-out from training)...")
    novel_frames = []
    for fname, lbl in PHASE3_NOVEL_FILES.items():
        chunk = load_csv(fname, f"Novel_{lbl}")
        if chunk is None: continue
        if NOVEL_CAP and len(chunk) > NOVEL_CAP:
            chunk = chunk.sample(NOVEL_CAP, random_state=42).reset_index(drop=True)
        novel_frames.append(chunk)
        print(f"  ✓  {fname:<46} → {len(chunk):>9,} rows  [{lbl}]")
    df_novel = pd.concat(novel_frames, ignore_index=True) if novel_frames else pd.DataFrame()
    assert len(df_novel) > 0, "No novel data loaded — OSR evaluation impossible."

    for name, df in [("known", df_known), ("novel", df_novel)]:
        before = len(df)
        df.drop_duplicates(inplace=True); df.reset_index(drop=True, inplace=True)
        print(f"  [DEDUP] {name:<6} {before:>9,} → {len(df):>9,}")

    print(f"\n[INFO] Totals  known={len(df_known):,}  novel={len(df_novel):,}")
    return df_known, df_novel


def stratified_split(df, y, train_ratio, val_ratio, seed=42):
    rng = np.random.default_rng(seed)
    tr_idx, va_idx, te_idx = [], [], []
    for cls in np.unique(y):
        idx = np.where(y == cls)[0]
        rng.shuffle(idx)
        n = len(idx)
        n_tr = int(n * train_ratio)
        n_va = int(n * val_ratio)
        tr_idx.append(idx[:n_tr])
        va_idx.append(idx[n_tr:n_tr+n_va])
        te_idx.append(idx[n_tr+n_va:])
    return (np.concatenate(tr_idx),
            np.concatenate(va_idx),
            np.concatenate(te_idx))


# ============================================================
#  RF TRAINING + LEAF-EMBEDDING SETUP
# ============================================================

def train_rf(X_tr, y_tr):
    print("\n" + "="*70)
    print("  RANDOM FOREST TRAINING  (6-class fine-grained)")
    print(f"  n_estimators={RF_N_ESTIMATORS}  max_depth={RF_MAX_DEPTH}  "
          f"min_samples_leaf={RF_MIN_SAMPLES_LEAF}")
    print("="*70)
    t0 = time.time()
    rf = RandomForestClassifier(
        n_estimators=RF_N_ESTIMATORS,
        max_depth=RF_MAX_DEPTH,
        min_samples_leaf=RF_MIN_SAMPLES_LEAF,
        class_weight="balanced",
        random_state=42,
        n_jobs=RF_N_JOBS,
        verbose=0,
    )
    rf.fit(X_tr, y_tr)
    print(f"  [DONE] RF trained in {time.time()-t0:.1f}s")
    print(f"  Trees: {len(rf.estimators_)}, total leaves (approx): "
          f"{sum(t.tree_.n_leaves for t in rf.estimators_):,}")
    return rf


def fit_leaf_embedding(rf, X_calib, y_calib, class_names):
    print("\n" + "="*70)
    print("  LEAF-EMBEDDING SETUP  (Lee et al. 2018, adapted to RF)")
    print("="*70)

    print(f"  Computing leaf-IDs on {len(X_calib):,} calibration samples...")
    leaves = rf.apply(X_calib).astype(np.float32)

    print(f"  Fitting PCA: {leaves.shape[1]} trees → {LEAF_PCA_DIM} components...")
    pca = PCA(n_components=LEAF_PCA_DIM, random_state=42)
    emb = pca.fit_transform(leaves)
    print(f"  PCA explained variance ratio (sum): "
          f"{pca.explained_variance_ratio_.sum():.4f}")

    y_pred = rf.predict(X_calib)
    correct_mask = (y_pred == y_calib)
    print(f"  Calibration accuracy: {correct_mask.mean()*100:.2f}% "
          f"({correct_mask.sum():,}/{len(y_calib):,} correctly classified)")

    means, inv_covs = {}, {}
    print(f"  Fitting per-class Gaussians on leaf embeddings...")
    for ci, cname in enumerate(class_names):
        mask = correct_mask & (y_calib == ci)
        n = mask.sum()
        if n < LEAF_PCA_DIM * 2:
            print(f"  [WARN] class {cname}: only {n} correct samples — "
                  f"using full class set as fallback")
            mask = (y_calib == ci)
            n = mask.sum()
        emb_c = emb[mask].astype(np.float64)
        cov = LedoitWolf().fit(emb_c)
        means[cname]    = cov.location_
        inv_covs[cname] = np.linalg.pinv(cov.covariance_)
        print(f"    {cname:<18} n={n:>7,}  shrinkage={cov.shrinkage_:.4f}")

    return pca, means, inv_covs


def calibrate_osr_thresholds(rf, opener_softmax_fn, opener_maha_fn,
                              X_calib, y_calib, class_names):
    print("\n" + "="*70)
    print(f"  OSR THRESHOLD CALIBRATION  (p={100-OSR_PERCENTILE:.0f} of correctly-")
    print(f"  classified known scores → captures the 'normal' confidence range)")
    print("="*70)

    y_pred = rf.predict(X_calib)
    correct_mask = (y_pred == y_calib)
    Xc = X_calib[correct_mask]
    print(f"  Using {len(Xc):,} correctly-classified calibration samples")

    s_softmax = opener_softmax_fn(Xc)
    s_maha    = opener_maha_fn(Xc)

    pct = 100.0 - OSR_PERCENTILE
    thr_softmax = float(np.percentile(s_softmax, pct))
    thr_maha    = float(np.percentile(s_maha,    pct))

    print(f"  Max-Softmax threshold (p{pct:.0f})    : {thr_softmax:.4f}")
    print(f"  Mahalanobis threshold (p{pct:.0f})    : {thr_maha:.4f}")
    print(f"  → Expected known→UNKNOWN flag rate at this threshold: "
          f"~{OSR_PERCENTILE:.0f}%")
    return thr_softmax, thr_maha, {
        "percentile": pct,
        "n_calibration_samples": int(len(Xc)),
    }


# ============================================================
#  EVALUATION
# ============================================================

def evaluate_closed_world(rf, X_test, y_test, class_names):
    print("\n" + "="*70)
    print("  CLOSED-WORLD EVALUATION  (6 known classes, test split)")
    print("="*70)
    y_pred = rf.predict(X_test)
    acc        = accuracy_score(y_test, y_pred)
    macro_f1   = f1_score(y_test, y_pred, average="macro",    zero_division=0)
    weighted_f1= f1_score(y_test, y_pred, average="weighted", zero_division=0)

    print(f"\n  Overall accuracy : {acc*100:.2f}%")
    print(f"  Macro F1         : {macro_f1*100:.2f}%")
    print(f"  Weighted F1      : {weighted_f1*100:.2f}%")
    print(f"\n  Per-class report:\n")
    print(classification_report(y_test, y_pred, target_names=class_names,
                                 digits=4, zero_division=0))

    cm = confusion_matrix(y_test, y_pred)
    per_class_metrics = {}
    for ci, cname in enumerate(class_names):
        mask = (y_test == ci)
        if mask.sum() == 0: continue
        prec = precision_score(y_test == ci, y_pred == ci, zero_division=0)
        rec  = recall_score(y_test == ci,    y_pred == ci, zero_division=0)
        f1   = f1_score(y_test == ci,        y_pred == ci, zero_division=0)
        per_class_metrics[cname] = {
            "precision": float(prec), "recall": float(rec),
            "f1": float(f1), "support": int(mask.sum()),
        }

    return {
        "accuracy":     float(acc),
        "macro_f1":     float(macro_f1),
        "weighted_f1":  float(weighted_f1),
        "per_class":    per_class_metrics,
        "confusion_matrix": cm.tolist(),
    }


def evaluate_open_world(opener, X_known_test, y_known_test,
                        X_novel, novel_src, class_names):
    print("\n" + "="*70)
    print("  OPEN-WORLD EVALUATION  (novel detection — both methods)")
    print("="*70)

    results = {}
    for method_name, score_fn, thr in [
        ("max_softmax",        opener.softmax_ood_score,     opener.thr_softmax),
        ("mahalanobis_leaves", opener.mahalanobis_ood_score, opener.thr_maha),
    ]:
        print(f"\n  ─── Method: {method_name}  (thr={thr:.4f}) ───")
        s_known = score_fn(X_known_test)
        s_novel = score_fn(X_novel)

        y_ood = np.r_[np.zeros(len(s_known), dtype=np.int8),
                      np.ones(len(s_novel),  dtype=np.int8)]
        s_ood = np.r_[s_known, s_novel]
        try:
            auroc = roc_auc_score(y_ood, s_ood)
            auprc = average_precision_score(y_ood, s_ood)
        except Exception:
            auroc = auprc = float("nan")

        flagged_known = (s_known > thr).mean()
        flagged_novel = (s_novel > thr).mean()
        print(f"    AUROC (novel vs known)     : {auroc:.4f}")
        print(f"    AUPRC                       : {auprc:.4f}")
        print(f"    Known flagged as UNKNOWN    : {flagged_known*100:.2f}%  "
              f"(= false alarm rate, target ≤ {OSR_PERCENTILE}%)")
        print(f"    Novel flagged as UNKNOWN    : {flagged_novel*100:.2f}%  "
              f"(= novel detection rate)")

        print(f"\n    Per-novel-source detection rate:")
        per_src = {}
        for src in np.unique(novel_src):
            mask = (novel_src == src)
            if mask.sum() == 0: continue
            tpr  = float((s_novel[mask] > thr).mean())
            tier = PHASE3_NOVEL_FILES.get(src, "Unknown")
            print(f"      {SOURCE_FILE_DETAIL_P3.get(src, src):<46} "
                  f"n={int(mask.sum()):>7,}  TPR={tpr*100:>6.2f}%  [{tier}]")
            per_src[src] = {"n": int(mask.sum()), "tpr": tpr, "tier": tier}

        results[method_name] = {
            "threshold":          float(thr),
            "auroc":              float(auroc),
            "auprc":              float(auprc),
            "known_flag_rate":    float(flagged_known),
            "novel_flag_rate":    float(flagged_novel),
            "per_novel_source":   per_src,
            "scores_known_sample": s_known[:1000].tolist(),
            "scores_novel_sample": s_novel[:1000].tolist(),
        }
    return results


# ============================================================
#  PLOTS
# ============================================================

def plot_closed_world_confusion(cm, class_names):
    cm_arr  = np.array(cm)
    cm_pct  = cm_arr.astype(float) / np.maximum(cm_arr.sum(axis=1, keepdims=True), 1) * 100
    n       = len(class_names)
    short   = [c.replace("_", "\n") for c in class_names]

    fig, ax = plt.subplots(figsize=(max(8, n * 2.5), max(7, n * 2.0)))
    sns.heatmap(cm_arr, annot=False, cmap="Blues", ax=ax,
                xticklabels=short, yticklabels=short,
                cbar_kws={"label": "Count", "pad": 0.02},
                linewidths=1.0, linecolor="white")

    threshold = cm_arr.max() * 0.5
    for i in range(n):
        for j in range(n):
            count = cm_arr[i, j]
            pct   = cm_pct[i, j]
            cell_color = "white" if count > threshold else "black"
            ax.text(j + 0.5, i + 0.38, f"{count:,}",
                    ha="center", va="center",
                    fontsize=11, fontweight="bold", color=cell_color)
            ax.text(j + 0.5, i + 0.62, f"({pct:.1f}% of actual)",
                    ha="center", va="center",
                    fontsize=7, color=cell_color, alpha=0.85)

    recall_parts = [f"{class_names[i].replace('_',' ')} recall={cm_pct[i,i]:.1f}%"
                    for i in range(n)]
    recall_str = "  |  ".join(recall_parts)

    ax.set_title(
        f"Closed-World Confusion Matrix\n{recall_str}",
        pad=12, fontsize=9, **TITLE_KWARGS)
    ax.set_ylabel("Actual Class", fontsize=11, fontweight="bold")
    ax.set_xlabel("Predicted Class", fontsize=11, fontweight="bold")
    ax.tick_params(axis="x", rotation=30, labelsize=9)
    ax.tick_params(axis="y", rotation=0,  labelsize=9)
    plt.tight_layout()
    _save_fig(fig, os.path.join(OUTPUT_DIR, "1_confusion_matrix_closed_world.png"))
    print("[GRAPH] 1_confusion_matrix_closed_world.png")


def plot_per_class_f1(per_class):
    items = sorted(per_class.items(), key=lambda kv: kv[1]["f1"])
    names = [k for k, _ in items]
    f1s   = [v["f1"]*100         for _, v in items]
    precs = [v["precision"]*100  for _, v in items]
    recs  = [v["recall"]*100     for _, v in items]

    fig, ax = plt.subplots(figsize=(13, 6))
    y = np.arange(len(names))
    w = 0.27
    ax.barh(y - w, precs, w, color=COL_BENIGN, label="Precision", alpha=0.85)
    ax.barh(y,     recs,  w, color=COL_KNOWN,  label="Recall",    alpha=0.85)
    ax.barh(y + w, f1s,   w, color=COL_RF,     label="F1",        alpha=0.85)
    for i, (p, r, f) in enumerate(zip(precs, recs, f1s)):
        ax.text(p+0.5, i-w, f"{p:.2f}", va="center", fontsize=8)
        ax.text(r+0.5, i,   f"{r:.2f}", va="center", fontsize=8)
        ax.text(f+0.5, i+w, f"{f:.2f}", va="center", fontsize=8, fontweight="bold")
    ax.set_yticks(y); ax.set_yticklabels(names)
    ax.set_xlim(0, 110); ax.set_xlabel("Score (%)")
    ax.set_title("Per-Class Closed-World Performance", **TITLE_KWARGS)
    ax.grid(axis="x", linestyle=":", alpha=0.5)
    ax.set_axisbelow(True); ax.spines[["top", "right"]].set_visible(False)
    ax.legend(loc="center left", bbox_to_anchor=(1.01, 0.5),
              frameon=True, fontsize=9)
    plt.tight_layout()
    _save_fig(fig, os.path.join(OUTPUT_DIR, "2_per_class_f1.png"))
    print("[GRAPH] 2_per_class_f1.png")


def plot_feature_importance(rf, feature_names, top_n=15):
    imp   = rf.feature_importances_
    order = np.argsort(imp)[::-1][:top_n]
    fig, ax = plt.subplots(figsize=(11, max(5, top_n*0.4)))
    y    = np.arange(len(order))
    bars = ax.barh(y, imp[order][::-1], color=COL_RF, alpha=0.88, edgecolor="white")
    for bar, val in zip(bars, imp[order][::-1]):
        ax.text(val + max(imp)*0.01, bar.get_y() + bar.get_height()/2,
                f"{val:.4f}", va="center", fontsize=8)
    ax.set_yticks(y)
    ax.set_yticklabels([feature_names[i] for i in order][::-1])
    ax.set_xlabel("Gini Importance")
    ax.set_title(f"RF Feature Importance — Top {top_n}", **TITLE_KWARGS)
    ax.grid(axis="x", linestyle=":", alpha=0.5)
    ax.set_axisbelow(True); ax.spines[["top", "right"]].set_visible(False)
    plt.tight_layout()
    _save_fig(fig, os.path.join(OUTPUT_DIR, "3_feature_importance.png"))
    print("[GRAPH] 3_feature_importance.png")


def plot_osr_roc_comparison(osr_results):
    fig, ax = plt.subplots(figsize=(9, 7.5))
    colors = {
        "max_softmax":        COL_KNOWN,
        "mahalanobis_leaves": COL_NOVEL,
    }
    method_pretty = {
        "max_softmax":        "Max-Softmax",
        "mahalanobis_leaves": "Mahalanobis-on-leaves",
    }
    for method, res in osr_results.items():
        s_k = np.array(res["scores_known_sample"])
        s_n = np.array(res["scores_novel_sample"])
        y   = np.r_[np.zeros(len(s_k)), np.ones(len(s_n))]
        s   = np.r_[s_k, s_n]
        fpr, tpr, _ = roc_curve(y, s)
        ax.plot(fpr, tpr, color=colors[method], lw=2.4,
                label=f"{method_pretty[method]}\nAUROC = {res['auroc']:.4f}")
    ax.plot([0, 1], [0, 1], "k--", lw=1, label="Random")
    ax.set_xlabel("False Positive Rate (known flagged as novel)")
    ax.set_ylabel("True Positive Rate (novel flagged as novel)")
    ax.set_title("OSR Method Comparison\nROC: Novel vs Known Attacks", **TITLE_KWARGS)
    ax.legend(loc="lower right", fontsize=9)
    ax.grid(linestyle=":", alpha=0.5); ax.spines[["top", "right"]].set_visible(False)
    plt.tight_layout()
    _save_fig(fig, os.path.join(OUTPUT_DIR, "4_osr_roc_comparison.png"))
    print("[GRAPH] 4_osr_roc_comparison.png")


def plot_per_novel_source_comparison(osr_results):
    sources = sorted(
        {s for r in osr_results.values() for s in r["per_novel_source"]},
        key=lambda s: osr_results["mahalanobis_leaves"]["per_novel_source"][s]["tpr"],
    )
    n            = len(sources)
    softmax_tprs = [osr_results["max_softmax"]["per_novel_source"][s]["tpr"]*100
                    for s in sources]
    maha_tprs    = [osr_results["mahalanobis_leaves"]["per_novel_source"][s]["tpr"]*100
                    for s in sources]
    counts       = [osr_results["mahalanobis_leaves"]["per_novel_source"][s]["n"]
                    for s in sources]

    fig, ax = plt.subplots(figsize=(13, max(6.5, n*0.6)))
    y = np.arange(n)
    h = 0.4
    bars_s = ax.barh(y - h/2, softmax_tprs, h,
                     color=COL_KNOWN, alpha=0.85, label="Max-Softmax",
                     edgecolor="white")
    bars_m = ax.barh(y + h/2, maha_tprs, h,
                     color=COL_NOVEL, alpha=0.85, label="Mahalanobis-leaves",
                     edgecolor="white")
    for bar, t in zip(bars_s, softmax_tprs):
        ax.text(min(t+1, 102), bar.get_y() + bar.get_height()/2,
                f"{t:.2f}%", va="center", fontsize=8)
    for bar, t, n_ in zip(bars_m, maha_tprs, counts):
        ax.text(min(t+1, 102), bar.get_y() + bar.get_height()/2,
                f"{t:.2f}%  (n={n_:,})", va="center", fontsize=8, fontweight="bold")
    ax.axvline(TARGET_NOVEL_DETECTION_RATE*100, color="crimson", ls="--", lw=1.5,
               label=f"Target ≥ {TARGET_NOVEL_DETECTION_RATE*100:.0f}%")
    ax.set_yticks(y)
    ax.set_yticklabels([SOURCE_FILE_DETAIL_P3.get(s, s) for s in sources], fontsize=9)
    ax.set_xlim(0, 115); ax.set_xlabel("Novel Detection Rate (%)")
    ax.set_title("Per-Novel-Source Detection Rate — OSR Method Comparison",
                 **TITLE_KWARGS)
    ax.invert_yaxis()
    ax.grid(axis="x", linestyle=":", alpha=0.5)
    ax.set_axisbelow(True); ax.spines[["top", "right"]].set_visible(False)
    ax.legend(loc="center left", bbox_to_anchor=(1.01, 0.5),
              frameon=True, fontsize=9)
    plt.tight_layout()
    _save_fig(fig, os.path.join(OUTPUT_DIR, "5_per_novel_source_comparison.png"))
    print("[GRAPH] 5_per_novel_source_comparison.png")


def plot_score_distributions(osr_results):
    fig, axes = plt.subplots(1, 2, figsize=(15, 6))
    for ax, (method, res) in zip(axes, osr_results.items()):
        s_k   = np.array(res["scores_known_sample"])
        s_n   = np.array(res["scores_novel_sample"])
        all_s = np.concatenate([s_k, s_n])
        if len(all_s) == 0: continue
        lo, hi = np.percentile(all_s, [1, 99])
        bins   = np.linspace(lo, hi, 60)
        ax.hist(s_k, bins=bins, alpha=0.55, color=COL_BENIGN, density=True,
                label=f"Known (n={len(s_k):,})")
        ax.hist(s_n, bins=bins, alpha=0.55, color=COL_NOVEL,  density=True,
                label=f"Novel (n={len(s_n):,})")
        ax.axvline(res["threshold"], color="red", ls="--", lw=2,
                   label=f"Threshold = {res['threshold']:.4f}")
        ax.set_xlabel("OOD Score"); ax.set_ylabel("Density")
        pretty = method.replace("_", " ").title()
        ax.set_title(f"{pretty}\nAUROC={res['auroc']:.4f}", **TITLE_KWARGS)
        ax.legend(loc="upper right", fontsize=9)
        ax.spines[["top", "right"]].set_visible(False)
    plt.tight_layout()
    _save_fig(fig, os.path.join(OUTPUT_DIR, "6_score_distributions.png"))
    print("[GRAPH] 6_score_distributions.png")


def plot_shap_summary(shap_values, X_sample, feature_names, class_names):
    try:
        if isinstance(shap_values, list):
            sv_list = shap_values
        else:
            sv_list = [shap_values[..., c] for c in range(shap_values.shape[-1])]

        mean_abs = np.stack([np.abs(sv).mean(axis=0) for sv in sv_list], axis=1)

        fig, ax = plt.subplots(figsize=(12, 7))
        order  = np.argsort(mean_abs.sum(axis=1))[::-1]
        n_show = min(15, len(feature_names))
        order  = order[:n_show][::-1]

        palette = sns.color_palette("husl", len(class_names))
        bottoms = np.zeros(n_show)
        for ci, cname in enumerate(class_names):
            vals = mean_abs[order, ci]
            ax.barh(np.arange(n_show), vals, left=bottoms,
                    color=palette[ci], label=cname, alpha=0.88, edgecolor="white")
            bottoms += vals
        ax.set_yticks(np.arange(n_show))
        ax.set_yticklabels([feature_names[i] for i in order])
        ax.set_xlabel("Mean |SHAP value| (stacked across classes)")
        ax.set_title("SHAP Feature Importance — Per-Class Contribution\n"
                     "(TreeExplainer, interventional)", **TITLE_KWARGS)
        ax.legend(loc="lower right", fontsize=8, ncol=2)
        ax.grid(axis="x", linestyle=":", alpha=0.5)
        ax.set_axisbelow(True); ax.spines[["top", "right"]].set_visible(False)
        plt.tight_layout()
        _save_fig(fig, os.path.join(OUTPUT_DIR, "7_shap_summary.png"))
        print("[GRAPH] 7_shap_summary.png")
        return True
    except Exception as e:
        print(f"  [WARN] SHAP plot failed: {e}")
        return False


def plot_summary_metrics(closed_metrics, osr_results):
    fig, axes = plt.subplots(1, 3, figsize=(16, 5))
    fig.suptitle("Phase 3 — ThreatMatrix Summary Metrics",
                 fontsize=14, fontweight="bold", y=1.02)

    # Closed-world overall
    ax = axes[0]
    labels = ["Accuracy", "Macro-F1", "Weighted-F1"]
    values = [
        closed_metrics["accuracy"]     * 100,
        closed_metrics["macro_f1"]     * 100,
        closed_metrics["weighted_f1"]  * 100,
    ]
    bars = ax.bar(labels, values, color=[COL_BENIGN, COL_RF, COL_KNOWN],
                  alpha=0.85, width=0.5)
    for bar, v in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width()/2, v + 0.1, f"{v:.2f}%",
                ha="center", va="bottom", fontsize=11, fontweight="bold")
    ax.set_ylim(90, 101)
    ax.set_title("Closed-World Performance\n(6 Known Classes)", **TITLE_KWARGS)
    ax.set_ylabel("Score (%)")
    ax.grid(axis="y", linestyle=":", alpha=0.5)
    ax.spines[["top", "right"]].set_visible(False)

    # AUROC comparison
    ax = axes[1]
    methods = ["Max-Softmax", "Mahalanobis\n-on-leaves"]
    aurocs  = [
        osr_results["max_softmax"]["auroc"],
        osr_results["mahalanobis_leaves"]["auroc"],
    ]
    bars = ax.bar(methods, aurocs, color=[COL_KNOWN, COL_NOVEL], alpha=0.85, width=0.4)
    for bar, v in zip(bars, aurocs):
        ax.text(bar.get_x() + bar.get_width()/2, v + 0.002, f"{v:.4f}",
                ha="center", va="bottom", fontsize=11, fontweight="bold")
    ax.set_ylim(0.85, 1.0)
    ax.set_title("OSR AUROC\n(Novel vs Known)", **TITLE_KWARGS)
    ax.set_ylabel("AUROC")
    ax.grid(axis="y", linestyle=":", alpha=0.5)
    ax.spines[["top", "right"]].set_visible(False)

    # Novel detection rate vs false-flag rate
    ax = axes[2]
    x     = np.arange(2)
    w     = 0.35
    ndr_s = osr_results["max_softmax"]["novel_flag_rate"]        * 100
    ndr_m = osr_results["mahalanobis_leaves"]["novel_flag_rate"] * 100
    ffr_s = osr_results["max_softmax"]["known_flag_rate"]        * 100
    ffr_m = osr_results["mahalanobis_leaves"]["known_flag_rate"] * 100

    b1 = ax.bar(x - w/2, [ndr_s, ffr_s], w, color=COL_KNOWN,  alpha=0.85,
                label="Max-Softmax")
    b2 = ax.bar(x + w/2, [ndr_m, ffr_m], w, color=COL_NOVEL, alpha=0.85,
                label="Mahalanobis-leaves")
    for bar in list(b1) + list(b2):
        v = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2, v + 0.3, f"{v:.2f}%",
                ha="center", va="bottom", fontsize=9, fontweight="bold")
    ax.set_xticks(x)
    ax.set_xticklabels(["Novel Detection\nRate (%)", "Known False-\nFlag Rate (%)"])
    ax.set_title("OSR Operating Point\n(at calibrated threshold)", **TITLE_KWARGS)
    ax.set_ylabel("Rate (%)")
    ax.legend(fontsize=8)
    ax.grid(axis="y", linestyle=":", alpha=0.5)
    ax.spines[["top", "right"]].set_visible(False)

    plt.tight_layout()
    _save_fig(fig, os.path.join(OUTPUT_DIR, "0_summary_metrics.png"))
    print("[GRAPH] 0_summary_metrics.png")


# ============================================================
#  MAIN
# ============================================================

def main():
    print("\n" + "="*70)
    print("  ThreatMatrix — Phase 3: RF + OSR")
    print("="*70)
    t0 = time.time()

    # ── Load data ──
    df_known, df_novel = load_phase3_data()

    # ── Build label vector for known ──
    cls_to_idx = {c: i for i, c in enumerate(CLASS_NAMES)}
    y_known = df_known["attack_type"].map(cls_to_idx).to_numpy(dtype=np.int64)
    if np.isnan(y_known).any():
        raise ValueError("Unknown class in df_known after mapping.")

    # ── Stratified 70/15/15 split ──
    print("\n" + "="*70)
    print("  STRATIFIED SPLIT  70/15/15 by class")
    print("="*70)
    tr_idx, va_idx, te_idx = stratified_split(df_known, y_known,
                                               TRAIN_RATIO, VAL_RATIO, seed=42)
    print(f"  train: {len(tr_idx):>9,}")
    print(f"  val  : {len(va_idx):>9,}  (used for OSR threshold calibration)")
    print(f"  test : {len(te_idx):>9,}  (closed-world + part of OSR test)")

    df_tr = df_known.iloc[tr_idx].reset_index(drop=True)
    df_va = df_known.iloc[va_idx].reset_index(drop=True)
    df_te = df_known.iloc[te_idx].reset_index(drop=True)
    y_tr  = y_known[tr_idx]
    y_va  = y_known[va_idx]
    y_te  = y_known[te_idx]

    # ── Preprocess ──
    print("\n[INFO] Fitting preprocessor on training set...")
    pre  = TreePreprocessor(UNIVERSAL_FEATURES)
    X_tr = pre.fit_transform(df_tr)
    X_va, _ = pre.transform(df_va)
    X_te, _ = pre.transform(df_te)
    X_nv, _ = pre.transform(df_novel)
    print(f"  X_tr: {X_tr.shape}")
    print(f"  X_va: {X_va.shape}")
    print(f"  X_te: {X_te.shape}")
    print(f"  X_nv: {X_nv.shape}  (novel — held out 100% for OSR test)")

    del df_tr; gc.collect()

    # ── Train RF ──
    rf = train_rf(X_tr, y_tr)

    # ── Closed-world evaluation ──
    closed_metrics = evaluate_closed_world(rf, X_te, y_te, CLASS_NAMES)
    plot_closed_world_confusion(closed_metrics["confusion_matrix"], CLASS_NAMES)
    plot_per_class_f1(closed_metrics["per_class"])
    plot_feature_importance(rf, UNIVERSAL_FEATURES, top_n=15)

    # ── Fit leaf embedding + per-class Gaussians on VAL ──
    pca, leaf_means, leaf_invcovs = fit_leaf_embedding(rf, X_va, y_va, CLASS_NAMES)

    # ── Build temporary opener (without thresholds) ──
    tmp_opener = OpenSetClassifier(
        rf=rf, class_names=CLASS_NAMES, feature_names=UNIVERSAL_FEATURES,
        leaf_pca=pca, leaf_class_means=leaf_means,
        leaf_class_inv_covs=leaf_invcovs,
        thr_softmax=0.0, thr_maha=0.0)

    # ── Calibrate thresholds on VAL ──
    thr_softmax, thr_maha, calib_meta = calibrate_osr_thresholds(
        rf, tmp_opener.softmax_ood_score, tmp_opener.mahalanobis_ood_score,
        X_va, y_va, CLASS_NAMES)

    # ── Build final opener with calibrated thresholds ──
    opener = OpenSetClassifier(
        rf=rf, class_names=CLASS_NAMES, feature_names=UNIVERSAL_FEATURES,
        leaf_pca=pca, leaf_class_means=leaf_means,
        leaf_class_inv_covs=leaf_invcovs,
        thr_softmax=thr_softmax, thr_maha=thr_maha,
        calibration_metadata=calib_meta)
    print(f"\n  → {opener!r}")

    # ── Open-world evaluation ──
    novel_src   = df_novel["_source_file"].to_numpy()
    osr_results = evaluate_open_world(opener, X_te, y_te,
                                      X_nv, novel_src, CLASS_NAMES)

    # ── Plots ──
    plot_summary_metrics(closed_metrics, osr_results)
    plot_osr_roc_comparison(osr_results)
    plot_per_novel_source_comparison(osr_results)
    plot_score_distributions(osr_results)

    # ── SHAP (XAI) ──
    shap_summary_metric = None
    if SHAP_ENABLED:
        print("\n" + "="*70)
        print("  SHAP — TreeExplainer (XAI)")
        print("="*70)
        try:
            import shap
            rng = np.random.default_rng(42)
            n_shap     = min(SHAP_EXPLAIN_N, len(X_te))
            sample_idx = rng.choice(len(X_te), n_shap, replace=False)
            X_shap     = X_te[sample_idx]
            print(f"  Computing SHAP on {n_shap:,} test samples...")
            t_shap     = time.time()
            explainer  = shap.TreeExplainer(rf, feature_perturbation="tree_path_dependent")
            shap_values= explainer.shap_values(X_shap, check_additivity=False)
            print(f"  SHAP done in {time.time()-t_shap:.1f}s")
            ok = plot_shap_summary(shap_values, X_shap, UNIVERSAL_FEATURES, CLASS_NAMES)
            if ok:
                if isinstance(shap_values, list):
                    sv_arr = np.stack([np.abs(sv).mean(axis=0) for sv in shap_values],
                                      axis=1)
                else:
                    sv_arr = np.stack([np.abs(shap_values[..., c]).mean(axis=0)
                                       for c in range(shap_values.shape[-1])], axis=1)
                shap_summary_metric = {
                    feat: {
                        "mean_abs_shap_overall": float(sv_arr[i].mean()),
                        "per_class": {CLASS_NAMES[c]: float(sv_arr[i, c])
                                      for c in range(len(CLASS_NAMES))},
                    }
                    for i, feat in enumerate(UNIVERSAL_FEATURES)
                }
        except ImportError:
            print("  [WARN] shap package not installed — skipping. "
                  "Install with: pip install shap")
        except Exception as e:
            print(f"  [WARN] SHAP failed: {e}")

    # ── Save artifacts ──
    print("\n" + "="*70)
    print("  SAVING ARTIFACTS")
    print("="*70)
    joblib.dump(opener, os.path.join(OUTPUT_DIR, "model_anomaly_detector.pkl"),
                compress=3)
    joblib.dump(pre,    os.path.join(OUTPUT_DIR, "preprocessor_phase3.pkl"),
                compress=3)
    joblib.dump(UNIVERSAL_FEATURES,
                os.path.join(OUTPUT_DIR, "feature_names.pkl"), compress=3)
    print(f"  ✓ model_anomaly_detector.pkl")
    print(f"  ✓ preprocessor_phase3.pkl")
    print(f"  ✓ feature_names.pkl")

    for stale in ["model_autoencoder.pt", "preprocessor_ae.pkl",
                  "preprocessor_raw.pkl"]:
        p = os.path.join(OUTPUT_DIR, stale)
        if os.path.exists(p):
            try:
                os.remove(p)
                print(f"  ✗ removed stale: {stale}")
            except Exception:
                pass

    # ── Metrics JSON  
    payload = {
        "phase":   "phase3",
        "version": "rf_with_dual_osr",
        "approach": "Supervised RF + Open-Set Recognition (max-softmax + Mahalanobis-on-leaves)",
        "non_redundancy_with_phase1": {
            "phase1_role":         "binary attack-vs-benign gatekeeper, optimised for recall",
            "phase3_role":         "fine-grained 6-class classifier with open-set rejection",
            "phase1_output_space": ["Benign", "Attack"],
            "phase3_output_space": CLASS_NAMES + ["UNKNOWN"],
            "shared":              "tree-ensemble algorithmic family",
            "different":           "output spaces, training objectives, operational roles",
        },
        "architecture": {
            "rf_n_estimators":          RF_N_ESTIMATORS,
            "rf_max_depth":             RF_MAX_DEPTH,
            "rf_min_samples_leaf":      RF_MIN_SAMPLES_LEAF,
            "leaf_pca_dim":             LEAF_PCA_DIM,
            "osr_calibration_percentile": OSR_PERCENTILE,
            "n_known_classes":          N_CLASSES,
            "class_names":              CLASS_NAMES,
            "n_features":               N_FEATURES,
            "feature_names":            UNIVERSAL_FEATURES,
        },
        "osr_thresholds": {
            "max_softmax":        float(thr_softmax),
            "mahalanobis_leaves": float(thr_maha),
            "calibration_metadata": calib_meta,
        },
        "closed_world_metrics": closed_metrics,
        "open_world_metrics": {
            method: {k: v for k, v in res.items()
                     if k not in ("scores_known_sample", "scores_novel_sample")}
            for method, res in osr_results.items()
        },
        "shap_feature_importance": shap_summary_metric,
        "targets": {
            "novel_detection_rate_target_pct": TARGET_NOVEL_DETECTION_RATE * 100,
            "benign_fpr_target_max_pct":       TARGET_BENIGN_FPR_MAX * 100,
        },
    }
    with open(os.path.join(OUTPUT_DIR, "phase3_metrics.json"), "w") as f:
        json.dump(payload, f, indent=4, default=str)
    print(f"  ✓ phase3_metrics.json")

    # ── Final summary ──
    elapsed = (time.time() - t0) / 60
    print(f"\n{'='*70}")
    print(f"  [DONE] Phase 3 complete in {elapsed:.1f} min")
    print(f"{'='*70}")
    print(f"  Closed-world accuracy   : {closed_metrics['accuracy']*100:.2f}%")
    print(f"  Closed-world macro-F1   : {closed_metrics['macro_f1']*100:.2f}%")
    print(f"\n  Open-world (Mahalanobis-on-leaves):")
    m = osr_results["mahalanobis_leaves"]
    print(f"    AUROC                  : {m['auroc']:.4f}")
    print(f"    Novel detection rate   : {m['novel_flag_rate']*100:.2f}%")
    print(f"    Known false-flag rate  : {m['known_flag_rate']*100:.2f}%")
    print(f"\n  Open-world (Max-Softmax baseline):")
    s = osr_results["max_softmax"]
    print(f"    AUROC                  : {s['auroc']:.4f}")
    print(f"    Novel detection rate   : {s['novel_flag_rate']*100:.2f}%")
    print(f"    Known false-flag rate  : {s['known_flag_rate']*100:.2f}%")
    print(f"\n  Output: {OUTPUT_DIR}")
    print("="*70)


if __name__ == "__main__":
    main()