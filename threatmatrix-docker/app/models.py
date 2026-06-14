# ============================================================
#  ThreatMatrix — Model Class Definitions
#
#  These classes MUST match exactly what was used during training
#  so that joblib.load() can  reconstruct them properly
#
#  Sources:
#    threatmatrix_binary.py      → EnsembleModel
#    threatmatrix_multiclass.py  → EnsembleModelMulticlass
#    threatmatrix_anomaly.py     → TreePreprocessor, OpenSetClassifier
# ============================================================

import numpy as np
import pandas as pd
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import RobustScaler


# ============================================================
#  PHASE 1 — BINARY ENSEMBLE
# ============================================================

class EnsembleModel:
    """
    Weighted soft-vote ensemble of RandomForest + XGBoost.
    Saved as model_ensemble.pkl
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
                f"weights={self.weights}, "
                f"threshold={self.threshold}, "
                f"low_conf_max={self.low_conf_max}, "
                f"high_conf_min={self.high_conf_min})")


# ============================================================
#  PHASE 2 — MULTICLASS ENSEMBLE
# ============================================================

class EnsembleModelMulticlass:
    """
    Weighted soft-vote ensemble of RandomForest + XGBoost (3-class).
    Saved as model_ensemble_mc.pkl
    """

    DOS_IDX = 0

    def __init__(self, rf, xgb_clf, class_names,
                 weights=(0.35, 0.65),
                 dos_weights=(0.65, 0.35),
                 confidence_min=0.70,
                 class_thresholds=None):
        self.rf               = rf
        self.xgb_clf          = xgb_clf
        self.class_names      = class_names
        self.weights          = weights
        self.dos_weights      = dos_weights
        self.confidence_min   = confidence_min
        self.class_thresholds = (
            list(class_thresholds)
            if class_thresholds is not None
            else [1.0 / len(class_names)] * len(class_names)
        )

    def predict_proba(self, X):
        p_rf  = self.rf.predict_proba(X)
        p_xgb = self.xgb_clf.predict_proba(X)
        return self.weights[0] * p_rf + self.weights[1] * p_xgb

    def _predict_proba_conditional(self, X):
        p_rf  = self.rf.predict_proba(X)
        p_xgb = self.xgb_clf.predict_proba(X)
        proba_std = self.weights[0] * p_rf + self.weights[1] * p_xgb
        _dw = getattr(self, 'dos_weights', self.weights)
        proba_dos = _dw[0] * p_rf + _dw[1] * p_xgb
        dos_wins  = np.argmax(proba_dos, axis=1) == self.DOS_IDX
        proba_out = proba_std.copy()
        proba_out[dos_wins] = proba_dos[dos_wins]
        return proba_out

    def predict(self, X):
        proba  = self._predict_proba_conditional(X)
        n      = proba.shape[0]
        _ct    = getattr(self, 'class_thresholds', [0.0] * proba.shape[1])
        thres  = np.array(getattr(self, 'class_thresholds', [0.0] * proba.shape[1]))
        preds  = np.empty(n, dtype=np.int8)
        ranked = np.argsort(proba, axis=1)[:, ::-1]
        for i in range(n):
            assigned = False
            for cls_idx in ranked[i]:
                if proba[i, cls_idx] >= thres[cls_idx]:
                    preds[i] = cls_idx
                    assigned = True
                    break
            if not assigned:
                preds[i] = ranked[i, 0]
        return preds

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
        thr_str = ", ".join(
            f"{c}={t:.3f}"
            for c, t in zip(self.class_names, self.class_thresholds)
        )
        return (
            f"EnsembleModelMulticlass(\n"
            f"  classes        = {self.class_names}\n"
            f"  global_weights = RF={self.weights[0]}, XGB={self.weights[1]}\n"
            f"  dos_weights    = RF={self.dos_weights[0]}, XGB={self.dos_weights[1]}\n"
            f"  confidence_min = {self.confidence_min}\n"
            f"  thresholds     = [{thr_str}]\n"
            f")"
        )


# ============================================================
#  PHASE 2 — LABEL COMPRESSOR
# ============================================================

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
#  PHASE 3 — TREE PREPROCESSOR
# ============================================================

class TreePreprocessor:

    def __init__(self, feature_names):
        self.feature_names = list(feature_names)
        self.imputer = SimpleImputer(strategy="median")
        self.scaler  = RobustScaler(quantile_range=(5.0, 95.0))

    def _select(self, df):
        miss = [c for c in self.feature_names if c not in df.columns]
        if miss:
            for c in miss:
                df[c] = np.nan
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
#  PHASE 3 — OPEN-SET CLASSIFIER
# ============================================================

class OpenSetClassifier:

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
        self.thr_softmax         = float(thr_softmax)
        self.thr_maha            = float(thr_maha)
        self.calibration_metadata = calibration_metadata or {}

    # ── leaf embedding ──
    def _leaf_embed(self, X):
        leaves = self.rf.apply(X)
        return self.leaf_pca.transform(leaves.astype(np.float32))

    # ── per-method OOD scores ──
    def softmax_ood_score(self, X):
        """Max-softmax baseline: 1 - max(proba). Higher = more OOD."""
        proba = self.rf.predict_proba(X)
        return 1.0 - proba.max(axis=1)

    def mahalanobis_ood_score(self, X):
        """Mahalanobis-on-leaves: min-over-classes distance. Higher = more OOD."""
        emb = self._leaf_embed(X).astype(np.float64)
        n = emb.shape[0]
        dists = np.full((n, len(self.class_names)), np.inf, dtype=np.float64)
        for ci, cname in enumerate(self.class_names):
            if cname not in self.leaf_class_means:
                continue
            mu  = self.leaf_class_means[cname]
            inv = self.leaf_class_inv_covs[cname]
            d = emb - mu
            dists[:, ci] = np.sqrt(
                np.einsum("ij,jk,ik->i", d, inv, d).clip(min=0))
        return dists.min(axis=1).astype(np.float32)

    # ── unified prediction APIs ──
    def predict_with_osr_softmax(self, X):
        """Returns (predicted_class_or_UNKNOWN, ood_score). PRODUCTION primary."""
        cls_idx = self.rf.predict(X)
        ood     = self.softmax_ood_score(X)
        labels  = np.array([self.class_names[i] for i in cls_idx], dtype=object)
        labels[ood > self.thr_softmax] = "UNKNOWN"
        return labels, ood

    def predict_with_osr_maha(self, X):
        """Returns (predicted_class_or_UNKNOWN, ood_score). Research path."""
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