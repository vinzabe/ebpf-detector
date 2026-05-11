"""Threat detector.

Wraps a ``GradientBoostingClassifier`` over the feature schema in
``features.py``.  Persisted to disk via ``joblib`` along with the schema and
class labels so that load-time mismatches are rejected loudly.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

import joblib
import numpy as np
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler

from .events import ProcessTrace
from .features import FeatureExtractor


@dataclass
class DetectorConfig:
    """Hyper-parameters for the detector model."""

    n_estimators: int = 200
    max_depth: int = 3
    learning_rate: float = 0.1
    random_state: int = 1337
    suspicious_threshold: float = 0.5

    def as_dict(self) -> Dict[str, float]:
        return {
            "n_estimators": float(self.n_estimators),
            "max_depth": float(self.max_depth),
            "learning_rate": float(self.learning_rate),
            "random_state": float(self.random_state),
            "suspicious_threshold": float(self.suspicious_threshold),
        }


@dataclass
class Verdict:
    """Per-process classifier verdict."""

    pid: int
    comm: str
    label: str  # the predicted class (e.g. "malicious" / "benign")
    score: float  # P(malicious) in [0,1]
    suspicious: bool
    top_features: List[Tuple[str, float]] = field(default_factory=list)
    label_index: int = -1

    def to_dict(self) -> Dict[str, object]:
        return {
            "pid": self.pid,
            "comm": self.comm,
            "label": self.label,
            "score": float(self.score),
            "suspicious": bool(self.suspicious),
            "top_features": [(n, float(v)) for n, v in self.top_features],
        }


class EBPFThreatDetector:
    """A two-class GBM with a scaler and persisted feature schema."""

    def __init__(self, config: Optional[DetectorConfig] = None) -> None:
        self.config = config or DetectorConfig()
        self._extractor = FeatureExtractor()
        self._scaler: Optional[StandardScaler] = None
        self._model: Optional[GradientBoostingClassifier] = None
        self._classes: Optional[List[str]] = None
        self._malicious_index: int = -1

    # -- training -------------------------------------------------------

    def fit(self, traces: Sequence[ProcessTrace]) -> "EBPFThreatDetector":
        if not traces:
            raise ValueError("cannot fit on empty corpus")
        labels = [t.label for t in traces]
        if any(l is None for l in labels):
            raise ValueError("all training traces must carry a label")
        unique = sorted(set(labels))
        if "malicious" not in unique:
            raise ValueError("training corpus must include label 'malicious'")
        if "benign" not in unique:
            raise ValueError("training corpus must include label 'benign'")
        X = self._extractor.transform(traces)
        scaler = StandardScaler()
        Xs = scaler.fit_transform(X)
        model = GradientBoostingClassifier(
            n_estimators=self.config.n_estimators,
            max_depth=self.config.max_depth,
            learning_rate=self.config.learning_rate,
            random_state=self.config.random_state,
        )
        model.fit(Xs, labels)
        self._scaler = scaler
        self._model = model
        self._classes = list(model.classes_)
        self._malicious_index = self._classes.index("malicious")
        return self

    @property
    def is_fitted(self) -> bool:
        return self._model is not None

    # -- inference ------------------------------------------------------

    def predict(self, traces: Sequence[ProcessTrace]) -> List[Verdict]:
        if not self.is_fitted:
            raise RuntimeError("detector is not fitted")
        if not traces:
            return []
        X = self._extractor.transform(traces)
        Xs = self._scaler.transform(X)
        probs = self._model.predict_proba(Xs)
        preds = self._model.predict(Xs)
        names = self._extractor.feature_names()
        importances = self._model.feature_importances_
        top_global = sorted(
            zip(names, importances), key=lambda kv: kv[1], reverse=True
        )[:8]
        out: List[Verdict] = []
        for trace, prob, pred, row in zip(traces, probs, preds, X):
            score = float(prob[self._malicious_index])
            # local explanation: feature_value * global_importance, top 5
            contrib = sorted(
                ((n, float(v) * float(imp)) for n, v, imp in zip(names, row, importances)),
                key=lambda kv: abs(kv[1]),
                reverse=True,
            )[:5]
            out.append(
                Verdict(
                    pid=trace.pid,
                    comm=trace.comm,
                    label=str(pred),
                    score=score,
                    suspicious=score >= self.config.suspicious_threshold,
                    top_features=contrib,
                    label_index=self._classes.index(str(pred)),
                )
            )
        return out

    # -- persistence ----------------------------------------------------

    def save(self, path: str) -> None:
        if not self.is_fitted:
            raise RuntimeError("cannot save unfitted detector")
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        payload = {
            "config": self.config.as_dict(),
            "feature_names": self._extractor.feature_names(),
            "classes": self._classes,
            "scaler": self._scaler,
            "model": self._model,
            "malicious_index": self._malicious_index,
            "schema_version": 1,
        }
        joblib.dump(payload, path)

    @classmethod
    def load(cls, path: str) -> "EBPFThreatDetector":
        payload = joblib.load(path)
        if payload.get("schema_version") != 1:
            raise ValueError("unsupported schema version")
        cfg_d = payload["config"]
        cfg = DetectorConfig(
            n_estimators=int(cfg_d["n_estimators"]),
            max_depth=int(cfg_d["max_depth"]),
            learning_rate=float(cfg_d["learning_rate"]),
            random_state=int(cfg_d["random_state"]),
            suspicious_threshold=float(cfg_d["suspicious_threshold"]),
        )
        det = cls(cfg)
        live_names = det._extractor.feature_names()
        if payload["feature_names"] != live_names:
            raise ValueError("persisted feature schema does not match library")
        det._scaler = payload["scaler"]
        det._model = payload["model"]
        det._classes = payload["classes"]
        det._malicious_index = int(payload["malicious_index"])
        return det
