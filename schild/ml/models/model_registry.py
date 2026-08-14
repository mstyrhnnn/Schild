import os
import json
import time
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Any

try:
    import numpy as np  # type: ignore
    import joblib  # type: ignore
    from sklearn.ensemble import IsolationForest
    from sklearn.svm import OneClassSVM
    from sklearn.neighbors import LocalOutlierFactor
    from sklearn.covariance import EllipticEnvelope
    from sklearn.preprocessing import StandardScaler
    from sklearn.linear_model import SGDOneClassSVM
    from sklearn.pipeline import Pipeline
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False

from schild.ml.feature_engineer import FeatureEngineer, N_FEATURES, FEATURE_NAMES

# Default model storage directory (relative to caller's CWD)
DEFAULT_MODEL_DIR = Path("schild/ml/models")


# ─────────────────────────────────────────────────────────────────────────────
# Base Model Interface
# ─────────────────────────────────────────────────────────────────────────────

class BaseAnomalyModel(ABC):
    """Base class for all Schild anomaly detection models."""

    def __init__(self, model_id: str, description: str):
        self.model_id = model_id
        self.description = description
        self.is_trained = False
        self.training_samples = 0
        self.last_trained: Optional[str] = None
        self.metadata: Dict = {}

    @abstractmethod
    def train(self, X: "np.ndarray") -> None:
        """Train the model on feature matrix X (shape: n_samples × n_features)."""
        ...

    @abstractmethod
    def predict(self, X: "np.ndarray") -> "np.ndarray":
        """Predict: returns array of +1 (normal) or -1 (anomaly)."""
        ...

    @abstractmethod
    def score_samples(self, X: "np.ndarray") -> "np.ndarray":
        """Return anomaly scores (lower = more anomalous)."""
        ...

    def update(self, X: "np.ndarray") -> bool:
        """
        Incremental update (online learning).
        Default: no-op for batch models. Override in online models.
        Returns True if update was performed.
        """
        return False

    def save(self, model_dir: Path = DEFAULT_MODEL_DIR) -> Path:
        """Persist model to disk. Returns saved path."""
        model_dir.mkdir(parents=True, exist_ok=True)
        path = model_dir / f"{self.model_id}.pkl"
        meta_path = model_dir / f"{self.model_id}.meta.json"
        joblib.dump(self._get_model_object(), path)
        meta = {
            "model_id": self.model_id,
            "description": self.description,
            "is_trained": self.is_trained,
            "training_samples": self.training_samples,
            "last_trained": self.last_trained,
            "feature_names": FEATURE_NAMES,
            **self.metadata,
        }
        meta_path.write_text(json.dumps(meta, indent=2))
        return path

    def load(self, model_dir: Path = DEFAULT_MODEL_DIR) -> bool:
        """Load model from disk. Returns True on success."""
        path = model_dir / f"{self.model_id}.pkl"
        meta_path = model_dir / f"{self.model_id}.meta.json"
        if not path.exists():
            return False
        try:
            self._set_model_object(joblib.load(path))
            if meta_path.exists():
                meta = json.loads(meta_path.read_text())
                self.is_trained = meta.get("is_trained", True)
                self.training_samples = meta.get("training_samples", 0)
                self.last_trained = meta.get("last_trained")
                self.metadata.update(meta)
            else:
                self.is_trained = True
            return True
        except Exception:
            return False

    @abstractmethod
    def _get_model_object(self) -> Any:
        ...

    @abstractmethod
    def _set_model_object(self, obj: Any) -> None:
        ...


# ─────────────────────────────────────────────────────────────────────────────
# Model Implementations
# ─────────────────────────────────────────────────────────────────────────────

class IsolationForestModel(BaseAnomalyModel):
    """
    Isolation Forest — Best general-purpose anomaly detector.
    Unsupervised, works without labels. Handles high dimensionality.
    """

    def __init__(self, contamination: float = 0.05, n_estimators: int = 150):
        super().__init__("isolation_forest", "Isolation Forest (unsupervised, tree-based)")
        self._pipeline: Optional["Pipeline"] = None
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.metadata = {"contamination": contamination, "n_estimators": n_estimators}

    def train(self, X: "np.ndarray") -> None:
        self._pipeline = Pipeline([
            ("scaler", StandardScaler()),
            ("model", IsolationForest(
                n_estimators=self.n_estimators,
                contamination=self.contamination,
                random_state=42,
                n_jobs=-1,
            )),
        ])
        self._pipeline.fit(X)
        self.is_trained = True
        self.training_samples = len(X)
        self.last_trained = datetime.now().isoformat()

    def predict(self, X: "np.ndarray") -> "np.ndarray":
        return self._pipeline.predict(X)

    def score_samples(self, X: "np.ndarray") -> "np.ndarray":
        return self._pipeline.score_samples(X)

    def _get_model_object(self):
        return self._pipeline

    def _set_model_object(self, obj):
        self._pipeline = obj


class OneClassSVMModel(BaseAnomalyModel):
    """
    One-Class SVM — Good for complex high-dimensional boundaries.
    More sensitive, higher false positive rate than IF but catches edge cases.
    """

    def __init__(self, nu: float = 0.05, kernel: str = "rbf"):
        super().__init__("one_class_svm", "One-Class SVM (kernel-based boundary)")
        self._pipeline: Optional["Pipeline"] = None
        self.nu = nu
        self.kernel = kernel
        self.metadata = {"nu": nu, "kernel": kernel}

    def train(self, X: "np.ndarray") -> None:
        self._pipeline = Pipeline([
            ("scaler", StandardScaler()),
            ("model", OneClassSVM(nu=self.nu, kernel=self.kernel, gamma="scale")),
        ])
        self._pipeline.fit(X)
        self.is_trained = True
        self.training_samples = len(X)
        self.last_trained = datetime.now().isoformat()

    def predict(self, X: "np.ndarray") -> "np.ndarray":
        return self._pipeline.predict(X)

    def score_samples(self, X: "np.ndarray") -> "np.ndarray":
        return self._pipeline.decision_function(X)

    def _get_model_object(self):
        return self._pipeline

    def _set_model_object(self, obj):
        self._pipeline = obj


class LocalOutlierFactorModel(BaseAnomalyModel):
    """
    Local Outlier Factor — Density-based, good for detecting local anomalies
    (e.g., a process doing something unusual compared to its neighbors).
    NOTE: LOF does not support traditional predict after fit (novelty=True needed).
    """

    def __init__(self, n_neighbors: int = 20, contamination: float = 0.05):
        super().__init__("local_outlier_factor", "Local Outlier Factor (density-based)")
        self._pipeline: Optional["Pipeline"] = None
        self.n_neighbors = n_neighbors
        self.contamination = contamination
        self.metadata = {"n_neighbors": n_neighbors, "contamination": contamination}

    def train(self, X: "np.ndarray") -> None:
        self._pipeline = Pipeline([
            ("scaler", StandardScaler()),
            ("model", LocalOutlierFactor(
                n_neighbors=self.n_neighbors,
                contamination=self.contamination,
                novelty=True,  # Enable predict() on new data
                n_jobs=-1,
            )),
        ])
        self._pipeline.fit(X)
        self.is_trained = True
        self.training_samples = len(X)
        self.last_trained = datetime.now().isoformat()

    def predict(self, X: "np.ndarray") -> "np.ndarray":
        return self._pipeline.predict(X)

    def score_samples(self, X: "np.ndarray") -> "np.ndarray":
        return self._pipeline.score_samples(X)

    def _get_model_object(self):
        return self._pipeline

    def _set_model_object(self, obj):
        self._pipeline = obj


class EllipticEnvelopeModel(BaseAnomalyModel):
    """
    Elliptic Envelope — Gaussian assumption, very fast.
    Best when metrics follow normal distribution (CPU at rest, etc.).
    """

    def __init__(self, contamination: float = 0.05):
        super().__init__("elliptic_envelope", "Elliptic Envelope (Gaussian covariance)")
        self._pipeline: Optional["Pipeline"] = None
        self.contamination = contamination
        self.metadata = {"contamination": contamination}

    def train(self, X: "np.ndarray") -> None:
        self._pipeline = Pipeline([
            ("scaler", StandardScaler()),
            ("model", EllipticEnvelope(
                contamination=self.contamination,
                random_state=42,
                support_fraction=0.9,
            )),
        ])
        self._pipeline.fit(X)
        self.is_trained = True
        self.training_samples = len(X)
        self.last_trained = datetime.now().isoformat()

    def predict(self, X: "np.ndarray") -> "np.ndarray":
        return self._pipeline.predict(X)

    def score_samples(self, X: "np.ndarray") -> "np.ndarray":
        return self._pipeline.score_samples(X)

    def _get_model_object(self):
        return self._pipeline

    def _set_model_object(self, obj):
        self._pipeline = obj


class OnlineSGDModel(BaseAnomalyModel):
    """
    Online SGD One-Class SVM — Supports incremental learning.
    Adapts to drift in system behavior over time.
    Use this for production systems where behavior evolves.
    """

    def __init__(self, nu: float = 0.05):
        super().__init__("online_sgd", "Online SGD One-Class SVM (incremental learning)")
        self._scaler: Optional["StandardScaler"] = None
        self._model: Optional["SGDOneClassSVM"] = None
        self.nu = nu
        self.metadata = {"nu": nu, "supports_online": True}

    def train(self, X: "np.ndarray") -> None:
        self._scaler = StandardScaler()
        X_scaled = self._scaler.fit_transform(X)
        self._model = SGDOneClassSVM(nu=self.nu, random_state=42)
        self._model.fit(X_scaled)
        self.is_trained = True
        self.training_samples = len(X)
        self.last_trained = datetime.now().isoformat()

    def update(self, X: "np.ndarray") -> bool:
        """Incremental update — adapts to new behavior."""
        if not self.is_trained or self._model is None:
            return False
        X_scaled = self._scaler.transform(X)
        self._model.partial_fit(X_scaled)
        self.training_samples += len(X)
        self.last_trained = datetime.now().isoformat()
        return True

    def predict(self, X: "np.ndarray") -> "np.ndarray":
        X_scaled = self._scaler.transform(X)
        return self._model.predict(X_scaled)

    def score_samples(self, X: "np.ndarray") -> "np.ndarray":
        X_scaled = self._scaler.transform(X)
        return self._model.score_samples(X_scaled)

    def _get_model_object(self):
        return {"scaler": self._scaler, "model": self._model}

    def _set_model_object(self, obj):
        self._scaler = obj["scaler"]
        self._model = obj["model"]
