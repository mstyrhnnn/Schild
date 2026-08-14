"""
Schild ML Training Pipeline — Orchestrates full model training lifecycle.

Workflow:
  1. COLLECT  — Gather behavioral baseline samples
  2. ENGINEER — Transform to feature vectors
  3. TRAIN    — Fit all configured models
  4. EVALUATE — Cross-validate & compute metrics
  5. PERSIST  — Save models + metadata to disk
  6. REGISTER — Update model registry in SchildMemory

Supports:
  - Cold-start training (first time, no baseline)
  - Retraining (replace existing models with new baseline)
  - Online update (incremental update for adaptive models)
  - Model ensemble (voting across all trained models)
"""

import json
import time
import os
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Tuple

try:
    import numpy as np  # type: ignore
    from sklearn.model_selection import cross_val_score
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False

from schild.core.config import COLORS, BASELINE_WARMUP_SAMPLES
from schild.core.memory import SchildMemory
from schild.ml.feature_engineer import FeatureEngineer, N_FEATURES
from schild.ml.baseline_profiler import BaselineProfiler, METRICS
from schild.ml.models.model_registry import (
    BaseAnomalyModel,
    IsolationForestModel,
    OneClassSVMModel,
    LocalOutlierFactorModel,
    EllipticEnvelopeModel,
    OnlineSGDModel,
    DEFAULT_MODEL_DIR,
    HAS_SKLEARN,
)


DEFAULT_MODELS = [
    IsolationForestModel(contamination=0.05, n_estimators=150),
    OneClassSVMModel(nu=0.05),
    LocalOutlierFactorModel(n_neighbors=20, contamination=0.05),
    EllipticEnvelopeModel(contamination=0.05),
    OnlineSGDModel(nu=0.05),
]


class TrainingPipeline:
    """
    Full ML training pipeline for Schild behavioral anomaly detection.
    """

    def __init__(
        self,
        memory: SchildMemory,
        profiler: Optional[BaselineProfiler] = None,
        model_dir: Path = DEFAULT_MODEL_DIR,
        models: Optional[List[BaseAnomalyModel]] = None,
    ):
        self.memory = memory
        self.profiler = profiler or BaselineProfiler(memory)
        self.model_dir = Path(model_dir)
        self.models = models or DEFAULT_MODELS
        self.feature_engineer = FeatureEngineer(window=5)
        self._training_history: List[Dict] = []

    # ─────────────────────────────────────────────────────────────────────────
    # Full Training
    # ─────────────────────────────────────────────────────────────────────────

    def train(self, n_samples: int = BASELINE_WARMUP_SAMPLES) -> Dict:
        """
        Run full training pipeline:
          1. Collect samples → 2. Engineer features → 3. Train all models
          → 4. Evaluate → 5. Persist → 6. Return training report
        """
        if not HAS_SKLEARN:
            return {"error": "scikit-learn not installed. Run: pip install scikit-learn numpy"}

        print(f"\n{COLORS['hunt']}{'' * 64}{COLORS['reset']}")
        print(f"{COLORS['hunt']} Schild ML Training Pipeline{COLORS['reset']}")
        print(f"{COLORS['hunt']}{'' * 64}{COLORS['reset']}")
        print(f"  Models  : {len(self.models)}")
        print(f"  Samples : {n_samples}")
        print(f"  Features: {N_FEATURES}")
        print(f"  Storage : {self.model_dir}\n")

        # Step 1: Collect
        t0 = time.time()
        print(f"{COLORS['info']}[1/5] Collecting behavioral samples...{COLORS['reset']}")
        raw_samples = self._collect_samples(n_samples)
        print(f"   Collected {len(raw_samples)} samples in {time.time()-t0:.1f}s\n")

        # Step 2: Feature engineering
        print(f"{COLORS['info']}[2/5] Engineering features ({N_FEATURES} features)...{COLORS['reset']}")
        self.feature_engineer.reset_history()
        feature_vectors = self.feature_engineer.fit_transform(raw_samples)
        X = np.array(feature_vectors)
        print(f"   Feature matrix shape: {X.shape}\n")

        # Step 3: Train models
        print(f"{COLORS['info']}[3/5] Training models...{COLORS['reset']}")
        training_results = {}
        for model in self.models:
            t_start = time.time()
            print(f"  Training [{model.model_id}]...", end=" ", flush=True)
            try:
                model.train(X)
                elapsed = time.time() - t_start
                print(f" ({elapsed:.2f}s, {model.training_samples} samples)")
                training_results[model.model_id] = {
                    "status": "ok", "elapsed_s": round(elapsed, 2),
                    "samples": model.training_samples,
                }
            except Exception as e:
                print(f" Error: {e}")
                training_results[model.model_id] = {"status": "error", "error": str(e)}

        # Step 4: Evaluate (anomaly rate on training data)
        print(f"\n{COLORS['info']}[4/5] Evaluating models...{COLORS['reset']}")
        eval_results = self._evaluate(X, training_results)

        # Step 5: Persist
        print(f"\n{COLORS['info']}[5/5] Persisting models to {self.model_dir}...{COLORS['reset']}")
        saved_paths = {}
        for model in self.models:
            if model.is_trained:
                try:
                    path = model.save(self.model_dir)
                    saved_paths[model.model_id] = str(path)
                    print(f"   {model.model_id} → {path.name}")
                except Exception as e:
                    print(f"   {model.model_id} save failed: {e}")

        # Build training report
        report = {
            "timestamp": datetime.now().isoformat(),
            "n_samples": len(raw_samples),
            "n_features": N_FEATURES,
            "feature_names": self.feature_engineer.get_feature_names(),
            "models": training_results,
            "evaluation": eval_results,
            "saved_to": saved_paths,
        }

        # Save to memory
        self.memory.save_event(
            "ML_TRAINING",
            f"Trained {len([m for m in self.models if m.is_trained])} models on {len(raw_samples)} samples",
            level="info",
        )
        self.memory.save_scan_result("ml_training", report)
        self._training_history.append(report)

        print(f"\n{COLORS['success']} Training complete!{COLORS['reset']}")
        print(f"{COLORS['hunt']}{'' * 64}{COLORS['reset']}\n")

        return report

    # ─────────────────────────────────────────────────────────────────────────
    # Online Update
    # ─────────────────────────────────────────────────────────────────────────

    def update_online(self, new_samples: Optional[List[Dict]] = None, n_new: int = 10) -> Dict:
        """
        Incrementally update online-learning models with new samples.
        Use this to adapt to legitimate behavior changes over time.
        """
        if not HAS_SKLEARN:
            return {"error": "scikit-learn not installed"}

        raw = new_samples or self._collect_samples(n_new)
        vectors = self.feature_engineer.fit_transform(raw)
        X_new = np.array(vectors)

        updated = []
        for model in self.models:
            if model.is_trained and model.update(X_new):
                model.save(self.model_dir)
                updated.append(model.model_id)

        result = {
            "timestamp": datetime.now().isoformat(),
            "n_new_samples": len(raw),
            "updated_models": updated,
        }
        self.memory.save_event(
            "ML_ONLINE_UPDATE",
            f"Online update: {len(updated)} models updated with {len(raw)} samples",
            level="info",
        )
        return result

    # ─────────────────────────────────────────────────────────────────────────
    # Load Trained Models
    # ─────────────────────────────────────────────────────────────────────────

    def load_models(self) -> int:
        """Load all models from disk. Returns count of successfully loaded models."""
        count = 0
        for model in self.models:
            if model.load(self.model_dir):
                count += 1
                print(f"  📂 Loaded [{model.model_id}] "
                      f"({model.training_samples} training samples, {model.last_trained[:10] if model.last_trained else 'unknown'})")
        return count

    def has_trained_models(self) -> bool:
        """Check if any trained models exist on disk."""
        return any(
            (self.model_dir / f"{m.model_id}.pkl").exists()
            for m in self.models
        )

    # ─────────────────────────────────────────────────────────────────────────
    # Helpers
    # ─────────────────────────────────────────────────────────────────────────

    def _collect_samples(self, n: int) -> List[Dict]:
        """Collect n metric samples from the live system."""
        samples = []
        interval = self.profiler.sample_interval

        for i in range(n):
            s = self.profiler.sample_once()
            samples.append(s)
            progress = int((i + 1) / n * 40)
            bar = "█" * progress + "░" * (40 - progress)
            print(f"\r  [{bar}] {i+1}/{n}", end="", flush=True)
            if i < n - 1:
                time.sleep(min(interval, 2))  # Cap at 2s for training speed

        print()
        return samples

    def _evaluate(self, X: "np.ndarray", training_results: Dict) -> Dict:
        """Compute anomaly rate on training data for each model."""
        eval_out = {}
        for model in self.models:
            if not model.is_trained or training_results.get(model.model_id, {}).get("status") != "ok":
                continue
            try:
                preds = model.predict(X)
                anomaly_rate = float(np.sum(preds == -1) / len(preds))
                scores = model.score_samples(X)
                eval_out[model.model_id] = {
                    "anomaly_rate_on_train": round(anomaly_rate, 4),
                    "mean_score": round(float(np.mean(scores)), 4),
                    "std_score": round(float(np.std(scores)), 4),
                    "min_score": round(float(np.min(scores)), 4),
                }
                print(
                    f"  {model.model_id:<25} anomaly_rate={anomaly_rate:.2%} "
                    f"score_mean={np.mean(scores):.4f}"
                )
            except Exception as e:
                eval_out[model.model_id] = {"error": str(e)}
        return eval_out
