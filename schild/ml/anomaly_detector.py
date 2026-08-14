import json
import time
import threading
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Callable

try:
    import numpy as np  # type: ignore
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False

from schild.core.config import ANOMALY_ZSCORE_THRESHOLD, COLORS
from schild.core.memory import SchildMemory
from schild.ml.baseline_profiler import BaselineProfiler, METRICS
from schild.ml.feature_engineer import FeatureEngineer
from schild.ml.pipelines.training_pipeline import TrainingPipeline, DEFAULT_MODELS
from schild.ml.models.model_registry import DEFAULT_MODEL_DIR


class AnomalyDetector:
    """
    Multi-layer anomaly detection engine.

    Layer 1 (Statistical): Z-score comparison against stored baseline.
    Layer 2 (ML Ensemble): Voting across all trained models.
    Both layers produce independent verdicts, then combined.
    """

    def __init__(
        self,
        memory: SchildMemory,
        profiler: Optional[BaselineProfiler] = None,
        zscore_threshold: float = ANOMALY_ZSCORE_THRESHOLD,
        model_dir: Path = DEFAULT_MODEL_DIR,
    ):
        self.memory = memory
        self.profiler = profiler or BaselineProfiler(memory)
        self.zscore_threshold = zscore_threshold
        self.model_dir = Path(model_dir)

        # Training pipeline (manages all models)
        self.training_pipeline = TrainingPipeline(
            memory=memory,
            profiler=self.profiler,
            model_dir=model_dir,
            models=DEFAULT_MODELS,
        )

        # Feature engineer for inference
        self._feature_eng = FeatureEngineer(window=5)

        # Load pre-trained models if available
        self._models_loaded = False
        self._try_load_models()

    # ─────────────────────────────────────────────────────────────────────────

    def _try_load_models(self):
        """Attempt to load models from disk silently."""
        if self.training_pipeline.has_trained_models():
            n = self.training_pipeline.load_models()
            if n > 0:
                self._models_loaded = True

    # ─────────────────────────────────────────────────────────────────────────
    # Main Detection
    # ─────────────────────────────────────────────────────────────────────────

    def detect(self) -> List[Dict]:
        """
        Run anomaly detection on a current live sample.
        Returns list of anomaly dicts (empty = no anomalies).
        """
        current = self.profiler.sample_once()
        anomalies = []

        # ── Layer 1: Statistical Z-score ────────────────────────────────────
        stat_anomalies = self._statistical_detect(current)
        anomalies.extend(stat_anomalies)

        # ── Layer 2: ML Ensemble ─────────────────────────────────────────────
        if HAS_SKLEARN and self._models_loaded:
            ml_result = self._ensemble_detect(current)
            if ml_result:
                anomalies.append(ml_result)
        elif not self._models_loaded:
            pass  # Silent — no models trained yet

        # Deduplicate by metric
        seen = set()
        unique_anomalies = []
        for a in anomalies:
            key = a.get("metric", "unknown")
            if key not in seen:
                seen.add(key)
                unique_anomalies.append(a)

        return unique_anomalies

    # ─────────────────────────────────────────────────────────────────────────
    # Layer 1: Statistical
    # ─────────────────────────────────────────────────────────────────────────

    def _statistical_detect(self, current: Dict) -> List[Dict]:
        """Z-score based detection against stored baseline."""
        baseline = self.profiler.load_baseline()
        if not baseline:
            return []

        anomalies = []
        print(f"\n{COLORS['info']}📊 Statistical Anomaly Scan (Z-score threshold: {self.zscore_threshold}){COLORS['reset']}")
        print(f"  {'Metric':<30} {'Current':>10} {'Baseline μ':>12} {'Z-score':>10} {'Status':>12}")
        print("  " + "─" * 76)

        for metric, value in current.items():
            if metric not in baseline:
                continue
            bl = baseline[metric]
            mean = bl.get("mean", 0.0)
            std  = bl.get("std", 0.0)
            zscore = (value - mean) / std if std > 0 else 0.0
            is_anomaly = abs(zscore) > self.zscore_threshold
            status = f"{COLORS['error']} ANOMALY{COLORS['reset']}" if is_anomaly else f"{COLORS['success']} OK{COLORS['reset']}"
            print(f"  {metric:<30} {value:>10.2f} {mean:>12.2f} {zscore:>10.2f}  {status}")

            if is_anomaly:
                severity = "high" if abs(zscore) > self.zscore_threshold * 2 else "medium"
                anomaly = {
                    "layer":         "statistical",
                    "metric":        metric,
                    "current_value": round(value, 4),
                    "baseline_mean": round(mean, 4),
                    "baseline_std":  round(std, 4),
                    "zscore":        round(zscore, 4),
                    "direction":     "spike" if zscore > 0 else "drop",
                    "severity":      severity,
                    "timestamp":     datetime.now().isoformat(),
                }
                anomalies.append(anomaly)
                self.memory.save_event(
                    "STATISTICAL_ANOMALY",
                    f"[{severity.upper()}] {metric}: value={value:.2f}, baseline={mean:.2f} (Z={zscore:.2f})",
                    level="warning",
                )

        return anomalies

    # ─────────────────────────────────────────────────────────────────────────
    # Layer 2: ML Ensemble
    # ─────────────────────────────────────────────────────────────────────────

    def _ensemble_detect(self, current: Dict) -> Optional[Dict]:
        """Ensemble vote across all trained ML models."""
        try:
            # Build feature vector
            vec = self._feature_eng.transform_one(current)
            X = np.array([vec])

            votes_anomaly = 0
            votes_normal  = 0
            model_results = {}
            scores = []

            for model in self.training_pipeline.models:
                if not model.is_trained:
                    continue
                try:
                    pred   = model.predict(X)[0]   # +1 normal, -1 anomaly
                    score  = model.score_samples(X)[0]
                    scores.append(float(score))
                    is_anom = pred == -1
                    if is_anom:
                        votes_anomaly += 1
                    else:
                        votes_normal += 1
                    model_results[model.model_id] = {
                        "prediction": "anomaly" if is_anom else "normal",
                        "score": round(float(score), 5),
                    }
                except Exception:
                    pass

            total_votes = votes_anomaly + votes_normal
            if total_votes == 0:
                return None

            anomaly_fraction = votes_anomaly / total_votes
            is_ensemble_anomaly = anomaly_fraction > 0.5
            confidence = anomaly_fraction if is_ensemble_anomaly else (1 - anomaly_fraction)

            print(f"\n{COLORS['info']} ML Ensemble ({total_votes} models voting){COLORS['reset']}")
            for mid, res in model_results.items():
                icon = "" if res["prediction"] == "anomaly" else ""
                print(f"  {icon} {mid:<25} score={res['score']:>8.5f}  → {res['prediction']}")

            if is_ensemble_anomaly:
                severity = "high" if anomaly_fraction > 0.75 else "medium"
                result = {
                    "layer":            "ml_ensemble",
                    "metric":           "ensemble_vote",
                    "anomaly_fraction": round(anomaly_fraction, 3),
                    "confidence":       round(confidence, 3),
                    "votes_anomaly":    votes_anomaly,
                    "votes_normal":     votes_normal,
                    "model_results":    model_results,
                    "mean_score":       round(sum(scores) / len(scores), 5) if scores else 0.0,
                    "severity":         severity,
                    "timestamp":        datetime.now().isoformat(),
                }
                print(f"\n  {COLORS['error']} ENSEMBLE VERDICT: ANOMALY "
                      f"({votes_anomaly}/{total_votes} models, confidence={confidence:.1%}){COLORS['reset']}")
                self.memory.save_event(
                    "ML_ENSEMBLE_ANOMALY",
                    f"[{severity.upper()}] Ensemble detected anomaly: "
                    f"{votes_anomaly}/{total_votes} models, confidence={confidence:.1%}",
                    level="warning",
                )
                return result
            else:
                print(f"\n  {COLORS['success']} ENSEMBLE VERDICT: Normal "
                      f"({votes_normal}/{total_votes} models agree){COLORS['reset']}")
                return None

        except Exception as e:
            self.memory.save_event("ML_DETECT_ERROR", str(e), level="error")
            return None

    # ─────────────────────────────────────────────────────────────────────────
    # Training Delegation
    # ─────────────────────────────────────────────────────────────────────────

    def train(self, n_samples: int = 60) -> Dict:
        """Train all ML models. Delegates to TrainingPipeline."""
        report = self.training_pipeline.train(n_samples=n_samples)
        if any(m.is_trained for m in self.training_pipeline.models):
            self._models_loaded = True
        return report

    def update_online(self, n_new: int = 10) -> Dict:
        """Incremental online update. Delegates to TrainingPipeline."""
        return self.training_pipeline.update_online(n_new=n_new)

    def retrain(self, n_samples: int = 60) -> Dict:
        """Retrain all models from scratch with fresh samples."""
        print(f"{COLORS['warning']}  Retraining all models from scratch...{COLORS['reset']}")
        return self.train(n_samples=n_samples)

    # ─────────────────────────────────────────────────────────────────────────
    # Continuous Monitoring
    # ─────────────────────────────────────────────────────────────────────────

    def monitor_continuous(
        self,
        interval: int = 30,
        on_anomaly: Optional[Callable[[List[Dict]], None]] = None,
        stop_event: Optional[threading.Event] = None,
    ):
        """Run continuous anomaly monitoring loop."""
        print(f"{COLORS['info']}  Continuous anomaly monitoring started (interval: {interval}s){COLORS['reset']}")
        while stop_event is None or not stop_event.is_set():
            try:
                anomalies = self.detect()
                if anomalies and on_anomaly:
                    on_anomaly(anomalies)
                (stop_event or threading.Event()).wait(interval) if stop_event else time.sleep(interval)
            except Exception as e:
                self.memory.save_event("MONITOR_ERROR", str(e), level="error")
                time.sleep(interval)
