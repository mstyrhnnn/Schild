import json
import math
from datetime import datetime
from typing import List, Dict, Optional, Tuple
import collections


FEATURE_NAMES = [
    # Raw metrics
    "cpu_percent",
    "memory_percent",
    "network_connections",
    "process_count",
    "disk_io_read",
    "disk_io_write",
    "listening_ports",
    # Rolling mean (window=5)
    "cpu_mean5",
    "mem_mean5",
    "net_mean5",
    "proc_mean5",
    # Rolling std (window=5)
    "cpu_std5",
    "mem_std5",
    "net_std5",
    # Rate of change (delta)
    "cpu_delta",
    "mem_delta",
    "net_delta",
    "proc_delta",
    # Ratios
    "cpu_mem_ratio",
    "net_proc_ratio",
    # Temporal
    "hour_sin",
    "hour_cos",
    "dow_sin",
    "dow_cos",
]

N_FEATURES = len(FEATURE_NAMES)


class FeatureEngineer:
    """
    Transforms raw metric samples into ML feature vectors.
    Maintains a rolling window for history-dependent features.
    """

    def __init__(self, window: int = 5):
        self.window = window
        self._history: collections.deque = collections.deque(maxlen=window + 1)

    def fit_transform(self, samples: List[Dict[str, float]]) -> List[List[float]]:
        """Transform a batch of samples into feature vectors."""
        vectors = []
        for s in samples:
            self._history.append(s)
            vec = self._build_vector(s)
            vectors.append(vec)
        return vectors

    def transform_one(self, sample: Dict[str, float]) -> List[float]:
        """Transform a single sample (incremental, uses rolling history)."""
        self._history.append(sample)
        return self._build_vector(sample)

    def _build_vector(self, sample: Dict[str, float]) -> List[float]:
        hist = list(self._history)

        def get(key: str) -> float:
            return float(sample.get(key, 0.0))

        cpu = get("cpu_percent")
        mem = get("memory_percent")
        net = get("network_connections")
        proc = get("process_count")
        dr  = get("disk_io_read")
        dw  = get("disk_io_write")
        ports = get("listening_ports")

        # Rolling statistics
        def roll_mean(key):
            vals = [h.get(key, 0.0) for h in hist]
            return sum(vals) / max(len(vals), 1)

        def roll_std(key):
            vals = [h.get(key, 0.0) for h in hist]
            if len(vals) < 2:
                return 0.0
            m = sum(vals) / len(vals)
            return math.sqrt(sum((v - m) ** 2 for v in vals) / max(len(vals) - 1, 1))

        cpu_m5  = roll_mean("cpu_percent")
        mem_m5  = roll_mean("memory_percent")
        net_m5  = roll_mean("network_connections")
        proc_m5 = roll_mean("process_count")

        cpu_s5 = roll_std("cpu_percent")
        mem_s5 = roll_std("memory_percent")
        net_s5 = roll_std("network_connections")

        # Rate of change (vs previous sample)
        if len(hist) >= 2:
            prev = hist[-2]
            cpu_d  = cpu  - float(prev.get("cpu_percent", cpu))
            mem_d  = mem  - float(prev.get("memory_percent", mem))
            net_d  = net  - float(prev.get("network_connections", net))
            proc_d = proc - float(prev.get("process_count", proc))
        else:
            cpu_d = mem_d = net_d = proc_d = 0.0

        # Ratios (avoid /0)
        cpu_mem_ratio = cpu / max(mem, 0.1)
        net_proc_ratio = net / max(proc, 1.0)

        # Temporal encoding (cyclical)
        now = datetime.now()
        hour_sin = math.sin(2 * math.pi * now.hour / 24)
        hour_cos = math.cos(2 * math.pi * now.hour / 24)
        dow_sin  = math.sin(2 * math.pi * now.weekday() / 7)
        dow_cos  = math.cos(2 * math.pi * now.weekday() / 7)

        return [
            cpu, mem, net, proc, dr, dw, ports,
            cpu_m5, mem_m5, net_m5, proc_m5,
            cpu_s5, mem_s5, net_s5,
            cpu_d, mem_d, net_d, proc_d,
            cpu_mem_ratio, net_proc_ratio,
            hour_sin, hour_cos, dow_sin, dow_cos,
        ]

    def reset_history(self):
        self._history.clear()

    def get_feature_names(self) -> List[str]:
        return FEATURE_NAMES.copy()
