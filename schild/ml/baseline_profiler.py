import subprocess
import time
import json
import os
from datetime import datetime
from typing import Dict, List, Optional

from schild.core.config import (
    BASELINE_SAMPLE_INTERVAL, BASELINE_WARMUP_SAMPLES, COLORS,
)
from schild.core.memory import SchildMemory


METRICS = [
    "cpu_percent",
    "memory_percent",
    "network_connections",
    "process_count",
    "disk_io_read",
    "disk_io_write",
    "listening_ports",
]


class BaselineProfiler:
    """
    Samples system metrics and builds statistical baseline profiles.
    The baseline is used by AnomalyDetector to identify deviations.
    """

    def __init__(self, memory: SchildMemory, sample_interval: int = BASELINE_SAMPLE_INTERVAL):
        self.memory = memory
        self.sample_interval = sample_interval
        self._samples: Dict[str, List[float]] = {m: [] for m in METRICS}

    # ─────────────────────────────────────────────────────────────────────────

    def sample_once(self) -> Dict[str, float]:
        """Collect a single sample of all metrics."""
        sample = {}

        try:
            cpu = subprocess.getoutput(
                "grep 'cpu ' /proc/stat | awk '{usage=($2+$4)*100/($2+$4+$5)} END {print usage}'"
            )
            sample["cpu_percent"] = float(cpu) if cpu else 0.0
        except Exception:
            sample["cpu_percent"] = 0.0

        try:
            mem = subprocess.getoutput(
                "free | grep Mem | awk '{printf \"%.1f\", $3/$2 * 100.0}'"
            )
            sample["memory_percent"] = float(mem) if mem else 0.0
        except Exception:
            sample["memory_percent"] = 0.0

        try:
            conns = subprocess.getoutput(
                "ss -tn state established 2>/dev/null | wc -l"
            )
            sample["network_connections"] = float(conns.strip()) if conns.strip().isdigit() else 0.0
        except Exception:
            sample["network_connections"] = 0.0

        try:
            procs = subprocess.getoutput("ps aux --no-header 2>/dev/null | wc -l")
            sample["process_count"] = float(procs.strip()) if procs.strip().isdigit() else 0.0
        except Exception:
            sample["process_count"] = 0.0

        try:
            read_bytes = subprocess.getoutput(
                "cat /proc/diskstats 2>/dev/null | awk '{sum+=$6} END {print sum}'"
            )
            sample["disk_io_read"] = float(read_bytes) if read_bytes else 0.0
        except Exception:
            sample["disk_io_read"] = 0.0

        try:
            write_bytes = subprocess.getoutput(
                "cat /proc/diskstats 2>/dev/null | awk '{sum+=$10} END {print sum}'"
            )
            sample["disk_io_write"] = float(write_bytes) if write_bytes else 0.0
        except Exception:
            sample["disk_io_write"] = 0.0

        try:
            ports = subprocess.getoutput("ss -tlnp 2>/dev/null | grep LISTEN | wc -l")
            sample["listening_ports"] = float(ports.strip()) if ports.strip().isdigit() else 0.0
        except Exception:
            sample["listening_ports"] = 0.0

        return sample

    # ─────────────────────────────────────────────────────────────────────────

    def build_baseline(self, num_samples: int = BASELINE_WARMUP_SAMPLES) -> Dict[str, Dict]:
        """
        Collect `num_samples` samples and compute statistical baseline.
        Returns dict of metric → {mean, std, min, max, samples}.
        """
        print(f"\n{COLORS['info']}📊 Building behavioral baseline ({num_samples} samples, "
              f"{self.sample_interval}s interval)...{COLORS['reset']}")

        all_samples: Dict[str, List[float]] = {m: [] for m in METRICS}

        for i in range(1, num_samples + 1):
            sample = self.sample_once()
            for metric, value in sample.items():
                all_samples[metric].append(value)

            progress = int((i / num_samples) * 40)
            bar = "█" * progress + "░" * (40 - progress)
            print(f"\r  [{bar}] {i}/{num_samples}", end="", flush=True)

            if i < num_samples:
                time.sleep(self.sample_interval)

        print(f"\n{COLORS['success']}  Baseline collection complete.{COLORS['reset']}")

        # Compute statistics
        baselines = {}
        for metric, values in all_samples.items():
            if not values:
                continue
            n = len(values)
            mean = sum(values) / n
            variance = sum((v - mean) ** 2 for v in values) / max(n - 1, 1)
            std = variance ** 0.5
            baselines[metric] = {
                "mean": round(mean, 4),
                "std": round(std, 4),
                "min": round(min(values), 4),
                "max": round(max(values), 4),
                "samples": n,
                "timestamp": datetime.now().isoformat(),
            }
            self.memory.save_baseline(metric, baselines[metric])
            print(
                f"  {metric:30s} mean={mean:.2f} std={std:.2f} "
                f"[{min(values):.2f} – {max(values):.2f}]"
            )

        return baselines

    # ─────────────────────────────────────────────────────────────────────────

    def load_baseline(self) -> Dict[str, Dict]:
        """Load the most recent baseline from memory."""
        baselines = {}
        for metric in METRICS:
            bl = self.memory.get_latest_baseline(metric)
            if bl:
                baselines[metric] = bl
        return baselines

    def is_baseline_ready(self) -> bool:
        """Check if a valid baseline exists in memory."""
        baselines = self.load_baseline()
        return len(baselines) >= len(METRICS) // 2  # At least half the metrics
