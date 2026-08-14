"""
SCHILD — Autonomous Engine for Guardian & Intelligent Security

Enterprise-grade autonomous defense platform with:
- API-key based AI (OpenAI / Anthropic / Gemini)
- MITRE ATT&CK-aligned threat hunting
- Zero-day behavioral detection
- ML anomaly detection
- IOC enrichment
- Autonomous response
"""

__version__ = "1.1.0"  # DONE: TASK-06
__author__ = "SCHILD Team"

from schild.core.agent import SchildAgent
from schild.core.config import DefenseMode, AIProvider, COLORS

__all__ = [
    "SchildAgent",
    "DefenseMode",
    "AIProvider",
    "COLORS",
]
