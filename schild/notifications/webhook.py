"""
SCHILD Webhook Notifier
Supports: Slack incoming webhooks, generic HTTP POST webhooks

Config via environment variables:
  SCHILD_WEBHOOK_URL      — Slack or generic webhook URL
  SCHILD_WEBHOOK_MIN_SEV  — minimum severity to notify (low/medium/high/critical)
                            default: high

DONE: TASK-10
"""

import os
import json
import requests
from datetime import datetime

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
SEVERITY_COLORS = {
    "low":      "#36a64f",
    "medium":   "#f0a500",
    "high":     "#e01e5a",
    "critical": "#8b0000",
}


class WebhookNotifier:
    def __init__(
        self,
        webhook_url: str = "",
        min_severity: str = "high",
    ):
        self.url = webhook_url or os.getenv("SCHILD_WEBHOOK_URL", "")
        min_sev_env = os.getenv("SCHILD_WEBHOOK_MIN_SEV", min_severity)
        self.min_severity = SEVERITY_ORDER.get(min_sev_env.lower(), 2)
        self.enabled = bool(self.url)

    def notify(self, title: str, message: str, severity: str = "high",
               hostname: str = "") -> bool:
        """
        Send alert to webhook.
        Returns True if sent successfully, False otherwise.
        """
        if not self.enabled:
            return False
        if SEVERITY_ORDER.get(severity.lower(), 0) < self.min_severity:
            return False

        payload = self._build_payload(title, message, severity, hostname)
        try:
            resp = requests.post(
                self.url,
                json=payload,
                timeout=5,
                headers={"Content-Type": "application/json"},
            )
            return resp.status_code in (200, 204)
        except Exception:
            return False

    def _build_payload(self, title: str, message: str,
                       severity: str, hostname: str) -> dict:
        """Build Slack-compatible payload (also works as generic JSON POST)."""
        color = SEVERITY_COLORS.get(severity.lower(), "#cccccc")
        return {
            "attachments": [
                {
                    "color": color,
                    "title": f"SCHILD [{severity.upper()}]: {title}",
                    "text": message,
                    "footer": f"Host: {hostname or 'unknown'} | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                    "footer_icon": "https://www.schild.dev/icon.png",
                }
            ]
        }
