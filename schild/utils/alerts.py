"""
Alert management utilities
"""

from datetime import datetime
from typing import Dict, List

from schild.core.config import COLORS


def create_alert(title: str, message: str, severity: str, hostname: str, alerts_list: List[Dict], memory,
                 notifier=None) -> Dict:  # DONE: TASK-10 — add notifier param
    """
    Generate and store security alert.
    
    Args:
        title: Alert title
        message: Alert message
        severity: Severity level (low, medium, high, critical)
        hostname: System hostname
        alerts_list: List to append alert to
        memory: GuardMemory instance
        notifier: Optional WebhookNotifier instance
        
    Returns:
        Alert dictionary
    """
    alert_entry = {
        "alert_id": f"alert-{len(alerts_list) + 1}",
        "timestamp": datetime.now().isoformat(),
        "title": title,
        "message": message,
        "severity": severity,
        "hostname": hostname
    }
    
    alerts_list.append(alert_entry)
    print(f"{COLORS['warning']}ALERT [{severity.upper()}]: {title} - {message}{COLORS['reset']}")
    
    # Save to memory
    if memory:
        memory.save_alert(
            title=alert_entry["title"],
            message=alert_entry["message"],
            severity=alert_entry["severity"],
            hostname=alert_entry["hostname"],
        )
    
    # DONE: TASK-10 — send webhook notification
    if notifier:
        notifier.notify(title=title, message=message,
                       severity=severity, hostname=hostname)
    
    return alert_entry

