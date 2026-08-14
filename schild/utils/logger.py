"""
Logging utilities
"""

from datetime import datetime
from typing import Dict, List

from schild.core.config import MAX_LOGS_IN_MEMORY


def log_event(message: str, level: str, hostname: str, logs_list: List[Dict]) -> Dict:
    """
    Log event locally.
    
    Args:
        message: Log message
        level: Log level (info, warning, error, debug)
        hostname: System hostname
        logs_list: List to append log to
        
    Returns:
        Log entry dictionary
    """
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "level": level,
        "message": message,
        "hostname": hostname
    }
    
    logs_list.append(log_entry)
    
    # Keep only last MAX_LOGS_IN_MEMORY logs in memory
    if len(logs_list) > MAX_LOGS_IN_MEMORY:
        logs_list[:] = logs_list[-MAX_LOGS_IN_MEMORY:]
    
    return log_entry

