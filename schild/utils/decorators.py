"""Error handling decorators for vulnerability checks"""

import functools 
import logging
from typing import Callable, Any


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


def safe_check(check_name: str):
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            try:
                return func(*args, **kwargs)
            except PermissionError as e: 
                logging.warning(f"[{check_name}] Permission denied: {e}")
                return None
            except FileNotFoundError as e:
                logging.debug(f"[{check_name}] file not found: {e}")
                return None
            except Exception as e:
                logging.error(f"[{check_name}] unexpected error: {e}", exc_info=True)
                return None
        return wrapper
    return decorator




    


    
