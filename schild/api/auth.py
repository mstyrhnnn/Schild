"""
SCHILD API Authentication

Simple API key validation via X-Schild-Token header.
Uses constant-time HMAC comparison to prevent timing attacks.
"""

import hmac
import os
from typing import Optional

from fastapi import Header, HTTPException, Depends

from schild.core.config import API_SECRET


def _verify_token(token: str) -> bool:
    """Constant-time comparison."""
    if not API_SECRET:
        # No secret configured = auth disabled (development mode)
        return True
    return hmac.compare_digest(token.encode(), API_SECRET.encode())


async def require_auth(
    x_schild_token: Optional[str] = Header(None, alias="X-Schild-Token"),
):
    """FastAPI dependency that enforces API key authentication."""
    if not API_SECRET:
        # Auth disabled if no secret is set
        return True
    if not x_schild_token:
        raise HTTPException(status_code=401, detail="Missing X-Schild-Token header")
    if not _verify_token(x_schild_token):
        raise HTTPException(status_code=403, detail="Invalid API token")
    return True
