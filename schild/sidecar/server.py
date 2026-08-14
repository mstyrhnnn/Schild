"""
SCHILD Sidecar Server
Dijalankan di remote host (web client VM / DVWA).
Menerima perintah mitigasi dari SCHILD backend via HTTP over VPN.

Jalankan di web client VM:
    SCHILD_SIDECAR_SECRET=<secret> python -m schild.sidecar.server

Atau dengan uvicorn langsung:
    SCHILD_SIDECAR_SECRET=<secret> uvicorn schild.sidecar.server:app \
        --host 0.0.0.0 --port 8421 --workers 1
"""

# DONE: TASK-11.3

import os
import hmac
import hashlib
import shlex
import subprocess
import logging
import ipaddress
from datetime import datetime
from typing import Dict, Any

try:
    from fastapi import FastAPI, HTTPException, Header, Request
    from pydantic import BaseModel
except ImportError:
    raise ImportError("Sidecar requires fastapi and pydantic: pip install fastapi uvicorn pydantic")

logger = logging.getLogger("schild.sidecar")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

app = FastAPI(title="SCHILD Sidecar", version="1.1.0", docs_url=None, redoc_url=None)

# ─── Auth ────────────────────────────────────────────────────────────────────

SECRET = os.environ.get("SCHILD_SIDECAR_SECRET", "")
if not SECRET:
    raise RuntimeError("SCHILD_SIDECAR_SECRET environment variable is not set.")

def _verify_token(token: str) -> bool:
    """Constant-time comparison to prevent timing attacks."""
    return hmac.compare_digest(token.encode(), SECRET.encode())

# ─── Allowlist ───────────────────────────────────────────────────────────────

# Hanya action yang terdaftar yang bisa dieksekusi.
# Parameter divalidasi per-action, bukan diterima mentah.
_ACTION_HANDLERS: Dict[str, Any] = {}   # diisi oleh decorator @handler di bawah

def handler(action: str):
    """Register a function as handler for a specific action."""
    def decorator(fn):
        _ACTION_HANDLERS[action] = fn
        return fn
    return decorator

# ─── Request / Response Schema ───────────────────────────────────────────────

class MitigationRequest(BaseModel):
    action: str
    params: dict = {}

class MitigationResponse(BaseModel):
    action: str
    success: bool
    output: str
    timestamp: str

# ─── Action Handlers ─────────────────────────────────────────────────────────

@handler("block_ip")
def _block_ip(params: dict) -> str:
    ip = params.get("ip", "")
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise ValueError(f"Invalid IP address: {ip!r}")
    if ip.startswith(("127.", "10.", "192.168.", "172.")):
        raise ValueError(f"Refusing to block private IP: {ip}")
    result = subprocess.run(
        f"iptables -I INPUT -s {shlex.quote(ip)} -j DROP",
        shell=True, capture_output=True, text=True, timeout=10,
    )
    return result.stdout.strip() or result.stderr.strip() or f"Blocked {ip}."


@handler("unblock_ip")
def _unblock_ip(params: dict) -> str:
    ip = params.get("ip", "")
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise ValueError(f"Invalid IP address: {ip!r}")
    result = subprocess.run(
        f"iptables -D INPUT -s {shlex.quote(ip)} -j DROP",
        shell=True, capture_output=True, text=True, timeout=10,
    )
    return result.stdout.strip() or result.stderr.strip() or f"Unblocked {ip}."


@handler("kill_process")
def _kill_process(params: dict) -> str:
    pid = str(params.get("pid", ""))
    if not pid.isdigit():
        raise ValueError(f"PID must be numeric, got: {pid!r}")
    result = subprocess.run(
        f"kill -9 {shlex.quote(pid)}",
        shell=True, capture_output=True, text=True, timeout=5,
    )
    return result.stdout.strip() or f"Sent SIGKILL to PID {pid}."


@handler("stop_service")
def _stop_service(params: dict) -> str:
    _SERVICE_WHITELIST = {"nginx", "apache2", "mysql", "postgresql", "mariadb", "docker", "redis", "php-fpm"}
    service = params.get("service", "")
    if service not in _SERVICE_WHITELIST:
        raise ValueError(f"Service {service!r} not in whitelist: {sorted(_SERVICE_WHITELIST)}")
    result = subprocess.run(
        f"systemctl stop {shlex.quote(service)}",
        shell=True, capture_output=True, text=True, timeout=15,
    )
    return result.stdout.strip() or f"Service {service} stopped."


@handler("restart_service")
def _restart_service(params: dict) -> str:
    _SERVICE_WHITELIST = {"nginx", "apache2", "mysql", "postgresql", "mariadb", "docker", "redis", "php-fpm"}
    service = params.get("service", "")
    if service not in _SERVICE_WHITELIST:
        raise ValueError(f"Service {service!r} not in whitelist: {sorted(_SERVICE_WHITELIST)}")
    result = subprocess.run(
        f"systemctl restart {shlex.quote(service)}",
        shell=True, capture_output=True, text=True, timeout=30,
    )
    return result.stdout.strip() or f"Service {service} restarted."


@handler("get_status")
def _get_status(params: dict) -> str:
    """Health check — returns basic host info."""
    import platform
    return f"hostname={platform.node()} os={platform.system()} uptime={subprocess.getoutput('uptime -p 2>/dev/null || uptime')}"


# ─── Endpoints ───────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    """Public health check — no auth needed."""
    return {"status": "ok", "service": "schild-sidecar", "version": "1.1.0"}


@app.post("/mitigate", response_model=MitigationResponse)
def mitigate(
    req: MitigationRequest,
    x_schild_token: str = Header(..., description="SCHILD sidecar secret token"),
):
    # Auth check
    if not _verify_token(x_schild_token):
        logger.warning(f"Unauthorized request for action={req.action}")
        raise HTTPException(status_code=403, detail="Forbidden")

    # Action allowlist check
    handler_fn = _ACTION_HANDLERS.get(req.action)
    if handler_fn is None:
        logger.warning(f"Unknown action requested: {req.action}")
        raise HTTPException(status_code=400, detail=f"Unknown action: {req.action!r}")

    logger.info(f"Executing action={req.action} params={req.params}")
    try:
        output = handler_fn(req.params)
        success = True
    except ValueError as e:
        output = f"Validation error: {e}"
        success = False
        logger.warning(f"Validation error for {req.action}: {e}")
    except Exception as e:
        output = f"Execution error: {e}"
        success = False
        logger.error(f"Error executing {req.action}: {e}")

    return MitigationResponse(
        action=req.action,
        success=success,
        output=output,
        timestamp=datetime.now().isoformat(),
    )


# ─── Entry point ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("SCHILD_SIDECAR_PORT", "8421"))
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
