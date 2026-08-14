"""
SCHILD REST API Backend

FastAPI server that exposes the full SchildAgent capability set over HTTP.
Replaces the interactive CLI for programmatic / frontend consumption.

Start with:
    schild --serve
    schild --serve --port 9000 --host 0.0.0.0

Or directly:
    uvicorn schild.api.server:create_app --factory --host 0.0.0.0 --port 8420
"""

import os
import logging
import threading
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from schild.api.auth import require_auth
from schild.api.schemas import (
    HealthResponse, StatusResponse, ModeUpdateRequest, MessageResponse,
    HuntRequest, HuntResponse, ScanResponse,
    AssetResponse,
    AlertListResponse, AlertItem,
    IOCListResponse, IOCItem, EnrichRequest,
    EventsResponse,
    BaselineBuildRequest, MLTrainRequest,
    MonitorStartRequest,
    MirrorStartRequest, MirrorStatsResponse,
    ChatRequest, ChatResponse,
    ContainRequest, ContainResponse,
    SidecarRegisterRequest, SidecarListResponse, SidecarItem,
)

logger = logging.getLogger("schild.api")

# ---------------------------------------------------------------------------
# Agent singleton — initialized at startup, shared across requests
# ---------------------------------------------------------------------------

_agent = None  # type: Optional["SchildAgent"]
_agent_lock = threading.Lock()


def _get_agent():
    """Return the initialized SchildAgent singleton."""
    if _agent is None:
        raise HTTPException(status_code=503, detail="Agent not initialized")
    return _agent


# ---------------------------------------------------------------------------
# App Factory
# ---------------------------------------------------------------------------

def create_app(
    defense_mode: str = "hunt",
    ai_provider: str = "openai",
    db_path: str = "schild_memory.db",
    api_key: Optional[str] = None,
) -> FastAPI:
    """
    Create and return a configured FastAPI application.

    The SchildAgent is instantiated during the lifespan startup event.
    This factory pattern allows both CLI integration and direct uvicorn usage.
    """

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        global _agent
        logger.info("Initializing SchildAgent...")

        from schild.core.config import DefenseMode, AIProvider
        from schild.core.agent import SchildAgent

        mode = DefenseMode(defense_mode)
        provider = AIProvider(ai_provider)

        _agent = SchildAgent(
            defense_mode=mode,
            db_path=db_path,
            ai_provider=provider,
            api_key=api_key,
        )
        logger.info(
            "SchildAgent ready: mode=%s provider=%s",
            mode.value, provider.value,
        )
        yield

        # Cleanup
        logger.info("Shutting down SchildAgent...")
        if _agent._monitoring_active:
            _agent.stop_monitoring()
        if _agent.ingestion:
            _agent.ingestion.stop_all()
        _agent.memory.close()
        logger.info("Shutdown complete.")

    app = FastAPI(
        title="SCHILD API",
        description="Autonomous Defense & AI-Driven Threat Hunting",
        version="1.2.0",
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url=None,
    )

    # CORS — allow frontend dev servers
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Register all route groups
    _register_routes(app)

    return app


# ---------------------------------------------------------------------------
# Route Registration
# ---------------------------------------------------------------------------

def _register_routes(app: FastAPI):

    # ── System ────────────────────────────────────────────────────────────

    @app.get("/api/health", response_model=HealthResponse, tags=["System"])
    async def health():
        return HealthResponse(status="ok", service="schild-api", version="1.2.0")

    @app.get("/api/status", response_model=StatusResponse, tags=["System"],
             dependencies=[Depends(require_auth)])
    async def status():
        agent = _get_agent()
        return StatusResponse(
            defense_mode=agent.defense_mode.value,
            provider=agent.provider.provider_name,
            triage_model=agent.provider.triage_model,
            analyst_model=agent.provider.analyst_model,
            provider_connected=agent._provider_ok,
            monitoring_active=agent._monitoring_active,
            system=agent.system_context,
        )

    @app.put("/api/config/mode", response_model=MessageResponse, tags=["System"],
             dependencies=[Depends(require_auth)])
    async def update_mode(req: ModeUpdateRequest):
        from schild.core.config import DefenseMode
        try:
            new_mode = DefenseMode(req.mode)
        except ValueError:
            raise HTTPException(400, f"Invalid mode: {req.mode}")
        agent = _get_agent()
        agent.defense_mode = new_mode
        agent.response_orchestrator.defense_mode = new_mode
        agent.memory.save_event(
            "CONFIG_CHANGE", f"Defense mode changed to {new_mode.value}", level="info",
        )
        return MessageResponse(message=f"Defense mode set to {new_mode.value}")

    # ── Threat Hunting ────────────────────────────────────────────────────

    @app.post("/api/hunt", response_model=HuntResponse, tags=["Hunting"],
              dependencies=[Depends(require_auth)])
    async def hunt(req: HuntRequest = None):
        agent = _get_agent()
        hyp_id = req.hypothesis_id if req else None
        results = agent.hunt(hypothesis_id=hyp_id)
        return HuntResponse(results=results, count=len(results))

    @app.get("/api/hunt/results", tags=["Hunting"],
             dependencies=[Depends(require_auth)])
    async def hunt_results(limit: int = 20):
        agent = _get_agent()
        results = agent.memory.get_hunt_results(limit=limit)
        return {"results": results, "count": len(results)}

    @app.post("/api/zeroday", response_model=ScanResponse, tags=["Hunting"],
              dependencies=[Depends(require_auth)])
    async def zeroday_scan():
        agent = _get_agent()
        findings = agent.zero_day_scan()
        return ScanResponse(findings=findings, count=len(findings))

    @app.post("/api/anomaly", response_model=ScanResponse, tags=["Hunting"],
              dependencies=[Depends(require_auth)])
    async def anomaly_scan():
        agent = _get_agent()
        findings = agent.anomaly_scan()
        return ScanResponse(findings=findings, count=len(findings))

    # ── Assets ────────────────────────────────────────────────────────────

    @app.get("/api/assets", response_model=AssetResponse, tags=["Assets"],
             dependencies=[Depends(require_auth)])
    async def get_assets():
        agent = _get_agent()
        inv = agent.asset_inventory or agent.memory.get_latest_asset_inventory()
        return AssetResponse(assets=inv)

    @app.post("/api/assets/discover", response_model=AssetResponse, tags=["Assets"],
              dependencies=[Depends(require_auth)])
    async def discover_assets():
        agent = _get_agent()
        assets = agent.discover_assets()
        return AssetResponse(assets=assets)

    # ── Alerts ────────────────────────────────────────────────────────────

    @app.get("/api/alerts", response_model=AlertListResponse, tags=["Alerts"],
             dependencies=[Depends(require_auth)])
    async def get_alerts(limit: int = 20):
        agent = _get_agent()
        raw = agent.memory.get_recent_alerts(limit=limit)
        items = [
            AlertItem(
                title=a["title"], message=a["message"], severity=a["severity"],
                hostname=a.get("hostname", ""), timestamp=a["timestamp"],
            )
            for a in raw
        ]
        return AlertListResponse(alerts=items, count=len(items))

    # ── IOCs ──────────────────────────────────────────────────────────────

    @app.get("/api/iocs", response_model=IOCListResponse, tags=["IOCs"],
             dependencies=[Depends(require_auth)])
    async def get_iocs(limit: int = 30, ioc_type: Optional[str] = None):
        agent = _get_agent()
        raw = agent.memory.get_iocs(ioc_type=ioc_type, limit=limit)
        items = [
            IOCItem(
                ioc_type=i["ioc_type"], value=i["value"],
                source=i.get("source", ""), threat_name=i.get("threat_name", ""),
                confidence=i.get("confidence", 0.0), last_seen=i.get("last_seen", ""),
            )
            for i in raw
        ]
        return IOCListResponse(iocs=items, count=len(items))

    @app.post("/api/iocs/enrich", tags=["IOCs"],
              dependencies=[Depends(require_auth)])
    async def enrich_ioc(req: EnrichRequest):
        agent = _get_agent()
        result = agent.enrich_ioc(req.ioc_type, req.value)
        return result

    # ── Events ────────────────────────────────────────────────────────────

    @app.get("/api/events", response_model=EventsResponse, tags=["Events"],
             dependencies=[Depends(require_auth)])
    async def get_events(limit: int = 20):
        agent = _get_agent()
        summary = agent.memory.get_recent_summary(limit=limit)
        return EventsResponse(summary=summary)

    # ── ML / Baseline ─────────────────────────────────────────────────────

    @app.post("/api/ml/train", response_model=MessageResponse, tags=["ML"],
              dependencies=[Depends(require_auth)])
    async def ml_train(req: MLTrainRequest = None):
        agent = _get_agent()
        n = req.n_samples if req else 40
        agent.anomaly_detector.train(n_samples=n)
        return MessageResponse(message=f"ML training completed with {n} samples")

    @app.post("/api/ml/retrain", response_model=MessageResponse, tags=["ML"],
              dependencies=[Depends(require_auth)])
    async def ml_retrain(req: MLTrainRequest = None):
        agent = _get_agent()
        n = req.n_samples if req else 40
        agent.anomaly_detector.retrain(n_samples=n)
        return MessageResponse(message=f"ML retrain completed with {n} samples")

    @app.post("/api/ml/baseline", response_model=MessageResponse, tags=["ML"],
              dependencies=[Depends(require_auth)])
    async def build_baseline(req: BaselineBuildRequest = None):
        agent = _get_agent()
        samples = req.samples if req else 20
        agent.build_baseline(samples=samples)
        return MessageResponse(message=f"Baseline built with {samples} samples")

    # ── Monitoring ────────────────────────────────────────────────────────

    @app.post("/api/monitor/start", response_model=MessageResponse, tags=["Monitoring"],
              dependencies=[Depends(require_auth)])
    async def monitor_start(req: MonitorStartRequest = None):
        agent = _get_agent()
        interval = req.interval if req else 60
        if agent._monitoring_active:
            raise HTTPException(409, "Monitoring already active")
        agent.start_monitoring(interval=interval)
        return MessageResponse(message=f"Monitoring started with interval={interval}s")

    @app.post("/api/monitor/stop", response_model=MessageResponse, tags=["Monitoring"],
              dependencies=[Depends(require_auth)])
    async def monitor_stop():
        agent = _get_agent()
        if not agent._monitoring_active:
            raise HTTPException(409, "Monitoring not active")
        agent.stop_monitoring()
        return MessageResponse(message="Monitoring stopped")

    # ── Ingestion / Port Mirror ───────────────────────────────────────────

    @app.post("/api/mirror/start", response_model=MessageResponse, tags=["Ingestion"],
              dependencies=[Depends(require_auth)])
    async def mirror_start(req: MirrorStartRequest):
        agent = _get_agent()
        if agent.ingestion is None:
            raise HTTPException(503, "Log ingestion layer not available")
        try:
            agent.start_port_mirror(
                interface=req.interface,
                bpf_filter=req.bpf_filter,
            )
            return MessageResponse(
                message=f"Port mirror started on {req.interface}"
                + (f" (filter: {req.bpf_filter})" if req.bpf_filter else "")
            )
        except ImportError as e:
            raise HTTPException(503, str(e))
        except PermissionError:
            raise HTTPException(403, "Permission denied - requires root or CAP_NET_RAW")

    @app.post("/api/mirror/stop", response_model=MessageResponse, tags=["Ingestion"],
              dependencies=[Depends(require_auth)])
    async def mirror_stop():
        agent = _get_agent()
        agent.stop_all_ingestion()
        return MessageResponse(message="All ingestion sources stopped")

    @app.get("/api/mirror/stats", response_model=MirrorStatsResponse, tags=["Ingestion"],
             dependencies=[Depends(require_auth)])
    async def mirror_stats():
        agent = _get_agent()
        captures = []
        if agent.ingestion and hasattr(agent.ingestion, '_mirror_captures'):
            for cap in agent.ingestion._mirror_captures:
                captures.append({
                    "interface": cap.interface,
                    "running": cap.is_running,
                    "stats": cap.get_stats(),
                })
        return MirrorStatsResponse(captures=captures)

    @app.post("/api/syslog/start", response_model=MessageResponse, tags=["Ingestion"],
              dependencies=[Depends(require_auth)])
    async def syslog_start(port: int = 5140):
        agent = _get_agent()
        agent.start_syslog_ingestion(port=port)
        return MessageResponse(message=f"Syslog receiver started on port {port}")

    # ── Chat / AI ─────────────────────────────────────────────────────────

    @app.post("/api/chat", response_model=ChatResponse, tags=["Chat"],
              dependencies=[Depends(require_auth)])
    async def chat(req: ChatRequest):
        agent = _get_agent()
        from schild.ai.router import plan_action, generate_memory_answer
        from schild.ai.provider import ModelTier
        from schild.core.config import TRIAGE_TIMEOUT

        planned = plan_action(
            provider=agent.provider,
            user_msg=req.message,
            memory_hint=agent.memory.get_recent_summary(limit=3),
            timeout=TRIAGE_TIMEOUT,
        )
        action = (planned or {}).get("action", "INVESTIGATE")

        if action == "CHAT":
            msg = str((planned or {}).get("message", "")).strip()
            if not msg:
                msg = agent.provider.complete(
                    req.message,
                    system_prompt="You are SCHILD, an autonomous threat defense system. Respond briefly.",
                    tier=ModelTier.TRIAGE,
                    timeout=TRIAGE_TIMEOUT,
                ).strip()
            return ChatResponse(action="CHAT", response=msg)

        if action == "ANSWER_MEMORY":
            ans = generate_memory_answer(
                provider=agent.provider,
                memory=agent.memory,
                user_msg=req.message,
                asset_inventory=agent.asset_inventory,
                vulnerabilities=agent.vulnerabilities,
                alerts=agent.alerts,
                iocs=agent.memory.get_iocs(limit=20),
            )
            return ChatResponse(action="ANSWER_MEMORY", response=ans)

        if action == "HUNT":
            results = agent.hunt()
            return ChatResponse(
                action="HUNT",
                response=f"Hunt completed. {len(results)} hypotheses evaluated.",
            )

        if action == "RUN_CMD":
            cmd = str((planned or {}).get("command", "")).strip()
            if cmd:
                out = agent.execute(cmd)
                return ChatResponse(action="RUN_CMD", response=out)
            return ChatResponse(action="RUN_CMD", response="No command to execute.")

        # INVESTIGATE — run the investigation loop and capture output
        from schild.ai.investigator import run_investigation_loop
        from schild.core.config import MAX_HUNT_STEPS, ANALYST_TIMEOUT

        # Capture stdout from investigation loop
        import io
        import sys
        buffer = io.StringIO()
        old_stdout = sys.stdout
        sys.stdout = buffer
        try:
            run_investigation_loop(
                user_msg=req.message,
                provider=agent.provider,
                execute_cmd=agent.execute,
                memory_summary=agent.memory.get_recent_summary,
                tool_registry=agent.tool_registry,
                mitre_data=agent._mitre_data,
                defense_mode=agent.defense_mode,
                max_steps=MAX_HUNT_STEPS,
                timeout=ANALYST_TIMEOUT,
            )
        finally:
            sys.stdout = old_stdout
        output = buffer.getvalue()
        # Strip ANSI color codes for clean API output
        import re
        clean = re.sub(r'\033\[[0-9;]*m', '', output).strip()
        return ChatResponse(action="INVESTIGATE", response=clean)

    # ── Containment ───────────────────────────────────────────────────────

    @app.post("/api/contain", response_model=ContainResponse, tags=["Response"],
              dependencies=[Depends(require_auth)])
    async def contain(req: ContainRequest):
        agent = _get_agent()
        from schild.response.orchestrator import ResponseAction
        ra = ResponseAction(
            action_type=req.action_type,
            target=req.target,
            reason=req.reason or f"API containment: {req.action_type} {req.target}",
            severity="high",
        )
        result = agent.response_orchestrator._execute_action(ra)
        return ContainResponse(
            action_type=result.action_type,
            target=result.target,
            executed=result.executed,
            result=result.result,
        )

    # ── Sidecars ──────────────────────────────────────────────────────────

    @app.get("/api/sidecars", response_model=SidecarListResponse, tags=["Sidecar"],
             dependencies=[Depends(require_auth)])
    async def list_sidecars():
        agent = _get_agent()
        items = []
        if agent._sidecar_registry:
            status = agent.ping_sidecars()
            for name, alive in status.items():
                items.append(SidecarItem(name=name, alive=alive))
        return SidecarListResponse(sidecars=items)

    @app.post("/api/sidecars/register", response_model=MessageResponse, tags=["Sidecar"],
              dependencies=[Depends(require_auth)])
    async def register_sidecar(req: SidecarRegisterRequest):
        agent = _get_agent()
        alive = agent.register_sidecar(
            name=req.name, url=req.url, secret=req.secret,
        )
        status = "reachable" if alive else "unreachable (registered anyway)"
        return MessageResponse(message=f"Sidecar '{req.name}' registered - {status}")

    @app.post("/api/sidecars/ping", tags=["Sidecar"],
              dependencies=[Depends(require_auth)])
    async def ping_sidecars():
        agent = _get_agent()
        results = agent.ping_sidecars()
        return results


# ---------------------------------------------------------------------------
# Standalone runner (for development)
# ---------------------------------------------------------------------------

def run_server(
    host: str = "0.0.0.0",
    port: int = 8420,
    defense_mode: str = "hunt",
    ai_provider: str = "openai",
    db_path: str = "schild_memory.db",
):
    """Start the API server with uvicorn."""
    import uvicorn

    app = create_app(
        defense_mode=defense_mode,
        ai_provider=ai_provider,
        db_path=db_path,
    )
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    from schild.core.config import API_HOST, API_PORT
    run_server(host=API_HOST, port=API_PORT)
