"""
SCHILD API Request/Response Schemas

Pydantic models for API validation and serialization.
"""

from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Generic
# ---------------------------------------------------------------------------

class MessageResponse(BaseModel):
    message: str


class ErrorResponse(BaseModel):
    detail: str


# ---------------------------------------------------------------------------
# System
# ---------------------------------------------------------------------------

class HealthResponse(BaseModel):
    status: str = "ok"
    service: str = "schild-api"
    version: str


class StatusResponse(BaseModel):
    defense_mode: str
    provider: str
    triage_model: str
    analyst_model: str
    provider_connected: bool
    monitoring_active: bool
    system: Dict[str, Any]


class ModeUpdateRequest(BaseModel):
    mode: str = Field(..., description="observe | hunt | contain | eliminate")


# ---------------------------------------------------------------------------
# Hunting
# ---------------------------------------------------------------------------

class HuntRequest(BaseModel):
    hypothesis_id: Optional[str] = Field(
        None, description="Specific hypothesis ID (e.g. H-001). Omit to run all."
    )


class HuntResultItem(BaseModel):
    hypothesis: str
    verdict: str
    mitre_tactic: str = ""
    mitre_tech: str = ""
    timestamp: str


class HuntResponse(BaseModel):
    results: List[Dict[str, Any]]
    count: int


class ScanResponse(BaseModel):
    findings: List[Dict[str, Any]]
    count: int


# ---------------------------------------------------------------------------
# Assets
# ---------------------------------------------------------------------------

class AssetResponse(BaseModel):
    assets: Optional[Dict[str, Any]] = None


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------

class AlertItem(BaseModel):
    title: str
    message: str
    severity: str
    hostname: str = ""
    timestamp: str


class AlertListResponse(BaseModel):
    alerts: List[AlertItem]
    count: int


# ---------------------------------------------------------------------------
# IOCs
# ---------------------------------------------------------------------------

class IOCItem(BaseModel):
    ioc_type: str
    value: str
    source: str = ""
    threat_name: str = ""
    confidence: float = 0.0
    last_seen: str = ""


class IOCListResponse(BaseModel):
    iocs: List[IOCItem]
    count: int


class EnrichRequest(BaseModel):
    ioc_type: str = Field(..., description="ip | domain | hash")
    value: str = Field(..., description="The IOC value to enrich")


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------

class EventsResponse(BaseModel):
    summary: str


# ---------------------------------------------------------------------------
# ML / Baseline
# ---------------------------------------------------------------------------

class BaselineBuildRequest(BaseModel):
    samples: int = Field(20, ge=5, le=100)


class MLTrainRequest(BaseModel):
    n_samples: int = Field(40, ge=10, le=200)


# ---------------------------------------------------------------------------
# Monitoring
# ---------------------------------------------------------------------------

class MonitorStartRequest(BaseModel):
    interval: int = Field(60, ge=10, le=3600, description="Interval in seconds")


# ---------------------------------------------------------------------------
# Ingestion / Port Mirror
# ---------------------------------------------------------------------------

class MirrorStartRequest(BaseModel):
    interface: str = Field(..., description="Network interface, e.g. eth1")
    bpf_filter: str = Field("", description="Optional BPF filter string")


class MirrorStatsResponse(BaseModel):
    captures: List[Dict[str, Any]]


# ---------------------------------------------------------------------------
# Chat
# ---------------------------------------------------------------------------

class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, description="User message / prompt")


class ChatResponse(BaseModel):
    action: str
    response: str


# ---------------------------------------------------------------------------
# Containment
# ---------------------------------------------------------------------------

class ContainRequest(BaseModel):
    action_type: str = Field(
        ..., description="block_ip | kill_process | isolate_service"
    )
    target: str = Field(..., description="IP, PID, or service name")
    reason: str = Field("", description="Reason for containment action")


class ContainResponse(BaseModel):
    action_type: str
    target: str
    executed: bool
    result: str


# ---------------------------------------------------------------------------
# Sidecars
# ---------------------------------------------------------------------------

class SidecarRegisterRequest(BaseModel):
    name: str
    url: str
    secret: str


class SidecarItem(BaseModel):
    name: str
    alive: bool


class SidecarListResponse(BaseModel):
    sidecars: List[SidecarItem]
