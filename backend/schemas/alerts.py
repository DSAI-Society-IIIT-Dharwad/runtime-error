"""Schemas for security alerts."""

from pydantic import BaseModel, Field, validator
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum
import json


class SeverityLevel(str, Enum):
    """Alert severity levels."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlertCategory(str, Enum):
    """Alert categories."""
    DNS_TUNNEL = "dns_tunnel"
    PORT_SCAN = "port_scan"
    DATA_EXFIL = "data_exfiltration"
    MALWARE = "malware"
    BRUTE_FORCE = "brute_force"
    LATERAL_MOVEMENT = "lateral_movement"
    C2_COMMUNICATION = "c2_communication"
    CRYPTO_MINING = "crypto_mining"
    HIGH_RISK_PORT = "high_risk_port"
    SUSPICIOUS_TLS = "suspicious_tls"
    ANOMALY = "anomaly"
    OTHER = "other"


class AlertStatus(str, Enum):
    """Alert status."""
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class AlertBase(BaseModel):
    """Base alert schema."""
    severity: SeverityLevel
    category: AlertCategory
    title: str = Field(..., max_length=200)
    description: str


class AlertCreate(AlertBase):
    """Alert creation schema."""
    device_mac: Optional[str] = Field(None, pattern="^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
    flow_id: Optional[int] = None
    details: Optional[Dict[str, Any]] = Field(default_factory=dict)


class AlertUpdate(BaseModel):
    """Alert update schema."""
    status: Optional[AlertStatus] = None
    notes: Optional[str] = None


class AlertResponse(AlertBase):
    """Alert response schema."""
    id: int
    timestamp: datetime
    device_mac: Optional[str] = None
    flow_id: Optional[int] = None
    status: AlertStatus = AlertStatus.NEW
    resolved_at: Optional[datetime] = None
    notes: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)
    explanation: Optional[str] = None
    recommendation: Optional[str] = None

    @validator("details", pre=True, always=True)
    def parse_details(cls, value):
        """Ensure details are returned as a dictionary."""
        if value is None:
            return {}
        if isinstance(value, dict):
            return value
        if isinstance(value, str):
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                return {}
        return {}
    
    class Config:
        """Pydantic config."""
        from_attributes = True


class AlertListResponse(BaseModel):
    """Alert list response."""
    alerts: List[AlertResponse]
    total: int
    unresolved: int
    since: Optional[datetime] = None
    
    class Config:
        """Pydantic config."""
        from_attributes = True


class AlertStatistics(BaseModel):
    """Alert statistics."""
    total_alerts: int
    severity_counts: Dict[str, int]
    unresolved_count: int
    window_hours: int
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class DetectionResult(BaseModel):
    """Detection result from heuristics or ML."""
    rule: str
    severity: SeverityLevel
    title: str
    description: str
    details: Dict[str, Any] = Field(default_factory=dict)
    confidence: float = Field(ge=0.0, le=1.0, default=1.0)


class AnomalyScore(BaseModel):
    """Anomaly detection score."""
    device_mac: str
    score: float = Field(ge=0.0, le=1.0)
    severity: SeverityLevel
    model_based: bool = False
    heuristic_based: bool = False
    features: Dict[str, float] = Field(default_factory=dict)
    detections: List[DetectionResult] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class ThreatIndicator(BaseModel):
    """Threat indicator details."""
    type: str
    value: str
    severity: SeverityLevel
    description: Optional[str] = None
    first_seen: datetime
    last_seen: datetime
    occurrence_count: int = 1


class AlertAggregation(BaseModel):
    """Aggregated alert information."""
    time_bucket: datetime
    severity: SeverityLevel
    category: AlertCategory
    count: int
    devices_affected: List[str] = Field(default_factory=list)


class AlertTimeline(BaseModel):
    """Alert timeline for visualization."""
    buckets: List[AlertAggregation]
    interval: str  # e.g., "1h", "15m"
    start_time: datetime
    end_time: datetime
