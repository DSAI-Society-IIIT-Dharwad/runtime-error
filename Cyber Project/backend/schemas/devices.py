"""Schemas for network devices."""

from pydantic import BaseModel, Field, validator
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


class DeviceRole(str, Enum):
    """Device role/type."""
    COMPUTER = "Computer"
    MOBILE = "Mobile"
    IOT = "IoT"
    CAMERA = "Camera"
    SMART_TV = "Smart TV"
    SMART_SPEAKER = "Smart Speaker"
    STREAMING = "Streaming Device"
    NETWORK = "Network Equipment"
    PRINTER = "Printer"
    RASPBERRY_PI = "Raspberry Pi"
    UNKNOWN = "Unknown"


class DeviceBase(BaseModel):
    """Base device schema."""
    mac: str = Field(..., pattern="^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
    ip: Optional[str] = Field(None, description="Current IP address")
    vendor: Optional[str] = Field(None, description="Vendor from OUI lookup")
    hostname: Optional[str] = Field(None, description="Device hostname")
    role: Optional[DeviceRole] = Field(DeviceRole.UNKNOWN, description="Device role/type")


class DeviceCreate(DeviceBase):
    """Device creation schema."""
    pass


class DeviceUpdate(BaseModel):
    """Device update schema."""
    ip: Optional[str] = None
    hostname: Optional[str] = None
    role: Optional[DeviceRole] = None
    score: Optional[float] = Field(None, ge=0.0, le=100.0)


class DeviceStatistics(BaseModel):
    """Device traffic statistics."""
    common_ports: List[int] = Field(default_factory=list)
    total_bytes_sent: int = 0
    total_bytes_received: int = 0
    unique_destinations: int = 0
    dns_queries_count: int = 0
    protocol_distribution: Dict[str, int] = Field(default_factory=dict)
    last_24h_activity: Dict[str, Any] = Field(default_factory=dict)


class DeviceResponse(DeviceBase):
    """Device response schema."""
    id: int
    first_seen: datetime
    last_seen: datetime
    score: float = Field(0.0, description="Risk score 0-100")
    is_active: bool = Field(True, description="Device seen in last 15 minutes")
    stats: Optional[DeviceStatistics] = None
    
    class Config:
        """Pydantic config."""
        from_attributes = True


class DeviceListResponse(BaseModel):
    """Device list response."""
    devices: List[DeviceResponse]
    total: int
    active_count: int
    mode: Optional[str] = Field(None, description="Capture mode: live or pcap")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    
    class Config:
        """Pydantic config."""
        from_attributes = True


class DeviceProfile(BaseModel):
    """Detailed device profile."""
    mac: str
    vendor: Optional[str] = None
    role: str
    confidence: float = Field(ge=0.0, le=1.0)
    characteristics: List[str] = Field(default_factory=list)
    risk_factors: List[str] = Field(default_factory=list)
    fingerprint: Dict[str, Any] = Field(default_factory=dict)


class DeviceActivity(BaseModel):
    """Device activity summary."""
    mac: str
    time_window: str  # e.g., "1h", "24h"
    flows_count: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    unique_destinations: List[str] = Field(default_factory=list)
    top_ports: List[int] = Field(default_factory=list)
    alerts_count: int = 0
    risk_score: float = Field(0.0, ge=0.0, le=100.0)


class DeviceRiskAssessment(BaseModel):
    """Device risk assessment."""
    mac: str
    overall_risk: str  # "Low", "Medium", "High", "Critical"
    risk_score: float = Field(ge=0.0, le=100.0)
    risk_factors: List[Dict[str, Any]] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    assessed_at: datetime = Field(default_factory=datetime.utcnow)


class NetworkTopology(BaseModel):
    """Network topology information."""
    nodes: List[Dict[str, Any]]  # Device nodes
    edges: List[Dict[str, Any]]  # Connections between devices
    clusters: Optional[List[Dict[str, Any]]] = None  # Device groupings
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class DeviceComparison(BaseModel):
    """Device behavior comparison."""
    device_mac: str
    baseline: Dict[str, float]
    current: Dict[str, float]
    deviations: Dict[str, float]
    anomaly_score: float = Field(ge=0.0, le=1.0)
    significant_changes: List[str] = Field(default_factory=list)
