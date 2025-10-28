"""Schemas for network traffic data."""

from pydantic import BaseModel, Field, validator
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


class ProtocolType(str, Enum):
    """Network protocol types."""
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    OTHER = "OTHER"


class FlowBase(BaseModel):
    """Base flow schema."""
    timestamp: datetime
    src_ip: str = Field(..., description="Source IP address")
    dst_ip: str = Field(..., description="Destination IP address")
    src_port: int = Field(ge=0, le=65535, description="Source port")
    dst_port: int = Field(ge=0, le=65535, description="Destination port")
    protocol: ProtocolType
    bytes_total: int = Field(ge=0, description="Total bytes in flow")
    packets_total: int = Field(ge=0, description="Total packets in flow")


class FlowCreate(FlowBase):
    """Flow creation schema."""
    src_mac: Optional[str] = Field(None, pattern="^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
    dst_mac: Optional[str] = Field(None, pattern="^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
    duration: Optional[float] = Field(None, ge=0, description="Flow duration in seconds")
    sni: Optional[str] = Field(None, description="TLS SNI")
    dns_query: Optional[str] = Field(None, description="DNS query")
    dns_response: Optional[str] = Field(None, description="DNS response")
    is_external: bool = Field(False, description="Is external traffic")
    is_encrypted: bool = Field(False, description="Is encrypted traffic")


class FlowResponse(FlowBase):
    """Flow response schema."""
    id: int
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    duration: float = 0.0
    sni: Optional[str] = None
    dns_query: Optional[str] = None
    is_external: bool = False
    is_encrypted: bool = False
    
    class Config:
        """Pydantic config."""
        from_attributes = True


class FlowListResponse(BaseModel):
    """Flow list response."""
    flows: List[FlowResponse]
    total: int
    since: datetime
    
    class Config:
        """Pydantic config."""
        from_attributes = True


class FlowStatistics(BaseModel):
    """Flow statistics response."""
    total_flows: int
    external_flows: int
    total_bytes: int
    unique_sources: int
    window_minutes: int
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class PacketInfo(BaseModel):
    """Packet information schema."""
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    size: int
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None


class CaptureMode(str, Enum):
    """Capture mode enum."""
    LIVE = "live"
    PCAP = "pcap"


class CaptureConfig(BaseModel):
    """Capture configuration."""
    mode: CaptureMode
    interface: Optional[str] = Field(None, description="Network interface for live capture")
    pcap_path: Optional[str] = Field(None, description="Path to PCAP file")
    
    @validator('interface')
    def validate_interface(cls, v, values):
        """Validate interface is provided for live mode."""
        if values.get('mode') == CaptureMode.LIVE and not v:
            raise ValueError("Interface required for live capture mode")
        return v
    
    @validator('pcap_path')
    def validate_pcap_path(cls, v, values):
        """Validate PCAP path is provided for PCAP mode."""
        if values.get('mode') == CaptureMode.PCAP and not v:
            raise ValueError("PCAP path required for PCAP mode")
        return v


class CaptureStatus(BaseModel):
    """Capture status response."""
    mode: CaptureMode
    is_running: bool
    interface: Optional[str] = None
    pcap_path: Optional[str] = None
    packets_captured: int = 0
    devices_discovered: int = 0
    active_flows: int = 0


class PcapUpload(BaseModel):
    """PCAP upload response."""
    filename: str
    size_bytes: int
    size_mb: float
    status: str
    message: str
    packet_count: Optional[int] = None


class TopTalker(BaseModel):
    """Top talker statistics."""
    mac: str
    vendor: Optional[str] = None
    total_bytes: int
    flow_count: int
    percentage: float = 0.0
    
    class Config:
        """Pydantic config."""
        from_attributes = True
