"""Database models for Home Net Guardian."""

from typing import Optional, List
from datetime import datetime
from sqlmodel import Field, SQLModel, create_engine, Session, Relationship
from sqlalchemy import Column, String, Float, Integer, DateTime, Text, Index, JSON
import json


class Device(SQLModel, table=True):
    """Network device model."""
    
    __tablename__ = "devices"
    
    id: Optional[int] = Field(default=None, primary_key=True)
    mac: str = Field(index=True, unique=True, max_length=17)
    ip: Optional[str] = Field(default=None, max_length=45)  # Support IPv6
    vendor: Optional[str] = Field(default=None, max_length=100)
    hostname: Optional[str] = Field(default=None, max_length=255)
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)
    role: Optional[str] = Field(default=None, max_length=50)  # e.g., 'IoT', 'Camera', 'TV'
    score: float = Field(default=0.0)  # Risk score 0-100
    
    # Statistics stored as JSON
    stats: Optional[str] = Field(default=None, sa_column=Column(Text))
    
    # Relationships
    flows_src: List["Flow"] = Relationship(
        back_populates="src_device",
        sa_relationship_kwargs={"foreign_keys": "Flow.src_mac"}
    )
    flows_dst: List["Flow"] = Relationship(
        back_populates="dst_device",
        sa_relationship_kwargs={"foreign_keys": "Flow.dst_mac"}
    )
    alerts: List["Alert"] = Relationship(back_populates="device")
    
    def get_stats(self) -> dict:
        """Parse stats JSON."""
        if self.stats:
            try:
                return json.loads(self.stats)
            except json.JSONDecodeError:
                return {}
        return {}
    
    def set_stats(self, stats: dict):
        """Set stats as JSON."""
        self.stats = json.dumps(stats)
    
    class Config:
        """Model config."""
        arbitrary_types_allowed = True


class Flow(SQLModel, table=True):
    """Network flow model."""
    
    __tablename__ = "flows"
    __table_args__ = (
        Index("ix_flows_timestamp", "timestamp"),
        Index("ix_flows_src_dst", "src_ip", "dst_ip"),
    )
    
    id: Optional[int] = Field(default=None, primary_key=True)
    timestamp: datetime = Field(default_factory=datetime.utcnow, index=True)
    src_ip: str = Field(max_length=45)
    dst_ip: str = Field(max_length=45)
    src_port: int = Field(default=0)
    dst_port: int = Field(default=0)
    protocol: str = Field(max_length=10)  # TCP, UDP, ICMP, etc.
    bytes_total: int = Field(default=0)
    packets_total: int = Field(default=0)
    duration: float = Field(default=0.0)  # Seconds
    
    # Optional fields
    src_mac: Optional[str] = Field(default=None, foreign_key="devices.mac", max_length=17)
    dst_mac: Optional[str] = Field(default=None, foreign_key="devices.mac", max_length=17)
    sni: Optional[str] = Field(default=None, max_length=255)  # TLS Server Name Indication
    dns_query: Optional[str] = Field(default=None, max_length=255)
    dns_response: Optional[str] = Field(default=None, sa_column=Column(Text))
    
    # Flags
    is_external: bool = Field(default=False)  # Traffic to/from external IPs
    is_encrypted: bool = Field(default=False)  # TLS/SSL traffic
    
    # Relationships
    src_device: Optional[Device] = Relationship(
        back_populates="flows_src",
        sa_relationship_kwargs={"foreign_keys": "Flow.src_mac"}
    )
    dst_device: Optional[Device] = Relationship(
        back_populates="flows_dst",
        sa_relationship_kwargs={"foreign_keys": "Flow.dst_mac"}
    )
    alerts: List["Alert"] = Relationship(back_populates="flow")
    
    class Config:
        """Model config."""
        arbitrary_types_allowed = True


class Alert(SQLModel, table=True):
    """Security alert model."""
    
    __tablename__ = "alerts"
    __table_args__ = (
        Index("ix_alerts_timestamp_severity", "timestamp", "severity"),
    )
    
    id: Optional[int] = Field(default=None, primary_key=True)
    timestamp: datetime = Field(default_factory=datetime.utcnow, index=True)
    severity: str = Field(max_length=10)  # LOW, MEDIUM, HIGH, CRITICAL
    category: str = Field(max_length=50)  # e.g., 'dns_tunnel', 'port_scan', 'anomaly'
    title: str = Field(max_length=200)
    description: str = Field(sa_column=Column(Text))
    
    # Optional associations
    device_mac: Optional[str] = Field(default=None, foreign_key="devices.mac", max_length=17)
    flow_id: Optional[int] = Field(default=None, foreign_key="flows.id")
    
    # Detection details stored as JSON
    details: Optional[str] = Field(default=None, sa_column=Column(Text))
    
    # Status
    status: str = Field(default="new", max_length=20)  # new, acknowledged, resolved, false_positive
    resolved_at: Optional[datetime] = Field(default=None)
    notes: Optional[str] = Field(default=None, sa_column=Column(Text))
    
    # Relationships
    device: Optional[Device] = Relationship(back_populates="alerts")
    flow: Optional[Flow] = Relationship(back_populates="alerts")
    
    def get_details(self) -> dict:
        """Parse details JSON."""
        if self.details:
            try:
                return json.loads(self.details)
            except json.JSONDecodeError:
                return {}
        return {}
    
    def set_details(self, details: dict):
        """Set details as JSON."""
        self.details = json.dumps(details)
    
    @property
    def severity_score(self) -> int:
        """Get numeric severity score."""
        scores = {
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4
        }
        return scores.get(self.severity.upper(), 0)
    
    class Config:
        """Model config."""
        arbitrary_types_allowed = True


class ModelState(SQLModel, table=True):
    """Machine learning model state."""
    
    __tablename__ = "model_states"
    
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(index=True, unique=True, max_length=50)
    version: str = Field(max_length=20)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    model_data: bytes = Field(sa_column=Column(String))  # Serialized model
    metrics: Optional[str] = Field(default=None, sa_column=Column(Text))  # JSON metrics
    parameters: Optional[str] = Field(default=None, sa_column=Column(Text))  # JSON params
    
    def get_metrics(self) -> dict:
        """Parse metrics JSON."""
        if self.metrics:
            try:
                return json.loads(self.metrics)
            except json.JSONDecodeError:
                return {}
        return {}
    
    def set_metrics(self, metrics: dict):
        """Set metrics as JSON."""
        self.metrics = json.dumps(metrics)
    
    class Config:
        """Model config."""
        arbitrary_types_allowed = True


# Database setup
from core.config import settings

engine = create_engine(
    settings.db_url,
    echo=False,
    connect_args={"check_same_thread": False} if "sqlite" in settings.db_url else {}
)


def create_tables():
    """Create all database tables."""
    SQLModel.metadata.create_all(engine)


def get_session():
    """Get database session."""
    with Session(engine) as session:
        yield session
