"""Configuration management for Home Net Guardian."""

import os
from typing import List, Optional
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, field_validator


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False
    )
    
    # Capture settings
    capture_mode: str = Field(default="pcap", description="Capture mode: 'live' or 'pcap'")
    pcap_path: str = Field(default="data/sample.pcap", description="Path to PCAP file")
    iface: str = Field(default="eth0", description="Network interface for live capture")
    
    # Database
    db_url: str = Field(
        default="sqlite:///./guardian.db",
        description="Database connection URL"
    )
    
    # API settings
    api_host: str = Field(default="0.0.0.0", description="API host")
    api_port: int = Field(default=8000, description="API port")
    ws_origin: str = Field(
        default="http://localhost:5173",
        description="WebSocket allowed origin"
    )
    cors_origins: List[str] = Field(
        default=["http://localhost:5173", "http://localhost:3000"],
        description="CORS allowed origins"
    )
    
    # Anomaly detection
    anomaly_contamination: float = Field(
        default=0.02,
        description="Expected proportion of anomalies"
    )
    model_retrain_interval: int = Field(
        default=86400,
        description="Seconds between model retraining"
    )
    
    # Security
    secret_key: str = Field(
        default="change-me-in-production-use-secrets",
        description="Secret key for security operations"
    )
    allowed_hosts: List[str] = Field(
        default=["127.0.0.1", "localhost"],
        description="Allowed host headers"
    )
    
    # Logging
    log_level: str = Field(default="INFO", description="Logging level")
    log_file: str = Field(default="logs/guardian.log", description="Log file path")
    
    # Thresholds
    dns_qps_threshold: float = Field(
        default=10.0,
        description="DNS queries per second threshold"
    )
    high_risk_ports: List[int] = Field(
        default=[23, 2323, 445, 135, 139, 3389],
        description="Ports considered high risk"
    )
    suspicious_domains_file: str = Field(
        default="data/suspicious_domains.txt",
        description="File containing suspicious domains"
    )
    
    # Performance
    flow_window_seconds: int = Field(
        default=5,
        description="Aggregation window for flows"
    )
    ws_update_interval: int = Field(
        default=2,
        description="WebSocket update interval in seconds"
    )
    max_flows_cache: int = Field(
        default=10000,
        description="Maximum flows to keep in memory"
    )
    max_alerts_cache: int = Field(
        default=1000,
        description="Maximum alerts to keep in memory"
    )
    
    @field_validator("capture_mode")
    @classmethod
    def validate_capture_mode(cls, v):
        """Validate capture mode."""
        if v not in ["live", "pcap"]:
            raise ValueError("capture_mode must be 'live' or 'pcap'")
        return v
    
    @field_validator("log_file")
    @classmethod
    def ensure_log_dir(cls, v):
        """Ensure log directory exists."""
        log_path = Path(v)
        log_dir = log_path.parent
        if not log_dir.exists():
            log_dir.mkdir(parents=True, exist_ok=True)
        return v
    
    @property
    def is_live_capture(self) -> bool:
        """Check if in live capture mode."""
        return self.capture_mode == "live"
    
    @property
    def is_pcap_mode(self) -> bool:
        """Check if in PCAP mode."""
        return self.capture_mode == "pcap"
    
    def get_suspicious_domains(self) -> set:
        """Load suspicious domains from file."""
        domains = set()
        path = Path(self.suspicious_domains_file)
        if path.exists():
            try:
                with open(path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            domains.add(line.lower())
            except Exception:
                pass
        return domains
    


# Singleton instance
settings = Settings()
