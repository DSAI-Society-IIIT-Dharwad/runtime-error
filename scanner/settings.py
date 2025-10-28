"""
Configuration settings for the security scanner
"""
import os
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field


@dataclass
class ZapSettings:
    """ZAP (DAST) configuration"""
    auth: Optional[Dict[str, str]] = None  # {username, password, login_url}
    openapi_url: Optional[str] = None
    ajax_crawl: bool = False
    api_key: Optional[str] = None


@dataclass
class NucleiSettings:
    """Nuclei template scanning configuration"""
    templates: str = "http"
    severity: List[str] = field(default_factory=lambda: ["critical", "high", "medium"])
    rate_limit: int = 150  # requests per second
    timeout: int = 5


@dataclass
class NmapSettings:
    """Nmap service enumeration configuration"""
    flags: str = "-sV -T4"
    script: Optional[str] = None  # e.g., "vuln" - only when not passive_only


@dataclass
class TrivySettings:
    """Trivy SCA/SBOM configuration"""
    target: str = "fs"  # fs|repo|image
    path: str = "."
    timeout: int = 600


@dataclass
class ScanOptions:
    """Consolidated scan engine options"""
    zap: ZapSettings = field(default_factory=ZapSettings)
    nuclei: NucleiSettings = field(default_factory=NucleiSettings)
    nmap: NmapSettings = field(default_factory=NmapSettings)
    trivy: TrivySettings = field(default_factory=TrivySettings)


@dataclass
class Controls:
    """Scan control parameters"""
    max_concurrency: int = 4
    passive_only: bool = False
    exclude: List[str] = field(default_factory=list)
    timeout: int = 3600  # per-engine timeout in seconds
    rate_limit: int = 100  # global rate limit


@dataclass
class ScannerConfig:
    """Main scanner configuration"""
    targets: List[str] = field(default_factory=list)
    scan_opts: ScanOptions = field(default_factory=ScanOptions)
    controls: Controls = field(default_factory=Controls)
    output_dir: str = "out"
    
    # Data sources for enrichment
    epss_url: str = "https://api.first.org/data/v1/epss"
    kev_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    
    # ZAP daemon settings
    zap_host: str = "localhost"
    zap_port: int = 8090
    
    def __post_init__(self):
        """Create output directory if it doesn't exist"""
        os.makedirs(self.output_dir, exist_ok=True)
        os.makedirs(f"{self.output_dir}/raw", exist_ok=True)


# Global configuration instance
config = ScannerConfig()


def load_config_from_dict(data: Dict[str, Any]) -> ScannerConfig:
    """Load configuration from dictionary (e.g., from JSON/YAML)"""
    cfg = ScannerConfig()
    
    if "targets" in data:
        cfg.targets = data["targets"]
    
    if "output_dir" in data:
        cfg.output_dir = data["output_dir"]
    
    if "scan_opts" in data:
        opts = data["scan_opts"]
        
        if "zap" in opts:
            cfg.scan_opts.zap = ZapSettings(**opts["zap"])
        
        if "nuclei" in opts:
            cfg.scan_opts.nuclei = NucleiSettings(**opts["nuclei"])
        
        if "nmap" in opts:
            cfg.scan_opts.nmap = NmapSettings(**opts["nmap"])
        
        if "trivy" in opts:
            cfg.scan_opts.trivy = TrivySettings(**opts["trivy"])
    
    if "controls" in data:
        cfg.controls = Controls(**data["controls"])
    
    return cfg


def load_config_from_env() -> ScannerConfig:
    """Load configuration from environment variables"""
    cfg = ScannerConfig()
    
    if targets := os.getenv("SCANNER_TARGETS"):
        cfg.targets = [t.strip() for t in targets.split(",")]
    
    if passive := os.getenv("SCANNER_PASSIVE_ONLY"):
        cfg.controls.passive_only = passive.lower() in ("true", "1", "yes")
    
    if concurrency := os.getenv("SCANNER_MAX_CONCURRENCY"):
        cfg.controls.max_concurrency = int(concurrency)
    
    if timeout := os.getenv("SCANNER_TIMEOUT"):
        cfg.controls.timeout = int(timeout)
    
    return cfg

