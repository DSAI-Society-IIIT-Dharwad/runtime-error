"""
Security scanner orchestrator - coordinates all engines and enrichment
"""
import argparse
import json
import logging
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

from scanner.settings import ScannerConfig, load_config_from_env
from scanner.engines.zap_runner import ZapRunner
from scanner.engines.nuclei_runner import NucleiRunner
from scanner.engines.nmap_runner import NmapRunner
from scanner.engines.trivy_runner import TrivyRunner
from scanner.enrich.epss import EPSSEnricher
from scanner.enrich.kev import KEVEnricher

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('scanner.log')
    ]
)
logger = logging.getLogger(__name__)


class ScanOrchestrator:
    """Orchestrates multi-engine security scanning"""
    
    def __init__(self, config: ScannerConfig):
        self.config = config
        self.findings: List[Dict[str, Any]] = []
    
    def validate_targets(self) -> bool:
        """Validate and filter targets based on controls"""
        if not self.config.targets:
            logger.error("No targets specified")
            return False
        
        # Filter out excluded targets
        if self.config.controls.exclude:
            original_count = len(self.config.targets)
            self.config.targets = [
                t for t in self.config.targets
                if not any(excl in t for excl in self.config.controls.exclude)
            ]
            
            if len(self.config.targets) < original_count:
                logger.info(f"Excluded {original_count - len(self.config.targets)} target(s)")
        
        if not self.config.targets:
            logger.error("All targets were excluded")
            return False
        
        logger.info(f"Validated {len(self.config.targets)} target(s)")
        return True
    
    def run_zap(self) -> Tuple[str, List[Dict[str, Any]]]:
        """Run ZAP DAST scan"""
        logger.info("Starting ZAP engine")
        try:
            runner = ZapRunner(self.config)
            findings = []
            
            # ZAP scans one target at a time
            for target in self.config.targets:
                if self._is_web_target(target):
                    target_findings = runner.run(target)
                    findings.extend(target_findings)
            
            return ("zap", findings)
        except Exception as e:
            logger.error(f"ZAP engine failed: {e}")
            return ("zap", [])
    
    def run_nuclei(self) -> Tuple[str, List[Dict[str, Any]]]:
        """Run Nuclei template scan"""
        logger.info("Starting Nuclei engine")
        try:
            runner = NucleiRunner(self.config)
            
            # Filter web targets
            web_targets = [t for t in self.config.targets if self._is_web_target(t)]
            
            if not web_targets:
                logger.info("No web targets for Nuclei")
                return ("nuclei", [])
            
            findings = runner.run(web_targets)
            return ("nuclei", findings)
        except Exception as e:
            logger.error(f"Nuclei engine failed: {e}")
            return ("nuclei", [])
    
    def run_nmap(self) -> Tuple[str, List[Dict[str, Any]]]:
        """Run Nmap service enumeration"""
        logger.info("Starting Nmap engine")
        try:
            runner = NmapRunner(self.config)
            
            # Extract hosts from targets
            hosts = []
            for target in self.config.targets:
                if self._is_web_target(target):
                    parsed = urlparse(target)
                    hosts.append(parsed.netloc.split(":")[0])
                else:
                    hosts.append(target)
            
            findings = runner.run(list(set(hosts)))  # deduplicate
            return ("nmap", findings)
        except Exception as e:
            logger.error(f"Nmap engine failed: {e}")
            return ("nmap", [])
    
    def run_trivy(self) -> Tuple[str, Dict[str, Any]]:
        """Run Trivy SCA/SBOM"""
        logger.info("Starting Trivy engine")
        try:
            runner = TrivyRunner(self.config)
            results = runner.run()
            return ("trivy", results)
        except Exception as e:
            logger.error(f"Trivy engine failed: {e}")
            return ("trivy", {"sbom": {}, "vulnerabilities": []})
    
    def _is_web_target(self, target: str) -> bool:
        """Check if target is a web URL"""
        return target.startswith("http://") or target.startswith("https://")
    
    def run_engines(self) -> Dict[str, Any]:
        """Run all scanning engines concurrently"""
        logger.info("Starting concurrent engine execution")
        
        raw_results = {
            "zap": [],
            "nuclei": [],
            "nmap": [],
            "trivy": {"sbom": {}, "vulnerabilities": []}
        }
        
        # Define engine tasks
        tasks = []
        
        # Only run web scanners if we have web targets
        has_web_targets = any(self._is_web_target(t) for t in self.config.targets)
        
        if has_web_targets:
            tasks.extend([
                ("zap", self.run_zap),
                ("nuclei", self.run_nuclei)
            ])
        
        # Always run network and SCA scans
        tasks.extend([
            ("nmap", self.run_nmap),
            ("trivy", self.run_trivy)
        ])
        
        # Execute with concurrency control
        with ThreadPoolExecutor(max_workers=self.config.controls.max_concurrency) as executor:
            futures = {executor.submit(task_fn): name for name, task_fn in tasks}
            
            for future in as_completed(futures):
                engine_name = futures[future]
                try:
                    name, results = future.result()
                    raw_results[name] = results
                    logger.info(f"Engine '{name}' completed")
                except Exception as e:
                    logger.error(f"Engine '{engine_name}' failed with exception: {e}")
        
        return raw_results
    
    def normalize_findings(self, raw_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Normalize findings from all engines to unified format"""
        logger.info("Normalizing findings")
        
        normalized = []
        
        # ZAP findings
        for finding in raw_results.get("zap", []):
            normalized.append({
                "source": "zap",
                "host": urlparse(finding.get("url", "")).netloc,
                "location": finding.get("url"),
                "cve": None,
                "cwe": finding.get("cweid"),
                "severity": self._normalize_severity(finding.get("risk", "").lower()),
                "title": finding.get("name"),
                "description": finding.get("description"),
                "evidence": finding.get("evidence"),
                "solution": finding.get("solution"),
                "references": finding.get("reference", []),
                "confidence": finding.get("confidence"),
                "plugin_id": finding.get("pluginid")
            })
        
        # Nuclei findings
        for finding in raw_results.get("nuclei", []):
            cve_list = finding.get("cve", [])
            cve = cve_list[0] if cve_list else None
            
            normalized.append({
                "source": "nuclei",
                "host": urlparse(finding.get("host", "")).netloc,
                "location": finding.get("matched_at", finding.get("host")),
                "cve": cve,
                "cwe": finding.get("cwe", [None])[0] if finding.get("cwe") else None,
                "severity": self._normalize_severity(finding.get("severity", "unknown")),
                "title": finding.get("template_name"),
                "description": finding.get("description"),
                "evidence": finding.get("matcher_name"),
                "solution": None,
                "references": finding.get("reference", []),
                "template": finding.get("template"),
                "tags": finding.get("tags", [])
            })
        
        # Nmap findings
        for finding in raw_results.get("nmap", []):
            # Create finding for each service with potential vulnerabilities
            for script in finding.get("scripts", []):
                if script.get("is_vulnerability"):
                    normalized.append({
                        "source": "nmap",
                        "host": finding.get("host"),
                        "location": f"{finding.get('host')}:{finding.get('port')}/{finding.get('protocol')}",
                        "cve": None,
                        "cwe": None,
                        "severity": "medium",  # Default for NSE findings
                        "title": f"NSE: {script.get('id')}",
                        "description": script.get("output"),
                        "evidence": None,
                        "solution": None,
                        "references": [],
                        "service": finding.get("service"),
                        "product": finding.get("product"),
                        "version": finding.get("version")
                    })
        
        # Trivy findings
        for finding in raw_results.get("trivy", {}).get("vulnerabilities", []):
            normalized.append({
                "source": "trivy",
                "host": "localhost",
                "location": finding.get("target"),
                "cve": finding.get("cve"),
                "cwe": finding.get("cwe", [None])[0] if finding.get("cwe") else None,
                "severity": self._normalize_severity(finding.get("severity", "unknown")),
                "title": finding.get("title"),
                "description": finding.get("description"),
                "evidence": None,
                "solution": f"Update to version {finding.get('fixed_version')}" if finding.get("fixed_version") else None,
                "references": finding.get("references", []),
                "component": finding.get("component"),
                "version": finding.get("version"),
                "fixed_version": finding.get("fixed_version")
            })
        
        logger.info(f"Normalized {len(normalized)} findings")
        return normalized
    
    def _normalize_severity(self, severity: str) -> str:
        """Normalize severity levels across engines"""
        severity = severity.lower()
        
        mapping = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "info": "info",
            "informational": "info",
            "unknown": "low"
        }
        
        return mapping.get(severity, "low")
    
    def deduplicate_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Deduplicate findings by (host, location, cve/template/pluginid)"""
        logger.info("Deduplicating findings")
        
        seen = set()
        deduplicated = []
        
        for finding in findings:
            # Create dedup key
            key_parts = [
                finding.get("host", ""),
                finding.get("location", ""),
                finding.get("cve") or finding.get("template") or finding.get("plugin_id") or finding.get("title", "")
            ]
            key = "|".join(str(p) for p in key_parts)
            
            if key not in seen:
                seen.add(key)
                deduplicated.append(finding)
        
        logger.info(f"Deduplicated: {len(findings)} -> {len(deduplicated)} findings")
        return deduplicated
    
    def enrich_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enrich findings with EPSS and KEV data"""
        logger.info("Enriching findings with EPSS and KEV")
        
        # EPSS enrichment
        epss_enricher = EPSSEnricher()
        findings = epss_enricher.add_epss(findings)
        
        # KEV enrichment
        kev_enricher = KEVEnricher()
        findings = kev_enricher.add_kev(findings)
        
        return findings
    
    def prioritize_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Sort findings by priority: KEV > Severity > EPSS"""
        logger.info("Prioritizing findings")
        
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        
        def sort_key(finding):
            return (
                not finding.get("is_kev", False),  # KEV first (False < True)
                severity_order.get(finding.get("severity", "low"), 5),
                -finding.get("epss_score", 0.0)  # Higher EPSS first
            )
        
        sorted_findings = sorted(findings, key=sort_key)
        return sorted_findings
    
    def save_findings(self, findings: List[Dict[str, Any]]):
        """Save findings to JSON file"""
        output_file = f"{self.config.output_dir}/findings.json"
        
        with open(output_file, "w") as f:
            json.dump(findings, f, indent=2)
        
        logger.info(f"Findings saved to {output_file}")
    
    def run(self) -> List[Dict[str, Any]]:
        """Execute full security scan orchestration"""
        logger.info("=" * 80)
        logger.info("Starting Security Scanner Orchestration")
        logger.info("=" * 80)
        
        # Validate targets
        if not self.validate_targets():
            logger.error("Target validation failed")
            return []
        
        # Run all engines
        raw_results = self.run_engines()
        
        # Normalize findings
        findings = self.normalize_findings(raw_results)
        
        # Deduplicate
        findings = self.deduplicate_findings(findings)
        
        # Enrich with EPSS and KEV
        findings = self.enrich_findings(findings)
        
        # Prioritize
        findings = self.prioritize_findings(findings)
        
        # Save findings
        self.save_findings(findings)
        
        # Store SBOM reference
        self.sbom = raw_results.get("trivy", {}).get("sbom", {})
        
        logger.info("=" * 80)
        logger.info(f"Scan completed: {len(findings)} prioritized findings")
        logger.info("=" * 80)
        
        return findings


def main():
    """CLI entry point"""
    parser = argparse.ArgumentParser(description="Enterprise Security Scanner")
    parser.add_argument(
        "--targets",
        nargs="+",
        help="Target URLs or hosts to scan"
    )
    parser.add_argument(
        "--passive-only",
        action="store_true",
        help="Run in passive mode (no active exploitation)"
    )
    parser.add_argument(
        "--max-concurrency",
        type=int,
        default=4,
        help="Maximum concurrent engines"
    )
    parser.add_argument(
        "--output-dir",
        default="out",
        help="Output directory for results"
    )
    parser.add_argument(
        "--exclude",
        nargs="+",
        help="Exclude patterns"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )
    
    args = parser.parse_args()
    
    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Build configuration
    config = load_config_from_env()
    
    if args.targets:
        config.targets = args.targets
    
    if args.passive_only:
        config.controls.passive_only = True
    
    if args.max_concurrency:
        config.controls.max_concurrency = args.max_concurrency
    
    if args.output_dir:
        config.output_dir = args.output_dir
    
    if args.exclude:
        config.controls.exclude = args.exclude
    
    # Run orchestrator
    orchestrator = ScanOrchestrator(config)
    findings = orchestrator.run()
    
    # Print summary
    print("\n" + "=" * 80)
    print("SCAN SUMMARY")
    print("=" * 80)
    print(f"Total Findings: {len(findings)}")
    
    # Count by severity
    severity_counts = {}
    kev_count = 0
    for finding in findings:
        severity = finding.get("severity", "unknown")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        if finding.get("is_kev"):
            kev_count += 1
    
    print("\nBy Severity:")
    for severity in ["critical", "high", "medium", "low", "info"]:
        count = severity_counts.get(severity, 0)
        if count > 0:
            print(f"  {severity.upper()}: {count}")
    
    print(f"\nKnown Exploited Vulnerabilities (KEV): {kev_count}")
    print(f"\nDetailed results saved to: {config.output_dir}/")
    print("=" * 80)


if __name__ == "__main__":
    main()

