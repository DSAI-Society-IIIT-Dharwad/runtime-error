"""
Nuclei vulnerability scanner runner
"""
import json
import logging
import subprocess
from typing import Any, Dict, List

from scanner.settings import ScannerConfig

logger = logging.getLogger(__name__)


class NucleiRunner:
    """Nuclei template-based vulnerability scanner"""
    
    def __init__(self, config: ScannerConfig):
        self.config = config
        self.nuclei_opts = config.scan_opts.nuclei
    
    def run(self, targets: List[str]) -> List[Dict[str, Any]]:
        """Execute Nuclei scan"""
        logger.info(f"Starting Nuclei scan for {len(targets)} target(s)")
        
        findings = []
        
        try:
            # Build command
            cmd = [
                "nuclei",
                "-silent",
                "-json",
                "-severity", ",".join(self.nuclei_opts.severity),
                "-rate-limit", str(self.nuclei_opts.rate_limit),
                "-timeout", str(self.nuclei_opts.timeout)
            ]
            
            # Add templates filter
            if self.nuclei_opts.templates:
                cmd.extend(["-tags", self.nuclei_opts.templates])
            
            # Passive mode: exclude certain aggressive templates
            if self.config.controls.passive_only:
                logger.info("Running in passive mode - excluding aggressive templates")
                cmd.extend(["-exclude-tags", "intrusive,dos,fuzzing"])
            
            # Add targets
            for target in targets:
                cmd.extend(["-u", target])
            
            logger.debug(f"Running command: {' '.join(cmd)}")
            
            # Run nuclei
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.controls.timeout
            )
            
            # Parse JSONL output
            if result.stdout:
                for line in result.stdout.strip().split("\n"):
                    if not line:
                        continue
                    try:
                        finding = json.loads(line)
                        
                        # Normalize structure
                        normalized = {
                            "template": finding.get("template-id"),
                            "template_name": finding.get("info", {}).get("name"),
                            "severity": finding.get("info", {}).get("severity", "unknown").lower(),
                            "host": finding.get("host"),
                            "matched_at": finding.get("matched-at"),
                            "type": finding.get("type"),
                            "cve": self._extract_cve(finding),
                            "cwe": self._extract_cwe(finding),
                            "description": finding.get("info", {}).get("description"),
                            "reference": finding.get("info", {}).get("reference", []),
                            "tags": finding.get("info", {}).get("tags", []),
                            "matcher_name": finding.get("matcher-name"),
                            "extracted_results": finding.get("extracted-results", [])
                        }
                        
                        findings.append(normalized)
                    
                    except json.JSONDecodeError as e:
                        logger.warning(f"Failed to parse Nuclei output line: {e}")
            
            if result.stderr:
                logger.debug(f"Nuclei stderr: {result.stderr}")
            
            logger.info(f"Nuclei scan completed: {len(findings)} findings")
            
            # Save raw output
            output_file = f"{self.config.output_dir}/raw/nuclei_findings.json"
            with open(output_file, "w") as f:
                json.dump(findings, f, indent=2)
            logger.info(f"Saved raw Nuclei output to {output_file}")
            
            return findings
        
        except subprocess.TimeoutExpired:
            logger.error("Nuclei scan timed out")
            return findings
        
        except FileNotFoundError:
            logger.error("Nuclei not found. Please install: https://github.com/projectdiscovery/nuclei")
            return findings
        
        except Exception as e:
            logger.error(f"Nuclei scan failed: {e}")
            return findings
    
    def _extract_cve(self, finding: Dict[str, Any]) -> List[str]:
        """Extract CVE IDs from finding"""
        cves = []
        
        # Check classification
        classification = finding.get("info", {}).get("classification", {})
        if "cve-id" in classification:
            cve_ids = classification["cve-id"]
            if isinstance(cve_ids, list):
                cves.extend(cve_ids)
            else:
                cves.append(cve_ids)
        
        # Check tags
        tags = finding.get("info", {}).get("tags", [])
        for tag in tags:
            if tag.upper().startswith("CVE-"):
                cves.append(tag.upper())
        
        return list(set(cves))  # deduplicate
    
    def _extract_cwe(self, finding: Dict[str, Any]) -> List[str]:
        """Extract CWE IDs from finding"""
        cwes = []
        
        classification = finding.get("info", {}).get("classification", {})
        if "cwe-id" in classification:
            cwe_ids = classification["cwe-id"]
            if isinstance(cwe_ids, list):
                cwes.extend(cwe_ids)
            else:
                cwes.append(cwe_ids)
        
        return cwes

