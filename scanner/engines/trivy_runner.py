"""
Trivy vulnerability scanner and SBOM generator
"""
import json
import logging
import subprocess
from typing import Any, Dict, List

from scanner.settings import ScannerConfig

logger = logging.getLogger(__name__)


class TrivyRunner:
    """Trivy for SCA and SBOM generation"""
    
    def __init__(self, config: ScannerConfig):
        self.config = config
        self.trivy_opts = config.scan_opts.trivy
    
    def run(self) -> Dict[str, Any]:
        """Execute Trivy scan and generate SBOM"""
        logger.info(f"Starting Trivy scan for {self.trivy_opts.target}: {self.trivy_opts.path}")
        
        results = {
            "sbom": {},
            "vulnerabilities": []
        }
        
        try:
            # Generate SBOM in CycloneDX format
            sbom_file = f"{self.config.output_dir}/sbom.json"
            sbom_result = self._generate_sbom(sbom_file)
            results["sbom"] = sbom_result
            
            # Scan for vulnerabilities
            vuln_file = f"{self.config.output_dir}/raw/trivy_vulnerabilities.json"
            vulnerabilities = self._scan_vulnerabilities(vuln_file)
            results["vulnerabilities"] = vulnerabilities
            
            logger.info(f"Trivy scan completed: {len(vulnerabilities)} vulnerabilities found")
            
            return results
        
        except Exception as e:
            logger.error(f"Trivy scan failed: {e}")
            return results
    
    def _generate_sbom(self, output_file: str) -> Dict[str, Any]:
        """Generate CycloneDX SBOM"""
        logger.info("Generating SBOM with Trivy")
        
        try:
            cmd = [
                "trivy",
                self.trivy_opts.target,
                self.trivy_opts.path,
                "--format", "cyclonedx",
                "--output", output_file,
                "--quiet"
            ]
            
            logger.debug(f"Running command: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.trivy_opts.timeout
            )
            
            if result.returncode != 0:
                logger.error(f"Trivy SBOM generation failed: {result.stderr}")
                return {}
            
            # Load and return SBOM
            with open(output_file, "r") as f:
                sbom = json.load(f)
            
            logger.info(f"SBOM generated: {output_file}")
            return sbom
        
        except subprocess.TimeoutExpired:
            logger.error("Trivy SBOM generation timed out")
            return {}
        
        except FileNotFoundError:
            logger.error("Trivy not found. Please install: https://aquasecurity.github.io/trivy/")
            return {}
        
        except Exception as e:
            logger.error(f"SBOM generation failed: {e}")
            return {}
    
    def _scan_vulnerabilities(self, output_file: str) -> List[Dict[str, Any]]:
        """Scan for vulnerabilities"""
        logger.info("Scanning for vulnerabilities with Trivy")
        
        try:
            cmd = [
                "trivy",
                self.trivy_opts.target,
                self.trivy_opts.path,
                "--format", "json",
                "--output", output_file,
                "--quiet"
            ]
            
            logger.debug(f"Running command: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.trivy_opts.timeout
            )
            
            if result.returncode != 0:
                logger.error(f"Trivy vulnerability scan failed: {result.stderr}")
                return []
            
            # Load results
            with open(output_file, "r") as f:
                scan_results = json.load(f)
            
            # Normalize findings
            findings = self._normalize_findings(scan_results)
            
            logger.info(f"Vulnerability scan completed: {len(findings)} findings")
            return findings
        
        except subprocess.TimeoutExpired:
            logger.error("Trivy vulnerability scan timed out")
            return []
        
        except FileNotFoundError:
            logger.error("Trivy not found. Please install: https://aquasecurity.github.io/trivy/")
            return []
        
        except Exception as e:
            logger.error(f"Vulnerability scan failed: {e}")
            return []
    
    def _normalize_findings(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Normalize Trivy findings"""
        findings = []
        
        results = scan_results.get("Results", [])
        
        for result in results:
            target = result.get("Target", "unknown")
            vulnerabilities = result.get("Vulnerabilities", [])
            
            for vuln in vulnerabilities:
                finding = {
                    "target": target,
                    "component": vuln.get("PkgName"),
                    "version": vuln.get("InstalledVersion"),
                    "cve": vuln.get("VulnerabilityID"),
                    "severity": vuln.get("Severity", "UNKNOWN").lower(),
                    "title": vuln.get("Title"),
                    "description": vuln.get("Description"),
                    "fixed_version": vuln.get("FixedVersion"),
                    "primary_url": vuln.get("PrimaryURL"),
                    "references": vuln.get("References", []),
                    "cvss": self._extract_cvss(vuln),
                    "cwe": self._extract_cwe(vuln)
                }
                
                findings.append(finding)
        
        return findings
    
    def _extract_cvss(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        """Extract CVSS scores"""
        cvss_data = {}
        
        cvss = vuln.get("CVSS", {})
        for vendor, data in cvss.items():
            if isinstance(data, dict) and "V3Score" in data:
                cvss_data[vendor] = {
                    "score": data.get("V3Score"),
                    "vector": data.get("V3Vector")
                }
        
        return cvss_data
    
    def _extract_cwe(self, vuln: Dict[str, Any]) -> List[str]:
        """Extract CWE IDs"""
        cwes = vuln.get("CweIDs", [])
        return cwes if isinstance(cwes, list) else [cwes] if cwes else []

