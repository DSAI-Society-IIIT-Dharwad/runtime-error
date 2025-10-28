"""
Nmap network scanner and service enumeration runner
"""
import json
import logging
import subprocess
import xml.etree.ElementTree as ET
from typing import Any, Dict, List

from scanner.settings import ScannerConfig

logger = logging.getLogger(__name__)


class NmapRunner:
    """Nmap network scanner for service detection and NSE scripts"""
    
    def __init__(self, config: ScannerConfig):
        self.config = config
        self.nmap_opts = config.scan_opts.nmap
    
    def run(self, targets: List[str]) -> List[Dict[str, Any]]:
        """Execute Nmap scan"""
        logger.info(f"Starting Nmap scan for {len(targets)} target(s)")
        
        findings = []
        
        try:
            output_file = f"{self.config.output_dir}/raw/nmap_output.xml"
            
            # Build command
            cmd = ["nmap"]
            
            # Add flags
            if self.nmap_opts.flags:
                cmd.extend(self.nmap_opts.flags.split())
            
            # Add vulnerability scripts if not passive mode
            if not self.config.controls.passive_only and self.nmap_opts.script:
                logger.info(f"Including NSE scripts: {self.nmap_opts.script}")
                cmd.extend(["--script", self.nmap_opts.script])
            elif self.config.controls.passive_only:
                logger.info("Running in passive mode - skipping vulnerability scripts")
            
            # Output format
            cmd.extend(["-oX", output_file])
            
            # Add targets
            cmd.extend(targets)
            
            logger.debug(f"Running command: {' '.join(cmd)}")
            
            # Run nmap
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.controls.timeout
            )
            
            if result.stderr:
                logger.debug(f"Nmap stderr: {result.stderr}")
            
            # Parse XML output
            findings = self._parse_xml(output_file)
            
            logger.info(f"Nmap scan completed: {len(findings)} services/findings")
            
            # Save normalized JSON
            json_file = f"{self.config.output_dir}/raw/nmap_findings.json"
            with open(json_file, "w") as f:
                json.dump(findings, f, indent=2)
            logger.info(f"Saved Nmap findings to {json_file}")
            
            return findings
        
        except subprocess.TimeoutExpired:
            logger.error("Nmap scan timed out")
            return findings
        
        except FileNotFoundError:
            logger.error("Nmap not found. Please install nmap.")
            return findings
        
        except Exception as e:
            logger.error(f"Nmap scan failed: {e}")
            return findings
    
    def _parse_xml(self, xml_file: str) -> List[Dict[str, Any]]:
        """Parse Nmap XML output"""
        findings = []
        
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            for host in root.findall("host"):
                # Get host address
                addr_elem = host.find("address[@addrtype='ipv4']")
                if addr_elem is None:
                    addr_elem = host.find("address[@addrtype='ipv6']")
                
                if addr_elem is None:
                    continue
                
                host_addr = addr_elem.get("addr")
                
                # Get hostname if available
                hostnames_elem = host.find("hostnames/hostname")
                hostname = hostnames_elem.get("name") if hostnames_elem is not None else host_addr
                
                # Parse ports
                ports = host.find("ports")
                if ports is None:
                    continue
                
                for port in ports.findall("port"):
                    port_id = port.get("portid")
                    protocol = port.get("protocol")
                    
                    state = port.find("state")
                    if state is None or state.get("state") != "open":
                        continue
                    
                    service = port.find("service")
                    service_name = service.get("name", "unknown") if service is not None else "unknown"
                    product = service.get("product", "") if service is not None else ""
                    version = service.get("version", "") if service is not None else ""
                    
                    finding = {
                        "host": host_addr,
                        "hostname": hostname,
                        "port": port_id,
                        "protocol": protocol,
                        "state": state.get("state"),
                        "service": service_name,
                        "product": product,
                        "version": version,
                        "cpe": [],
                        "scripts": []
                    }
                    
                    # Extract CPE identifiers
                    if service is not None:
                        for cpe in service.findall("cpe"):
                            if cpe.text:
                                finding["cpe"].append(cpe.text)
                    
                    # Parse NSE script results
                    for script in port.findall("script"):
                        script_id = script.get("id")
                        script_output = script.get("output", "")
                        
                        script_result = {
                            "id": script_id,
                            "output": script_output
                        }
                        
                        # Check for vulnerabilities in script output
                        if "vuln" in script_id.lower() or "CVE" in script_output:
                            script_result["is_vulnerability"] = True
                        
                        finding["scripts"].append(script_result)
                    
                    findings.append(finding)
            
        except ET.ParseError as e:
            logger.error(f"Failed to parse Nmap XML: {e}")
        except Exception as e:
            logger.error(f"Error processing Nmap results: {e}")
        
        return findings

