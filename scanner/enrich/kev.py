"""
CISA KEV (Known Exploited Vulnerabilities) enrichment
"""
import logging
import requests
from typing import Any, Dict, List, Set

logger = logging.getLogger(__name__)


class KEVEnricher:
    """Enrich CVEs with CISA KEV data"""
    
    def __init__(self):
        self.kev_cves: Set[str] = set()
        self.kev_details: Dict[str, Dict[str, Any]] = {}
        self.catalog_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    
    def load_kev_data(self) -> bool:
        """Load CISA KEV catalog"""
        logger.info("Loading CISA KEV catalog")
        
        try:
            response = requests.get(self.catalog_url, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            
            # Parse vulnerabilities
            vulnerabilities = data.get("vulnerabilities", [])
            
            for vuln in vulnerabilities:
                cve_id = vuln.get("cveID", "").upper()
                if cve_id:
                    self.kev_cves.add(cve_id)
                    
                    # Store additional details
                    self.kev_details[cve_id] = {
                        "vendor_project": vuln.get("vendorProject"),
                        "product": vuln.get("product"),
                        "vulnerability_name": vuln.get("vulnerabilityName"),
                        "date_added": vuln.get("dateAdded"),
                        "short_description": vuln.get("shortDescription"),
                        "required_action": vuln.get("requiredAction"),
                        "due_date": vuln.get("dueDate"),
                        "known_ransomware": vuln.get("knownRansomwareCampaignUse", "Unknown")
                    }
            
            logger.info(f"KEV catalog loaded: {len(self.kev_cves)} known exploited vulnerabilities")
            return True
        
        except requests.RequestException as e:
            logger.error(f"Failed to load KEV catalog: {e}")
            return False
        except Exception as e:
            logger.error(f"Error processing KEV data: {e}")
            return False
    
    def is_kev(self, cve_id: str) -> bool:
        """Check if CVE is in KEV catalog"""
        if not cve_id:
            return False
        return cve_id.upper() in self.kev_cves
    
    def get_kev_details(self, cve_id: str) -> Dict[str, Any]:
        """Get KEV details for a specific CVE"""
        if not cve_id:
            return {}
        return self.kev_details.get(cve_id.upper(), {})
    
    def add_kev(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Add KEV flags to findings"""
        logger.info("Enriching findings with KEV data")
        
        # Load KEV catalog
        self.load_kev_data()
        
        # Enrich findings
        kev_count = 0
        for finding in findings:
            cve_field = finding.get("cve")
            
            if not cve_field:
                finding["is_kev"] = False
                finding["kev_details"] = {}
                continue
            
            # Handle multiple CVEs
            if isinstance(cve_field, list):
                # Check if any CVE is in KEV
                is_kev = False
                kev_details = {}
                
                for cve in cve_field:
                    if not cve:
                        continue
                    if self.is_kev(cve):
                        is_kev = True
                        # Store details for first KEV found
                        if not kev_details:
                            kev_details = self.get_kev_details(cve)
                        break
                
                finding["is_kev"] = is_kev
                finding["kev_details"] = kev_details
                
                if is_kev:
                    kev_count += 1
            
            else:
                is_kev = self.is_kev(cve_field)
                finding["is_kev"] = is_kev
                finding["kev_details"] = self.get_kev_details(cve_field) if is_kev else {}
                
                if is_kev:
                    kev_count += 1
        
        logger.info(f"KEV enrichment completed: {kev_count} KEV findings identified")
        return findings

