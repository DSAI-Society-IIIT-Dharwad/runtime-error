"""
EPSS (Exploit Prediction Scoring System) enrichment
"""
import logging
import requests
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


class EPSSEnricher:
    """Enrich CVEs with EPSS scores"""
    
    def __init__(self):
        self.epss_data: Dict[str, float] = {}
        self.api_url = "https://api.first.org/data/v1/epss"
    
    def load_epss_data(self, cves: List[str]) -> bool:
        """Load EPSS data for specific CVEs via API"""
        if not cves:
            logger.info("No CVEs to enrich with EPSS")
            return True
        
        logger.info(f"Loading EPSS data for {len(cves)} CVE(s)")
        
        try:
            # EPSS API supports batch queries
            # Split into batches of 30 (API limitation)
            batch_size = 30
            for i in range(0, len(cves), batch_size):
                batch = cves[i:i + batch_size]
                cve_query = ",".join(batch)
                
                params = {"cve": cve_query}
                response = requests.get(self.api_url, params=params, timeout=30)
                response.raise_for_status()
                
                data = response.json()
                
                # Parse response
                if "data" in data:
                    for item in data["data"]:
                        cve_id = item.get("cve", "").upper()
                        epss_score = float(item.get("epss", 0))
                        percentile = float(item.get("percentile", 0))
                        
                        self.epss_data[cve_id] = {
                            "score": epss_score,
                            "percentile": percentile
                        }
                
                logger.debug(f"Loaded EPSS data for batch {i // batch_size + 1}")
            
            logger.info(f"EPSS data loaded for {len(self.epss_data)} CVE(s)")
            return True
        
        except requests.RequestException as e:
            logger.error(f"Failed to load EPSS data: {e}")
            return False
        except Exception as e:
            logger.error(f"Error processing EPSS data: {e}")
            return False
    
    def get_epss_score(self, cve_id: str) -> Dict[str, float]:
        """Get EPSS score for a specific CVE"""
        if not cve_id:
            return {"score": 0.0, "percentile": 0.0}
        
        cve_upper = cve_id.upper()
        return self.epss_data.get(cve_upper, {"score": 0.0, "percentile": 0.0})
    
    def add_epss(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Add EPSS scores to findings"""
        logger.info("Enriching findings with EPSS scores")
        
        # Collect all unique CVEs
        cves = set()
        for finding in findings:
            # Handle different CVE field formats
            cve_field = finding.get("cve")
            if cve_field:
                if isinstance(cve_field, list):
                    cves.update([c.upper() for c in cve_field if c])
                elif isinstance(cve_field, str):
                    cves.add(cve_field.upper())
        
        # Load EPSS data
        if cves:
            self.load_epss_data(list(cves))
        
        # Enrich findings
        for finding in findings:
            cve_field = finding.get("cve")
            
            if not cve_field:
                finding["epss_score"] = 0.0
                finding["epss_percentile"] = 0.0
                continue
            
            # Handle multiple CVEs - use highest EPSS score
            if isinstance(cve_field, list):
                max_score = 0.0
                max_percentile = 0.0
                
                for cve in cve_field:
                    if not cve:
                        continue
                    epss_data = self.get_epss_score(cve)
                    max_score = max(max_score, epss_data["score"])
                    max_percentile = max(max_percentile, epss_data["percentile"])
                
                finding["epss_score"] = round(max_score, 4)
                finding["epss_percentile"] = round(max_percentile, 4)
            
            else:
                epss_data = self.get_epss_score(cve_field)
                finding["epss_score"] = round(epss_data["score"], 4)
                finding["epss_percentile"] = round(epss_data["percentile"], 4)
        
        logger.info("EPSS enrichment completed")
        return findings

