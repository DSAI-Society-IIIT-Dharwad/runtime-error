"""
OWASP ZAP DAST engine runner
"""
import json
import logging
import subprocess
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
import requests

from scanner.settings import ScannerConfig

logger = logging.getLogger(__name__)


class ZapRunner:
    """OWASP ZAP Dynamic Application Security Testing"""
    
    def __init__(self, config: ScannerConfig):
        self.config = config
        self.zap_host = config.zap_host
        self.zap_port = config.zap_port
        self.api_key = config.scan_opts.zap.api_key or "scanner-api-key"
        self.base_url = f"http://{self.zap_host}:{self.zap_port}"
        self.process: Optional[subprocess.Popen] = None
    
    def _api_call(self, path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Make ZAP API call"""
        params = params or {}
        params["apikey"] = self.api_key
        
        url = f"{self.base_url}/{path}"
        try:
            response = requests.get(url, params=params, timeout=30)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"ZAP API call failed: {e}")
            return {}
    
    def start_daemon(self) -> bool:
        """Start ZAP in daemon mode"""
        logger.info(f"Starting ZAP daemon on {self.zap_host}:{self.zap_port}")
        
        try:
            # Start ZAP in headless daemon mode
            cmd = [
                "zap.sh" if subprocess.run(["which", "zap.sh"], 
                                          capture_output=True).returncode == 0 else "zap",
                "-daemon",
                "-host", self.zap_host,
                "-port", str(self.zap_port),
                "-config", f"api.key={self.api_key}",
                "-config", "api.addrs.addr.name=.*",
                "-config", "api.addrs.addr.regex=true"
            ]
            
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Wait for ZAP to be ready
            max_wait = 60
            for i in range(max_wait):
                try:
                    result = self._api_call("JSON/core/view/version")
                    if "version" in result:
                        logger.info(f"ZAP daemon ready (version: {result.get('version')})")
                        return True
                except Exception:
                    pass
                time.sleep(1)
            
            logger.error("ZAP daemon failed to start within timeout")
            return False
            
        except Exception as e:
            logger.error(f"Failed to start ZAP daemon: {e}")
            return False
    
    def stop_daemon(self):
        """Stop ZAP daemon"""
        try:
            self._api_call("JSON/core/action/shutdown")
        except Exception:
            pass
        
        if self.process:
            self.process.terminate()
            self.process.wait(timeout=10)
    
    def configure_authentication(self, target: str) -> Optional[str]:
        """Configure authentication context"""
        auth = self.config.scan_opts.zap.auth
        if not auth:
            return None
        
        logger.info("Configuring ZAP authentication")
        
        try:
            # Create context
            context_name = "AuthContext"
            result = self._api_call(
                "JSON/context/action/newContext",
                {"contextName": context_name}
            )
            context_id = result.get("contextId")
            
            # Include target in context
            parsed = urlparse(target)
            include_regex = f"{parsed.scheme}://{parsed.netloc}.*"
            self._api_call(
                "JSON/context/action/includeInContext",
                {"contextName": context_name, "regex": include_regex}
            )
            
            # Configure form-based authentication
            if "login_url" in auth:
                login_url = auth["login_url"]
                username = auth.get("username", "")
                password = auth.get("password", "")
                
                # Set authentication method
                self._api_call(
                    "JSON/authentication/action/setAuthenticationMethod",
                    {
                        "contextId": context_id,
                        "authMethodName": "formBasedAuthentication",
                        "authMethodConfigParams": f"loginUrl={login_url}"
                    }
                )
                
                # Create user
                self._api_call(
                    "JSON/users/action/newUser",
                    {
                        "contextId": context_id,
                        "name": "scanner_user"
                    }
                )
                
                # Set credentials
                self._api_call(
                    "JSON/users/action/setAuthenticationCredentials",
                    {
                        "contextId": context_id,
                        "userId": "0",
                        "authCredentialsConfigParams": f"username={username}&password={password}"
                    }
                )
                
                # Enable user
                self._api_call(
                    "JSON/users/action/setUserEnabled",
                    {"contextId": context_id, "userId": "0", "enabled": "true"}
                )
                
                logger.info("Authentication configured successfully")
                return context_id
        
        except Exception as e:
            logger.error(f"Failed to configure authentication: {e}")
        
        return None
    
    def import_openapi(self, openapi_url: str):
        """Import OpenAPI specification"""
        logger.info(f"Importing OpenAPI spec from {openapi_url}")
        try:
            self._api_call(
                "JSON/openapi/action/importUrl",
                {"url": openapi_url}
            )
        except Exception as e:
            logger.error(f"Failed to import OpenAPI spec: {e}")
    
    def spider(self, target: str, context_id: Optional[str] = None) -> str:
        """Run spider/crawler"""
        logger.info(f"Starting spider on {target}")
        
        if self.config.scan_opts.zap.ajax_crawl:
            # Use Ajax Spider for SPAs
            result = self._api_call(
                "JSON/ajaxSpider/action/scan",
                {"url": target, "contextName": context_id or ""}
            )
            scan_id = result.get("scanId", "")
            
            # Wait for completion
            while True:
                status = self._api_call("JSON/ajaxSpider/view/status")
                if status.get("status") == "stopped":
                    break
                time.sleep(2)
        else:
            # Use traditional spider
            params = {"url": target}
            if context_id:
                params["contextId"] = context_id
            
            result = self._api_call("JSON/spider/action/scan", params)
            scan_id = result.get("scan", "")
            
            # Wait for completion
            while True:
                status = self._api_call("JSON/spider/view/status", {"scanId": scan_id})
                progress = int(status.get("status", 0))
                if progress >= 100:
                    break
                logger.debug(f"Spider progress: {progress}%")
                time.sleep(2)
        
        logger.info("Spider completed")
        return scan_id
    
    def active_scan(self, target: str, context_id: Optional[str] = None) -> str:
        """Run active security scan"""
        if self.config.controls.passive_only:
            logger.info("Skipping active scan (passive_only mode)")
            return ""
        
        logger.info(f"Starting active scan on {target}")
        
        params = {"url": target}
        if context_id:
            params["contextId"] = context_id
        
        # Set scan policy to High+Medium
        self._api_call(
            "JSON/ascan/action/setScannerAttackStrength",
            {"id": "all", "attackStrength": "MEDIUM"}
        )
        
        result = self._api_call("JSON/ascan/action/scan", params)
        scan_id = result.get("scan", "")
        
        # Wait for completion
        while True:
            status = self._api_call("JSON/ascan/view/status", {"scanId": scan_id})
            progress = int(status.get("status", 0))
            if progress >= 100:
                break
            logger.debug(f"Active scan progress: {progress}%")
            time.sleep(5)
        
        logger.info("Active scan completed")
        return scan_id
    
    def get_alerts(self) -> List[Dict[str, Any]]:
        """Retrieve all alerts"""
        logger.info("Retrieving ZAP alerts")
        
        result = self._api_call("JSON/core/view/alerts")
        alerts = result.get("alerts", [])
        
        # Normalize alert structure
        findings = []
        for alert in alerts:
            findings.append({
                "pluginid": alert.get("pluginid"),
                "name": alert.get("name"),
                "risk": alert.get("risk"),  # High, Medium, Low, Informational
                "confidence": alert.get("confidence"),
                "url": alert.get("url"),
                "description": alert.get("description"),
                "solution": alert.get("solution"),
                "evidence": alert.get("evidence"),
                "cweid": alert.get("cweid"),
                "wascid": alert.get("wascid"),
                "reference": alert.get("reference", "").split("\n") if alert.get("reference") else []
            })
        
        logger.info(f"Retrieved {len(findings)} alerts")
        return findings
    
    def run(self, target: str) -> List[Dict[str, Any]]:
        """Execute full ZAP scan"""
        logger.info(f"Starting ZAP scan for {target}")
        
        try:
            # Start ZAP daemon
            if not self.start_daemon():
                logger.error("Failed to start ZAP daemon")
                return []
            
            # Import OpenAPI if provided
            if self.config.scan_opts.zap.openapi_url:
                self.import_openapi(self.config.scan_opts.zap.openapi_url)
            
            # Configure authentication
            context_id = self.configure_authentication(target)
            
            # Access target
            self._api_call("JSON/core/action/accessUrl", {"url": target})
            time.sleep(2)
            
            # Spider
            self.spider(target, context_id)
            
            # Active scan (if not passive_only)
            self.active_scan(target, context_id)
            
            # Get results
            findings = self.get_alerts()
            
            # Save raw output
            output_file = f"{self.config.output_dir}/raw/zap_alerts.json"
            with open(output_file, "w") as f:
                json.dump(findings, f, indent=2)
            logger.info(f"Saved raw ZAP output to {output_file}")
            
            return findings
            
        except Exception as e:
            logger.error(f"ZAP scan failed: {e}")
            return []
        
        finally:
            self.stop_daemon()

