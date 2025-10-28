"""Heuristic rules for anomaly detection."""

import re
import logging
from typing import List, Dict, Optional, Tuple
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from ipaddress import ip_address, ip_network

from core.config import settings
from core.security import SecurityUtils

logger = logging.getLogger(__name__)


class HeuristicDetector:
    """Rule-based detection for known attack patterns."""
    
    def __init__(self):
        """Initialize heuristic detector."""
        self.rules = [
            self.check_high_risk_ports,
            self.check_dns_tunneling,
            self.check_port_scanning,
            self.check_data_exfiltration,
            self.check_suspicious_tls,
            self.check_brute_force,
            self.check_malware_indicators,
            self.check_lateral_movement,
            self.check_c2_communication,
            self.check_crypto_mining
        ]
        
        # Load configuration
        self.high_risk_ports = settings.high_risk_ports
        self.dns_qps_threshold = settings.dns_qps_threshold
        self.suspicious_domains = settings.get_suspicious_domains()
        
        # Cache for tracking patterns
        self.pattern_cache = defaultdict(lambda: {
            'dns_queries': [],
            'connections': [],
            'failed_attempts': [],
            'last_update': datetime.utcnow()
        })
    
    def detect(self, device_mac: str, flows: List[Dict], 
              features: Dict[str, float]) -> List[Dict]:
        """Run heuristic detection rules.
        
        Args:
            device_mac: Device MAC address
            flows: Recent flows for device
            features: Extracted features
            
        Returns:
            List of detected issues with severity and details
        """
        detections = []
        
        # Update cache
        self._update_cache(device_mac, flows)
        
        # Run each rule
        for rule in self.rules:
            try:
                result = rule(device_mac, flows, features)
                if result:
                    if isinstance(result, list):
                        detections.extend(result)
                    else:
                        detections.append(result)
            except Exception as e:
                logger.error(f"Error in rule {rule.__name__}: {e}")
        
        # Clean old cache entries
        self._clean_cache()
        
        return detections
    
    def check_high_risk_ports(self, device_mac: str, flows: List[Dict],
                              features: Dict[str, float]) -> Optional[Dict]:
        """Check for connections to high-risk ports."""
        risky_connections = []
        
        for flow in flows:
            if flow.get('src_mac') == device_mac:
                dst_port = flow.get('dst_port')
                if dst_port in self.high_risk_ports:
                    dst_ip = flow.get('dst_ip', 'unknown')
                    
                    # Check if it's external
                    if not SecurityUtils.is_private_ip(dst_ip):
                        risky_connections.append({
                            'port': dst_port,
                            'ip': dst_ip,
                            'timestamp': flow.get('timestamp'),
                            'service': self._get_service_name(dst_port)
                        })
        
        if risky_connections:
            # Determine severity based on ports
            critical_ports = [23, 2323, 445]  # Telnet, alternate telnet, SMB
            has_critical = any(c['port'] in critical_ports for c in risky_connections)
            
            return {
                'rule': 'high_risk_ports',
                'severity': 'HIGH' if has_critical else 'MEDIUM',
                'title': 'High-Risk Port Activity Detected',
                'description': f"Device connected to {len(risky_connections)} high-risk ports",
                'details': {
                    'connections': risky_connections[:10],  # Limit to 10
                    'total_count': len(risky_connections),
                    'ports': list(set(c['port'] for c in risky_connections))
                }
            }
        
        return None
    
    def check_dns_tunneling(self, device_mac: str, flows: List[Dict],
                            features: Dict[str, float]) -> Optional[Dict]:
        """Check for DNS tunneling indicators."""
        dns_issues = []
        
        # Check DNS query rate
        dns_qps = features.get('dns_query_rate', 0)
        if dns_qps > self.dns_qps_threshold:
            dns_issues.append(f"High DNS query rate: {dns_qps:.2f} qps")
        
        # Analyze DNS queries in flows
        dns_queries = []
        suspicious_queries = []
        
        for flow in flows:
            if flow.get('src_mac') == device_mac:
                queries = flow.get('dns_queries', [])
                dns_queries.extend(queries)
                
                for query in queries:
                    # Check for tunneling patterns
                    if SecurityUtils.is_dns_tunneling_suspect(query):
                        suspicious_queries.append(query)
                    
                    # Check against known suspicious domains
                    if query.lower() in self.suspicious_domains:
                        suspicious_queries.append(query)
        
        # Check for excessive unique domains
        unique_domains = len(set(dns_queries))
        if unique_domains > 50:  # Threshold for unique domains in window
            dns_issues.append(f"Excessive unique domains: {unique_domains}")
        
        # Check for long domain names (common in tunneling)
        long_domains = [d for d in dns_queries if len(d) > 50]
        if long_domains:
            dns_issues.append(f"Long domain names detected: {len(long_domains)}")
        
        # Calculate subdomain entropy
        high_entropy_domains = []
        for domain in set(dns_queries):
            parts = domain.split('.')
            if len(parts) > 2:  # Has subdomain
                subdomain = parts[0]
                if len(subdomain) > 10:
                    entropy = SecurityUtils.calculate_entropy(subdomain)
                    if entropy > 4.0:
                        high_entropy_domains.append(domain)
        
        if high_entropy_domains:
            dns_issues.append(f"High entropy subdomains: {len(high_entropy_domains)}")
        
        if dns_issues or suspicious_queries:
            severity = 'HIGH' if suspicious_queries or dns_qps > self.dns_qps_threshold * 2 else 'MEDIUM'
            
            return {
                'rule': 'dns_tunneling',
                'severity': severity,
                'title': 'Potential DNS Tunneling Detected',
                'description': 'Suspicious DNS activity that may indicate data exfiltration',
                'details': {
                    'issues': dns_issues,
                    'suspicious_queries': suspicious_queries[:10],
                    'dns_qps': dns_qps,
                    'unique_domains': unique_domains,
                    'high_entropy_examples': high_entropy_domains[:5]
                }
            }
        
        return None
    
    def check_port_scanning(self, device_mac: str, flows: List[Dict],
                            features: Dict[str, float]) -> Optional[Dict]:
        """Check for port scanning behavior."""
        # Track destination IP and port combinations
        dst_ips = defaultdict(set)
        failed_connections = []
        
        for flow in flows:
            if flow.get('src_mac') == device_mac:
                dst_ip = flow.get('dst_ip')
                dst_port = flow.get('dst_port')
                
                if dst_ip and dst_port:
                    dst_ips[dst_ip].add(dst_port)
                    
                    # Check for failed connections (low packet count)
                    if flow.get('packets_total', 0) <= 3:
                        failed_connections.append({
                            'ip': dst_ip,
                            'port': dst_port,
                            'timestamp': flow.get('timestamp')
                        })
        
        # Detect scanning patterns
        scan_indicators = []
        
        # Vertical scan: many ports on same IP
        for ip, ports in dst_ips.items():
            if len(ports) > 10:
                scan_indicators.append({
                    'type': 'vertical_scan',
                    'target': ip,
                    'port_count': len(ports),
                    'ports': sorted(list(ports))[:20]
                })
        
        # Horizontal scan: same port on many IPs
        port_targets = defaultdict(set)
        for ip, ports in dst_ips.items():
            for port in ports:
                port_targets[port].add(ip)
        
        for port, ips in port_targets.items():
            if len(ips) > 5:
                scan_indicators.append({
                    'type': 'horizontal_scan',
                    'port': port,
                    'target_count': len(ips),
                    'targets': list(ips)[:10]
                })
        
        # Check scan behavior score from features
        scan_score = features.get('scan_behavior_score', 0)
        if scan_score > 0.5:
            scan_indicators.append({
                'type': 'behavioral',
                'score': scan_score
            })
        
        if scan_indicators:
            # Determine severity
            total_suspicious = sum(1 for s in scan_indicators if s.get('port_count', 0) > 20 or s.get('target_count', 0) > 10)
            severity = 'HIGH' if total_suspicious > 0 else 'MEDIUM'
            
            return {
                'rule': 'port_scanning',
                'severity': severity,
                'title': 'Port Scanning Activity Detected',
                'description': 'Device is exhibiting port scanning behavior',
                'details': {
                    'scan_patterns': scan_indicators,
                    'failed_connections': len(failed_connections),
                    'unique_targets': len(dst_ips),
                    'total_ports_scanned': sum(len(ports) for ports in dst_ips.values())
                }
            }
        
        return None
    
    def check_data_exfiltration(self, device_mac: str, flows: List[Dict],
                                features: Dict[str, float]) -> Optional[Dict]:
        """Check for data exfiltration indicators."""
        large_uploads = []
        total_uploaded = 0
        external_transfers = []
        
        for flow in flows:
            if flow.get('src_mac') == device_mac:
                bytes_out = flow.get('bytes_total', 0)
                total_uploaded += bytes_out
                
                dst_ip = flow.get('dst_ip', '')
                is_external = not SecurityUtils.is_private_ip(dst_ip)
                
                # Check for large transfers
                if bytes_out > 10485760:  # > 10MB
                    large_uploads.append({
                        'destination': dst_ip,
                        'bytes': bytes_out,
                        'mb': bytes_out / 1048576,
                        'timestamp': flow.get('timestamp'),
                        'is_external': is_external
                    })
                
                # Track external transfers
                if is_external and bytes_out > 1048576:  # > 1MB to external
                    external_transfers.append({
                        'destination': dst_ip,
                        'bytes': bytes_out,
                        'port': flow.get('dst_port')
                    })
        
        # Check exfiltration score from features
        exfil_score = features.get('data_exfil_score', 0)
        
        # Check for suspicious upload patterns
        suspicious_patterns = []
        
        # Night time uploads (00:00 - 06:00)
        night_uploads = [u for u in large_uploads 
                        if self._is_night_time(u.get('timestamp'))]
        if night_uploads:
            suspicious_patterns.append(f"Night time uploads: {len(night_uploads)}")
        
        # Uploads to non-standard ports
        unusual_port_uploads = [t for t in external_transfers 
                               if t.get('port') not in [80, 443, 22]]
        if unusual_port_uploads:
            suspicious_patterns.append(f"Uploads to unusual ports: {len(unusual_port_uploads)}")
        
        if large_uploads or (exfil_score > 0.5 and external_transfers):
            # Determine severity
            total_mb = sum(u['mb'] for u in large_uploads)
            severity = 'CRITICAL' if total_mb > 100 else ('HIGH' if total_mb > 50 else 'MEDIUM')
            
            return {
                'rule': 'data_exfiltration',
                'severity': severity,
                'title': 'Potential Data Exfiltration',
                'description': f"Large data transfers detected: {total_mb:.2f} MB",
                'details': {
                    'large_uploads': large_uploads[:10],
                    'total_uploaded_mb': total_uploaded / 1048576,
                    'external_transfers': len(external_transfers),
                    'suspicious_patterns': suspicious_patterns,
                    'exfiltration_score': exfil_score
                }
            }
        
        return None
    
    def check_suspicious_tls(self, device_mac: str, flows: List[Dict],
                             features: Dict[str, float]) -> Optional[Dict]:
        """Check for suspicious TLS/SSL patterns."""
        tls_issues = []
        sni_list = []
        sni_changes = []
        
        # Track SNI changes over time
        last_sni = None
        last_time = None
        
        for flow in sorted(flows, key=lambda f: f.get('timestamp', '')):
            if flow.get('src_mac') == device_mac:
                sni = flow.get('sni')
                if sni:
                    sni_list.append(sni)
                    
                    # Check for rapid SNI changes (possible tunneling)
                    if last_sni and last_sni != sni:
                        if last_time:
                            try:
                                current_time = self._parse_timestamp(flow.get('timestamp'))
                                time_diff = (current_time - last_time).total_seconds()
                                
                                if time_diff < 10:  # SNI change within 10 seconds
                                    sni_changes.append({
                                        'from': last_sni,
                                        'to': sni,
                                        'interval': time_diff
                                    })
                            except:
                                pass
                    
                    last_sni = sni
                    last_time = self._parse_timestamp(flow.get('timestamp'))
        
        # Check for suspicious SNI patterns
        if sni_changes and len(sni_changes) > 5:
            tls_issues.append(f"Rapid SNI changes: {len(sni_changes)}")
        
        # Check for IP addresses as SNI
        ip_snis = [s for s in sni_list if self._is_ip_address(s)]
        if ip_snis:
            tls_issues.append(f"IP addresses used as SNI: {len(ip_snis)}")
        
        # Check for suspicious domains in SNI
        suspicious_snis = [s for s in sni_list if s.lower() in self.suspicious_domains]
        if suspicious_snis:
            tls_issues.append(f"Suspicious domains in SNI: {len(suspicious_snis)}")
        
        # Check for uncommon TLS ports
        tls_flows_unusual_ports = []
        for flow in flows:
            if flow.get('src_mac') == device_mac and flow.get('sni'):
                port = flow.get('dst_port')
                if port not in [443, 8443, 9443]:  # Common TLS ports
                    tls_flows_unusual_ports.append({
                        'port': port,
                        'sni': flow.get('sni'),
                        'destination': flow.get('dst_ip')
                    })
        
        if tls_flows_unusual_ports:
            tls_issues.append(f"TLS on unusual ports: {len(tls_flows_unusual_ports)}")
        
        if tls_issues:
            severity = 'HIGH' if (suspicious_snis or ip_snis) else 'MEDIUM'
            
            return {
                'rule': 'suspicious_tls',
                'severity': severity,
                'title': 'Suspicious TLS Activity',
                'description': 'Abnormal TLS/SSL patterns detected',
                'details': {
                    'issues': tls_issues,
                    'sni_changes': sni_changes[:10],
                    'ip_snis': ip_snis[:5],
                    'suspicious_snis': suspicious_snis[:5],
                    'unusual_port_tls': tls_flows_unusual_ports[:5]
                }
            }
        
        return None
    
    def check_brute_force(self, device_mac: str, flows: List[Dict],
                         features: Dict[str, float]) -> Optional[Dict]:
        """Check for brute force attack patterns."""
        # Track authentication-related connections
        auth_ports = [21, 22, 23, 3389, 5900]  # FTP, SSH, Telnet, RDP, VNC
        auth_attempts = defaultdict(list)
        
        for flow in flows:
            if flow.get('src_mac') == device_mac:
                dst_port = flow.get('dst_port')
                if dst_port in auth_ports:
                    dst_ip = flow.get('dst_ip')
                    auth_attempts[dst_ip].append({
                        'port': dst_port,
                        'service': self._get_service_name(dst_port),
                        'timestamp': flow.get('timestamp'),
                        'packets': flow.get('packets_total', 0)
                    })
        
        # Detect brute force patterns
        brute_force_targets = []
        
        for target_ip, attempts in auth_attempts.items():
            if len(attempts) > 10:  # Many attempts to same target
                # Group by time window (1 minute)
                time_windows = defaultdict(list)
                for attempt in attempts:
                    try:
                        ts = self._parse_timestamp(attempt['timestamp'])
                        window = ts.replace(second=0, microsecond=0)
                        time_windows[window].append(attempt)
                    except:
                        pass
                
                # Check for rapid attempts
                for window, window_attempts in time_windows.items():
                    if len(window_attempts) > 5:
                        brute_force_targets.append({
                            'target': target_ip,
                            'attempts_in_window': len(window_attempts),
                            'services': list(set(a['service'] for a in window_attempts)),
                            'timestamp': window.isoformat()
                        })
        
        # Check failed connection ratio from features
        failed_ratio = features.get('failed_conn_ratio', 0)
        if failed_ratio > 0.5 and auth_attempts:
            brute_force_targets.append({
                'indicator': 'high_failure_rate',
                'ratio': failed_ratio
            })
        
        if brute_force_targets:
            total_attempts = sum(len(attempts) for attempts in auth_attempts.values())
            severity = 'CRITICAL' if total_attempts > 100 else 'HIGH'
            
            return {
                'rule': 'brute_force',
                'severity': severity,
                'title': 'Brute Force Attack Detected',
                'description': f"Multiple authentication attempts to {len(auth_attempts)} targets",
                'details': {
                    'targets': brute_force_targets[:10],
                    'total_attempts': total_attempts,
                    'targeted_services': list(set(self._get_service_name(p) for p in auth_ports if any(a['port'] == p for attempts in auth_attempts.values() for a in attempts))),
                    'failed_connection_ratio': failed_ratio
                }
            }
        
        return None
    
    def check_malware_indicators(self, device_mac: str, flows: List[Dict],
                                 features: Dict[str, float]) -> Optional[Dict]:
        """Check for malware communication patterns."""
        malware_indicators = []
        
        # Known malware ports
        malware_ports = [4444, 5555, 6666, 6667, 7777, 8888, 9999]  # Common backdoor/botnet ports
        
        # Check for connections to malware ports
        malware_connections = []
        for flow in flows:
            if flow.get('src_mac') == device_mac:
                dst_port = flow.get('dst_port')
                if dst_port in malware_ports:
                    malware_connections.append({
                        'port': dst_port,
                        'destination': flow.get('dst_ip'),
                        'timestamp': flow.get('timestamp')
                    })
        
        if malware_connections:
            malware_indicators.append(f"Connections to known malware ports: {len(malware_connections)}")
        
        # Check for beaconing behavior (regular intervals)
        beacon_candidates = self._detect_beaconing(flows, device_mac)
        if beacon_candidates:
            malware_indicators.append(f"Beaconing behavior detected: {len(beacon_candidates)} patterns")
        
        # Check for DGA domains
        dga_domains = []
        for flow in flows:
            queries = flow.get('dns_queries', [])
            for domain in queries:
                if self._is_dga_domain(domain):
                    dga_domains.append(domain)
        
        if dga_domains:
            malware_indicators.append(f"DGA-like domains: {len(set(dga_domains))}")
        
        # Check suspicious download patterns
        download_patterns = self._check_download_patterns(flows, device_mac)
        if download_patterns:
            malware_indicators.extend(download_patterns)
        
        if malware_indicators:
            severity = 'CRITICAL' if (malware_connections or beacon_candidates) else 'HIGH'
            
            return {
                'rule': 'malware_indicators',
                'severity': severity,
                'title': 'Potential Malware Activity',
                'description': 'Patterns consistent with malware communication detected',
                'details': {
                    'indicators': malware_indicators,
                    'malware_port_connections': malware_connections[:10],
                    'beacon_patterns': beacon_candidates[:5],
                    'dga_domains': list(set(dga_domains))[:10]
                }
            }
        
        return None
    
    def check_lateral_movement(self, device_mac: str, flows: List[Dict],
                               features: Dict[str, float]) -> Optional[Dict]:
        """Check for lateral movement within network."""
        internal_scans = []
        admin_connections = []
        file_shares = []
        
        for flow in flows:
            if flow.get('src_mac') == device_mac:
                dst_ip = flow.get('dst_ip')
                
                # Check if targeting internal network
                if SecurityUtils.is_private_ip(dst_ip):
                    dst_port = flow.get('dst_port')
                    
                    # Admin/remote access ports
                    if dst_port in [22, 23, 3389, 5900, 5985, 5986]:  # SSH, Telnet, RDP, VNC, WinRM
                        admin_connections.append({
                            'target': dst_ip,
                            'port': dst_port,
                            'service': self._get_service_name(dst_port),
                            'timestamp': flow.get('timestamp')
                        })
                    
                    # File sharing ports
                    elif dst_port in [139, 445, 2049]:  # SMB, NFS
                        file_shares.append({
                            'target': dst_ip,
                            'port': dst_port,
                            'service': self._get_service_name(dst_port),
                            'timestamp': flow.get('timestamp')
                        })
        
        # Check for internal scanning
        internal_targets = defaultdict(set)
        for flow in flows:
            if flow.get('src_mac') == device_mac:
                dst_ip = flow.get('dst_ip')
                if SecurityUtils.is_private_ip(dst_ip):
                    dst_port = flow.get('dst_port')
                    internal_targets[dst_ip].add(dst_port)
        
        # Many internal IPs contacted = possible scanning
        if len(internal_targets) > 10:
            internal_scans.append({
                'type': 'wide_internal_scan',
                'target_count': len(internal_targets),
                'sample_targets': list(internal_targets.keys())[:10]
            })
        
        if admin_connections or file_shares or internal_scans:
            unique_admin_targets = len(set(c['target'] for c in admin_connections))
            severity = 'HIGH' if unique_admin_targets > 3 else 'MEDIUM'
            
            return {
                'rule': 'lateral_movement',
                'severity': severity,
                'title': 'Potential Lateral Movement',
                'description': 'Suspicious internal network activity detected',
                'details': {
                    'admin_connections': admin_connections[:10],
                    'file_share_access': file_shares[:10],
                    'internal_scanning': internal_scans,
                    'unique_internal_targets': len(internal_targets),
                    'unique_admin_targets': unique_admin_targets
                }
            }
        
        return None
    
    def check_c2_communication(self, device_mac: str, flows: List[Dict],
                               features: Dict[str, float]) -> Optional[Dict]:
        """Check for Command & Control communication patterns."""
        c2_indicators = []
        
        # Check for beaconing
        beacon_patterns = self._detect_beaconing(flows, device_mac)
        if beacon_patterns:
            c2_indicators.append({
                'type': 'beaconing',
                'patterns': beacon_patterns
            })
        
        # Check for encrypted channels on unusual ports
        encrypted_unusual = []
        for flow in flows:
            if flow.get('src_mac') == device_mac:
                if flow.get('is_encrypted') or flow.get('sni'):
                    port = flow.get('dst_port')
                    if port not in [443, 8443, 993, 995, 465, 587]:  # Common encrypted ports
                        encrypted_unusual.append({
                            'port': port,
                            'destination': flow.get('dst_ip'),
                            'sni': flow.get('sni')
                        })
        
        if encrypted_unusual:
            c2_indicators.append({
                'type': 'encrypted_unusual_ports',
                'count': len(encrypted_unusual),
                'examples': encrypted_unusual[:5]
            })
        
        # Check for long-duration connections
        long_connections = []
        for flow in flows:
            if flow.get('src_mac') == device_mac:
                duration = flow.get('duration', 0)
                if duration > 300:  # > 5 minutes
                    long_connections.append({
                        'destination': flow.get('dst_ip'),
                        'port': flow.get('dst_port'),
                        'duration_seconds': duration,
                        'duration_minutes': duration / 60
                    })
        
        if long_connections:
            c2_indicators.append({
                'type': 'persistent_connections',
                'connections': long_connections[:5]
            })
        
        # Check for suspicious user agents or headers (if HTTP)
        # This would require deeper packet inspection
        
        if c2_indicators:
            severity = 'CRITICAL' if len(c2_indicators) > 2 else 'HIGH'
            
            return {
                'rule': 'c2_communication',
                'severity': severity,
                'title': 'Potential C2 Communication',
                'description': 'Patterns consistent with command and control activity',
                'details': {
                    'indicators': c2_indicators,
                    'beacon_count': len(beacon_patterns) if beacon_patterns else 0,
                    'encrypted_unusual_count': len(encrypted_unusual)
                }
            }
        
        return None
    
    def check_crypto_mining(self, device_mac: str, flows: List[Dict],
                           features: Dict[str, float]) -> Optional[Dict]:
        """Check for cryptocurrency mining activity."""
        mining_indicators = []
        
        # Known mining pool ports
        mining_ports = [3333, 4444, 5555, 7777, 8333, 8888, 9999, 14444, 45560]
        
        # Known mining pool domains (partial list)
        mining_domains = [
            'pool.', 'mining.', 'miner.', 'xmr.', 'eth.', 'btc.',
            'nanopool', 'ethermine', 'f2pool', 'slushpool', 'antpool'
        ]
        
        # Check for connections to mining ports
        mining_connections = []
        for flow in flows:
            if flow.get('src_mac') == device_mac:
                dst_port = flow.get('dst_port')
                if dst_port in mining_ports:
                    mining_connections.append({
                        'port': dst_port,
                        'destination': flow.get('dst_ip'),
                        'timestamp': flow.get('timestamp')
                    })
        
        if mining_connections:
            mining_indicators.append(f"Connections to mining ports: {len(mining_connections)}")
        
        # Check DNS queries for mining pools
        mining_dns = []
        for flow in flows:
            queries = flow.get('dns_queries', [])
            for query in queries:
                query_lower = query.lower()
                if any(pool in query_lower for pool in mining_domains):
                    mining_dns.append(query)
        
        if mining_dns:
            mining_indicators.append(f"Mining pool DNS queries: {len(set(mining_dns))}")
        
        # Check for sustained high CPU indication (many flows, consistent activity)
        if features.get('connection_rate', 0) > 10 and features.get('temporal_consistency', 0) > 0.8:
            mining_indicators.append("Sustained high network activity")
        
        # Check for Stratum protocol patterns (would need deeper inspection)
        stratum_patterns = self._detect_stratum_protocol(flows, device_mac)
        if stratum_patterns:
            mining_indicators.append(f"Stratum protocol patterns: {len(stratum_patterns)}")
        
        if mining_indicators:
            severity = 'HIGH' if (mining_connections and mining_dns) else 'MEDIUM'
            
            return {
                'rule': 'crypto_mining',
                'severity': severity,
                'title': 'Cryptocurrency Mining Activity',
                'description': 'Device may be mining cryptocurrency',
                'details': {
                    'indicators': mining_indicators,
                    'mining_connections': mining_connections[:10],
                    'mining_domains': list(set(mining_dns))[:10],
                    'connection_rate': features.get('connection_rate', 0)
                }
            }
        
        return None
    
    # Helper methods
    
    def _update_cache(self, device_mac: str, flows: List[Dict]):
        """Update pattern cache for device."""
        cache = self.pattern_cache[device_mac]
        cache['connections'].extend(flows)
        cache['last_update'] = datetime.utcnow()
        
        # Keep only recent data (last hour)
        cutoff = datetime.utcnow() - timedelta(hours=1)
        cache['connections'] = [
            f for f in cache['connections']
            if self._parse_timestamp(f.get('timestamp')) >= cutoff
        ]
    
    def _clean_cache(self):
        """Remove old cache entries."""
        cutoff = datetime.utcnow() - timedelta(hours=2)
        to_remove = []
        
        for mac, cache in self.pattern_cache.items():
            if cache['last_update'] < cutoff:
                to_remove.append(mac)
        
        for mac in to_remove:
            del self.pattern_cache[mac]
    
    def _get_service_name(self, port: int) -> str:
        """Get service name for port."""
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP',
            443: 'HTTPS', 445: 'SMB', 1433: 'MSSQL', 3306: 'MySQL',
            3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC',
            2323: 'Telnet-Alt', 4444: 'Backdoor', 8080: 'HTTP-Proxy'
        }
        return services.get(port, f'Port-{port}')
    
    def _parse_timestamp(self, ts) -> datetime:
        """Parse timestamp from various formats."""
        if isinstance(ts, datetime):
            return ts
        elif isinstance(ts, str):
            try:
                return datetime.fromisoformat(ts.replace('Z', '+00:00'))
            except:
                return datetime.utcnow()
        else:
            return datetime.utcnow()
    
    def _is_night_time(self, timestamp) -> bool:
        """Check if timestamp is during night hours (00:00-06:00)."""
        try:
            ts = self._parse_timestamp(timestamp)
            return 0 <= ts.hour < 6
        except:
            return False
    
    def _is_ip_address(self, value: str) -> bool:
        """Check if string is an IP address."""
        try:
            ip_address(value)
            return True
        except:
            return False
    
    def _detect_beaconing(self, flows: List[Dict], device_mac: str) -> List[Dict]:
        """Detect beaconing behavior (regular intervals)."""
        # Group connections by destination
        destination_times = defaultdict(list)
        
        for flow in flows:
            if flow.get('src_mac') == device_mac:
                dst = f"{flow.get('dst_ip')}:{flow.get('dst_port')}"
                ts = self._parse_timestamp(flow.get('timestamp'))
                destination_times[dst].append(ts)
        
        beacon_patterns = []
        
        for dst, timestamps in destination_times.items():
            if len(timestamps) < 5:  # Need at least 5 connections
                continue
            
            # Sort timestamps
            timestamps.sort()
            
            # Calculate intervals
            intervals = []
            for i in range(1, len(timestamps)):
                interval = (timestamps[i] - timestamps[i-1]).total_seconds()
                intervals.append(interval)
            
            # Check for regular intervals (low variance)
            if intervals:
                mean_interval = sum(intervals) / len(intervals)
                if mean_interval > 0:
                    variance = sum((i - mean_interval) ** 2 for i in intervals) / len(intervals)
                    cv = (variance ** 0.5) / mean_interval  # Coefficient of variation
                    
                    # Low CV indicates regular intervals
                    if cv < 0.2 and mean_interval > 10:  # Regular and not too frequent
                        beacon_patterns.append({
                            'destination': dst,
                            'interval_seconds': mean_interval,
                            'regularity': 1 - cv,  # Higher is more regular
                            'connection_count': len(timestamps)
                        })
        
        return beacon_patterns
    
    def _is_dga_domain(self, domain: str) -> bool:
        """Check if domain looks like DGA (Domain Generation Algorithm)."""
        if not domain:
            return False
        
        # Remove TLD
        parts = domain.split('.')
        if len(parts) < 2:
            return False
        
        name = parts[0]  # Get domain name without TLD
        
        # DGA characteristics:
        # 1. High consonant to vowel ratio
        # 2. No common words
        # 3. High entropy
        # 4. Specific length patterns
        
        if len(name) < 5 or len(name) > 20:
            return False
        
        # Check entropy
        entropy = SecurityUtils.calculate_entropy(name)
        if entropy < 3.5:  # Too low entropy for DGA
            return False
        
        # Check vowel ratio
        vowels = sum(1 for c in name.lower() if c in 'aeiou')
        if len(name) > 0:
            vowel_ratio = vowels / len(name)
            if vowel_ratio > 0.4 or vowel_ratio < 0.1:  # Normal domains have ~35% vowels
                return False
        
        # Check for numbers (common in DGA)
        has_numbers = any(c.isdigit() for c in name)
        
        # High entropy + unusual vowel ratio + possibly numbers = likely DGA
        return entropy > 4.0 or (entropy > 3.5 and has_numbers)
    
    def _check_download_patterns(self, flows: List[Dict], device_mac: str) -> List[str]:
        """Check for suspicious download patterns."""
        patterns = []
        
        # Check for downloads from non-standard ports
        downloads = []
        for flow in flows:
            if flow.get('dst_mac') == device_mac:  # Incoming to device
                src_port = flow.get('src_port')
                if src_port not in [80, 443, 21, 22] and flow.get('bytes_total', 0) > 1048576:
                    downloads.append({
                        'source': flow.get('src_ip'),
                        'port': src_port,
                        'bytes': flow.get('bytes_total')
                    })
        
        if downloads:
            patterns.append(f"Downloads from unusual ports: {len(downloads)}")
        
        # Check for binary downloads (would need content inspection)
        # This is a simplified check based on port and size
        
        return patterns
    
    def _detect_stratum_protocol(self, flows: List[Dict], device_mac: str) -> List[Dict]:
        """Detect Stratum mining protocol patterns."""
        stratum_patterns = []
        
        # Stratum typically uses JSON-RPC over TCP
        # Look for persistent connections with regular small data exchanges
        
        for flow in flows:
            if flow.get('src_mac') == device_mac:
                # Check for mining-related ports with sustained connections
                if (flow.get('dst_port') in [3333, 4444, 8333] and
                    flow.get('duration', 0) > 60 and
                    flow.get('packets_total', 0) > 100):
                    
                    stratum_patterns.append({
                        'destination': f"{flow.get('dst_ip')}:{flow.get('dst_port')}",
                        'duration': flow.get('duration'),
                        'packets': flow.get('packets_total')
                    })
        
        return stratum_patterns
