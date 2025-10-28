"""Feature engineering for anomaly detection."""

import numpy as np
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import math
import logging

logger = logging.getLogger(__name__)


class FeatureExtractor:
    """Extract features from network traffic for anomaly detection."""
    
    def __init__(self):
        """Initialize feature extractor."""
        self.feature_names = [
            'outbound_ratio',
            'unique_dst_count',
            'unique_dst_ports',
            'bytes_out_total',
            'packets_out_total',
            'avg_packet_size',
            'port_entropy',
            'dns_query_rate',
            'dns_unique_domains',
            'tcp_ratio',
            'udp_ratio',
            'high_port_ratio',
            'night_activity_ratio',
            'burst_score',
            'connection_rate',
            'failed_conn_ratio',
            'data_exfil_score',
            'scan_behavior_score',
            'protocol_diversity',
            'temporal_consistency'
        ]
        
        # Cache for historical data
        self.history = defaultdict(lambda: {
            'flows': [],
            'dns_queries': [],
            'connections': [],
            'last_update': datetime.utcnow()
        })
    
    def extract_features(self, device_mac: str, flows: List[Dict],
                         window_minutes: int = 5) -> Dict[str, float]:
        """Extract features for a device from recent flows.
        
        Args:
            device_mac: Device MAC address
            flows: List of flow dictionaries
            window_minutes: Time window for feature extraction
            
        Returns:
            Dictionary of feature values
        """
        features = {}
        
        # Filter flows for this device and time window
        now = datetime.utcnow()
        cutoff = now - timedelta(minutes=window_minutes)
        
        device_flows = []
        for flow in flows:
            try:
                # Parse timestamp if string
                if isinstance(flow.get('timestamp'), str):
                    flow_time = datetime.fromisoformat(flow['timestamp'].replace('Z', '+00:00'))
                else:
                    flow_time = flow.get('timestamp', now)
                
                # Check if flow involves this device
                if flow_time >= cutoff:
                    if (flow.get('src_mac') == device_mac or 
                        flow.get('dst_mac') == device_mac):
                        device_flows.append(flow)
            except Exception as e:
                logger.warning(f"Error processing flow: {e}")
                continue
        
        if not device_flows:
            # Return zero features if no flows
            return {name: 0.0 for name in self.feature_names}
        
        # Calculate features
        features['outbound_ratio'] = self._calc_outbound_ratio(device_flows, device_mac)
        features['unique_dst_count'] = self._calc_unique_destinations(device_flows, device_mac)
        features['unique_dst_ports'] = self._calc_unique_dst_ports(device_flows, device_mac)
        
        # Traffic volume features
        volumes = self._calc_traffic_volumes(device_flows, device_mac)
        features.update(volumes)
        
        # Port entropy
        features['port_entropy'] = self._calc_port_entropy(device_flows, device_mac)
        
        # DNS features
        dns_features = self._calc_dns_features(device_flows, device_mac, window_minutes)
        features.update(dns_features)
        
        # Protocol ratios
        protocol_features = self._calc_protocol_ratios(device_flows)
        features.update(protocol_features)
        
        # Temporal features
        temporal_features = self._calc_temporal_features(device_flows, device_mac)
        features.update(temporal_features)
        
        # Behavioral scores
        behavioral_features = self._calc_behavioral_scores(device_flows, device_mac)
        features.update(behavioral_features)
        
        # Update history
        self._update_history(device_mac, device_flows)
        
        # Ensure all features are present
        for name in self.feature_names:
            if name not in features:
                features[name] = 0.0
        
        return features
    
    def _calc_outbound_ratio(self, flows: List[Dict], device_mac: str) -> float:
        """Calculate ratio of outbound vs inbound traffic."""
        outbound = 0
        inbound = 0
        
        for flow in flows:
            if flow.get('src_mac') == device_mac:
                outbound += flow.get('bytes_total', 0)
            elif flow.get('dst_mac') == device_mac:
                inbound += flow.get('bytes_total', 0)
        
        total = outbound + inbound
        return outbound / total if total > 0 else 0.0
    
    def _calc_unique_destinations(self, flows: List[Dict], device_mac: str) -> float:
        """Count unique destination IPs."""
        destinations = set()
        
        for flow in flows:
            if flow.get('src_mac') == device_mac:
                dst_ip = flow.get('dst_ip')
                if dst_ip:
                    destinations.add(dst_ip)
        
        return float(len(destinations))
    
    def _calc_unique_dst_ports(self, flows: List[Dict], device_mac: str) -> float:
        """Count unique destination ports."""
        ports = set()
        
        for flow in flows:
            if flow.get('src_mac') == device_mac:
                dst_port = flow.get('dst_port')
                if dst_port:
                    ports.add(dst_port)
        
        return float(len(ports))
    
    def _calc_traffic_volumes(self, flows: List[Dict], device_mac: str) -> Dict[str, float]:
        """Calculate traffic volume features."""
        total_bytes_out = 0
        total_packets_out = 0
        packet_sizes = []
        
        for flow in flows:
            if flow.get('src_mac') == device_mac:
                bytes_total = flow.get('bytes_total', 0)
                packets_total = flow.get('packets_total', 1)
                
                total_bytes_out += bytes_total
                total_packets_out += packets_total
                
                if packets_total > 0:
                    avg_size = bytes_total / packets_total
                    packet_sizes.append(avg_size)
        
        avg_packet_size = np.mean(packet_sizes) if packet_sizes else 0.0
        
        return {
            'bytes_out_total': float(total_bytes_out),
            'packets_out_total': float(total_packets_out),
            'avg_packet_size': float(avg_packet_size)
        }
    
    def _calc_port_entropy(self, flows: List[Dict], device_mac: str) -> float:
        """Calculate Shannon entropy of destination ports."""
        port_counts = Counter()
        
        for flow in flows:
            if flow.get('src_mac') == device_mac:
                dst_port = flow.get('dst_port')
                if dst_port:
                    port_counts[dst_port] += 1
        
        if not port_counts:
            return 0.0
        
        # Calculate entropy
        total = sum(port_counts.values())
        entropy = 0.0
        
        for count in port_counts.values():
            if count > 0:
                prob = count / total
                entropy -= prob * math.log2(prob)
        
        # Normalize by log2 of unique ports
        n_unique = len(port_counts)
        if n_unique > 1:
            entropy = entropy / math.log2(n_unique)
        
        return float(entropy)
    
    def _calc_dns_features(self, flows: List[Dict], device_mac: str, 
                           window_minutes: int) -> Dict[str, float]:
        """Calculate DNS-related features."""
        dns_queries = []
        unique_domains = set()
        
        for flow in flows:
            if flow.get('src_mac') == device_mac:
                # Check for DNS queries in flow
                queries = flow.get('dns_queries', [])
                if queries:
                    dns_queries.extend(queries)
                    unique_domains.update(queries)
                
                # Also check if it's DNS traffic (port 53)
                if flow.get('dst_port') == 53:
                    dns_queries.append(flow.get('timestamp'))
        
        # Calculate query rate (queries per second)
        query_rate = len(dns_queries) / (window_minutes * 60) if window_minutes > 0 else 0
        
        return {
            'dns_query_rate': float(query_rate),
            'dns_unique_domains': float(len(unique_domains))
        }
    
    def _calc_protocol_ratios(self, flows: List[Dict]) -> Dict[str, float]:
        """Calculate protocol distribution ratios."""
        total_flows = len(flows)
        if total_flows == 0:
            return {
                'tcp_ratio': 0.0,
                'udp_ratio': 0.0,
                'protocol_diversity': 0.0
            }
        
        protocol_counts = Counter()
        for flow in flows:
            protocol = flow.get('protocol', 'UNKNOWN')
            protocol_counts[protocol] += 1
        
        tcp_ratio = protocol_counts.get('TCP', 0) / total_flows
        udp_ratio = protocol_counts.get('UDP', 0) / total_flows
        
        # Protocol diversity (normalized entropy)
        diversity = 0.0
        for count in protocol_counts.values():
            if count > 0:
                prob = count / total_flows
                diversity -= prob * math.log2(prob)
        
        # Normalize
        n_protocols = len(protocol_counts)
        if n_protocols > 1:
            diversity = diversity / math.log2(n_protocols)
        
        return {
            'tcp_ratio': float(tcp_ratio),
            'udp_ratio': float(udp_ratio),
            'protocol_diversity': float(diversity)
        }
    
    def _calc_temporal_features(self, flows: List[Dict], device_mac: str) -> Dict[str, float]:
        """Calculate temporal behavior features."""
        # High port ratio (ports > 1024)
        high_ports = 0
        total_ports = 0
        
        # Night activity (00:00 - 06:00)
        night_flows = 0
        total_flows = 0
        
        # Connection timestamps for burst detection
        timestamps = []
        
        for flow in flows:
            if flow.get('src_mac') == device_mac:
                # Port analysis
                dst_port = flow.get('dst_port', 0)
                if dst_port > 0:
                    total_ports += 1
                    if dst_port > 1024:
                        high_ports += 1
                
                # Time analysis
                try:
                    if isinstance(flow.get('timestamp'), str):
                        flow_time = datetime.fromisoformat(flow['timestamp'].replace('Z', '+00:00'))
                    else:
                        flow_time = flow.get('timestamp', datetime.utcnow())
                    
                    timestamps.append(flow_time)
                    hour = flow_time.hour
                    
                    total_flows += 1
                    if 0 <= hour < 6:  # Night hours
                        night_flows += 1
                except:
                    pass
        
        high_port_ratio = high_ports / total_ports if total_ports > 0 else 0.0
        night_activity_ratio = night_flows / total_flows if total_flows > 0 else 0.0
        
        # Calculate burst score (connections in short time)
        burst_score = self._calc_burst_score(timestamps)
        
        # Connection rate (connections per minute)
        if timestamps:
            duration = (max(timestamps) - min(timestamps)).total_seconds() / 60
            connection_rate = len(timestamps) / max(duration, 1)
        else:
            connection_rate = 0.0
        
        return {
            'high_port_ratio': float(high_port_ratio),
            'night_activity_ratio': float(night_activity_ratio),
            'burst_score': float(burst_score),
            'connection_rate': float(connection_rate)
        }
    
    def _calc_burst_score(self, timestamps: List[datetime]) -> float:
        """Calculate burst score based on connection timing."""
        if len(timestamps) < 2:
            return 0.0
        
        # Sort timestamps
        timestamps = sorted(timestamps)
        
        # Calculate inter-arrival times
        deltas = []
        for i in range(1, len(timestamps)):
            delta = (timestamps[i] - timestamps[i-1]).total_seconds()
            deltas.append(delta)
        
        if not deltas:
            return 0.0
        
        # Burst score: inverse of average inter-arrival time
        avg_delta = np.mean(deltas)
        if avg_delta > 0:
            # Normalize to 0-1 range (1 second = score of 1)
            burst_score = min(1.0, 1.0 / avg_delta)
        else:
            burst_score = 1.0
        
        return burst_score
    
    def _calc_behavioral_scores(self, flows: List[Dict], device_mac: str) -> Dict[str, float]:
        """Calculate behavioral anomaly scores."""
        failed_connections = 0
        total_connections = 0
        
        # Data exfiltration indicators
        large_uploads = 0
        upload_bytes = 0
        
        # Scanning behavior
        unique_dst_ports = set()
        dst_ip_port_pairs = set()
        
        for flow in flows:
            if flow.get('src_mac') == device_mac:
                total_connections += 1
                
                # Check for failed connections (simplified - no response)
                if flow.get('packets_total', 0) <= 2:
                    failed_connections += 1
                
                # Data exfiltration check
                bytes_out = flow.get('bytes_total', 0)
                upload_bytes += bytes_out
                if bytes_out > 1048576:  # > 1MB
                    large_uploads += 1
                
                # Scanning behavior
                dst_ip = flow.get('dst_ip')
                dst_port = flow.get('dst_port')
                if dst_ip and dst_port:
                    unique_dst_ports.add(dst_port)
                    dst_ip_port_pairs.add((dst_ip, dst_port))
        
        # Calculate scores
        failed_conn_ratio = failed_connections / total_connections if total_connections > 0 else 0.0
        
        # Data exfiltration score (based on large uploads)
        data_exfil_score = min(1.0, large_uploads / 10.0)  # Normalize to 0-1
        
        # Scan behavior score (many ports, few IPs = scanning)
        if len(unique_dst_ports) > 0:
            scan_behavior_score = len(unique_dst_ports) / max(len(set(f.get('dst_ip') for f in flows if f.get('dst_ip'))), 1)
            scan_behavior_score = min(1.0, scan_behavior_score / 10.0)  # Normalize
        else:
            scan_behavior_score = 0.0
        
        # Temporal consistency (how regular is the traffic pattern)
        temporal_consistency = self._calc_temporal_consistency(flows, device_mac)
        
        return {
            'failed_conn_ratio': float(failed_conn_ratio),
            'data_exfil_score': float(data_exfil_score),
            'scan_behavior_score': float(scan_behavior_score),
            'temporal_consistency': float(temporal_consistency)
        }
    
    def _calc_temporal_consistency(self, flows: List[Dict], device_mac: str) -> float:
        """Calculate temporal consistency of traffic pattern."""
        # Get hourly distribution
        hourly_counts = defaultdict(int)
        
        for flow in flows:
            if flow.get('src_mac') == device_mac:
                try:
                    if isinstance(flow.get('timestamp'), str):
                        flow_time = datetime.fromisoformat(flow['timestamp'].replace('Z', '+00:00'))
                    else:
                        flow_time = flow.get('timestamp', datetime.utcnow())
                    
                    hour = flow_time.hour
                    hourly_counts[hour] += 1
                except:
                    pass
        
        if not hourly_counts:
            return 0.0
        
        # Calculate coefficient of variation (lower = more consistent)
        counts = list(hourly_counts.values())
        if len(counts) < 2:
            return 1.0  # Single hour = very consistent
        
        mean_count = np.mean(counts)
        std_count = np.std(counts)
        
        if mean_count > 0:
            cv = std_count / mean_count
            # Invert and normalize (high consistency = low CV)
            consistency = max(0.0, 1.0 - cv)
        else:
            consistency = 0.0
        
        return consistency
    
    def _update_history(self, device_mac: str, flows: List[Dict]):
        """Update historical data for device."""
        history = self.history[device_mac]
        history['flows'].extend(flows)
        history['last_update'] = datetime.utcnow()
        
        # Keep only recent history (last hour)
        cutoff = datetime.utcnow() - timedelta(hours=1)
        history['flows'] = [
            f for f in history['flows']
            if self._parse_timestamp(f.get('timestamp')) >= cutoff
        ]
    
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
    
    def get_feature_vector(self, features: Dict[str, float]) -> np.ndarray:
        """Convert feature dictionary to numpy array.
        
        Args:
            features: Dictionary of feature values
            
        Returns:
            Numpy array of features in consistent order
        """
        vector = []
        for name in self.feature_names:
            value = features.get(name, 0.0)
            # Handle any non-numeric values
            if isinstance(value, (int, float)):
                vector.append(float(value))
            else:
                vector.append(0.0)
        
        return np.array(vector, dtype=np.float32)
