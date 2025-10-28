"""Security utilities for Home Net Guardian."""

import hashlib
import hmac
import secrets
from typing import Optional
from datetime import datetime, timedelta
import re
from ipaddress import ip_address, ip_network, IPv4Address, IPv6Address


class SecurityUtils:
    """Security-related utilities."""
    
    @staticmethod
    def is_private_ip(ip: str) -> bool:
        """Check if IP address is private (RFC1918)."""
        try:
            addr = ip_address(ip)
            return addr.is_private or addr.is_loopback
        except ValueError:
            return False
    
    @staticmethod
    def is_multicast_ip(ip: str) -> bool:
        """Check if IP address is multicast."""
        try:
            addr = ip_address(ip)
            return addr.is_multicast
        except ValueError:
            return False
    
    @staticmethod
    def is_valid_mac(mac: str) -> bool:
        """Validate MAC address format."""
        pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
        return bool(re.match(pattern, mac))
    
    @staticmethod
    def normalize_mac(mac: str) -> str:
        """Normalize MAC address to lowercase with colons."""
        if not mac:
            return ""
        # Remove any separators and convert to lowercase
        clean_mac = re.sub(r'[:-]', '', mac.lower())
        # Add colons every 2 characters
        return ':'.join(clean_mac[i:i+2] for i in range(0, 12, 2))
    
    @staticmethod
    def hash_ip(ip: str, salt: str = "") -> str:
        """Hash IP address for privacy."""
        return hashlib.sha256(f"{ip}{salt}".encode()).hexdigest()[:16]
    
    @staticmethod
    def is_suspicious_port(port: int, high_risk_ports: list) -> bool:
        """Check if port is in high-risk list."""
        return port in high_risk_ports
    
    @staticmethod
    def is_dns_tunneling_suspect(domain: str) -> bool:
        """Check if domain looks like DNS tunneling."""
        if not domain:
            return False
        
        # Check for excessive subdomain depth
        parts = domain.split('.')
        if len(parts) > 5:
            return True
        
        # Check for high entropy in subdomain
        if parts and len(parts[0]) > 32:
            # Long random-looking subdomain
            entropy = SecurityUtils.calculate_entropy(parts[0])
            if entropy > 4.0:  # High entropy threshold
                return True
        
        # Check for base64-like patterns
        if re.search(r'[A-Za-z0-9+/]{20,}={0,2}', domain):
            return True
        
        return False
    
    @staticmethod
    def calculate_entropy(s: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not s:
            return 0.0
        
        # Count character frequencies
        freq = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        length = len(s)
        for count in freq.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * (probability and (probability * 2).bit_length() - 1)
        
        return entropy
    
    @staticmethod
    def is_suspicious_sni(sni: str, common_snis: set) -> bool:
        """Check if SNI is suspicious (rare or malformed)."""
        if not sni:
            return False
        
        # Check if it's a rare SNI
        if sni not in common_snis and not sni.endswith(('.com', '.org', '.net', '.io')):
            return True
        
        # Check for IP address as SNI (suspicious)
        try:
            ip_address(sni)
            return True
        except ValueError:
            pass
        
        # Check for excessive dots or suspicious patterns
        if sni.count('.') > 4 or re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', sni):
            return True
        
        return False
    
    @staticmethod
    def sanitize_input(value: str, max_length: int = 1000) -> str:
        """Sanitize user input to prevent injection attacks."""
        if not value:
            return ""
        
        # Truncate to max length
        value = value[:max_length]
        
        # Remove null bytes
        value = value.replace('\x00', '')
        
        # Remove control characters except newlines and tabs
        value = re.sub(r'[\x01-\x08\x0B-\x0C\x0E-\x1F\x7F]', '', value)
        
        return value.strip()
    
    @staticmethod
    def generate_token() -> str:
        """Generate a secure random token."""
        return secrets.token_urlsafe(32)
    
    @staticmethod
    def verify_token(token: str, expected: str) -> bool:
        """Securely compare tokens."""
        return secrets.compare_digest(token, expected)


class RateLimiter:
    """Simple in-memory rate limiter."""
    
    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        """Initialize rate limiter.
        
        Args:
            max_requests: Maximum requests allowed in window
            window_seconds: Time window in seconds
        """
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = {}  # IP -> list of timestamps
    
    def is_allowed(self, identifier: str) -> bool:
        """Check if request is allowed for given identifier."""
        now = datetime.now()
        window_start = now - timedelta(seconds=self.window_seconds)
        
        # Clean old requests
        if identifier in self.requests:
            self.requests[identifier] = [
                ts for ts in self.requests[identifier]
                if ts > window_start
            ]
        else:
            self.requests[identifier] = []
        
        # Check if under limit
        if len(self.requests[identifier]) < self.max_requests:
            self.requests[identifier].append(now)
            return True
        
        return False
    
    def reset(self, identifier: Optional[str] = None):
        """Reset rate limit for identifier or all."""
        if identifier:
            self.requests.pop(identifier, None)
        else:
            self.requests.clear()
