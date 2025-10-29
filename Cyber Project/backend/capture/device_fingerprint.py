"""Device fingerprinting and vendor identification."""

import re
import logging
from typing import Dict, Optional, List, Set
from pathlib import Path
from collections import defaultdict
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class DeviceFingerprinter:
    """Fingerprint devices based on MAC address and behavior."""
    
    def __init__(self, oui_file: Optional[str] = None):
        """Initialize device fingerprinter.
        
        Args:
            oui_file: Path to OUI database file
        """
        self.oui_db = {}
        self.device_profiles = {}
        self.common_services = self._load_common_services()
        
        # Load OUI database
        if oui_file and Path(oui_file).exists():
            self._load_oui_file(oui_file)
        else:
            self._load_default_oui()
    
    def _load_default_oui(self):
        """Load minimal default OUI database."""
        # Common vendor OUIs
        self.oui_db = {
            '00:00:5e': 'IANA (Multicast)',
            '00:01:5c': 'Cisco Systems',
            '00:04:4b': 'NVIDIA',
            '00:05:69': 'VMware',
            '00:0c:29': 'VMware',
            '00:0d:b9': 'PC Engines GmbH',
            '00:11:32': 'Synology',
            '00:15:5d': 'Microsoft (Hyper-V)',
            '00:1b:21': 'Intel',
            '00:1c:42': 'Parallels',
            '00:24:9b': 'Action Star',
            '00:25:90': 'Super Micro',
            '00:50:56': 'VMware',
            '00:e0:4c': 'Realtek',
            '08:00:27': 'Oracle VirtualBox',
            '0c:29:ef': 'VMware',
            '18:03:73': 'Dell',
            '20:47:47': 'Dell',
            '24:6e:96': 'Dell',
            '28:d2:44': 'Google',
            '2c:44:fd': 'Amazon',
            '30:9c:23': 'Micro-Star',
            '34:17:eb': 'Dell',
            '38:21:87': 'Midea Group',
            '3c:37:86': 'Amazon',
            '44:07:0b': 'Google',
            '48:4d:7e': 'Dell',
            '4c:ed:fb': 'ASUS',
            '50:9a:4c': 'Amazon',
            '52:54:00': 'QEMU/KVM',
            '54:52:00': 'Linux KVM',
            '58:9c:fc': 'Amazon',
            '5c:cf:7f': 'Espressif (ESP32)',
            '60:01:94': 'Espressif',
            '64:16:66': 'Amazon Ring',
            '68:54:f5': 'Amazon',
            '68:72:dc': 'Amazon',
            '6c:ad:f8': 'Azurewave',
            '70:85:c2': 'Realtek',
            '74:c6:3b': 'Amazon',
            '78:2b:cb': 'Dell',
            '7c:78:b2': 'Amazon',
            '80:2a:a8': 'Ubiquiti',
            '84:16:f9': 'TP-Link',
            '84:f3:eb': 'Amazon',
            '88:71:e5': 'Amazon',
            '8c:aa:b5': 'Amazon',
            '90:84:2b': 'Amazon',
            '94:b8:6d': 'Intel',
            '98:da:c4': 'Microsoft',
            'a0:62:fb': 'Amazon',
            'a4:08:ea': 'Amazon',
            'a4:b1:c1': 'Amazon',
            'a8:42:e3': 'Amazon',
            'ac:63:be': 'Amazon',
            'ac:84:c6': 'TP-Link',
            'b0:72:bf': 'Roku',
            'b0:a7:b9': 'TP-Link',
            'b4:7a:f1': 'Amazon',
            'b8:27:eb': 'Raspberry Pi',
            'b8:7c:6f': 'Amazon',
            'bc:14:01': 'Google Nest',
            'c0:06:c3': 'TP-Link',
            'c0:25:e9': 'TP-Link',
            'c4:41:1e': 'Amazon',
            'cc:9e:00': 'Amazon',
            'd0:03:4b': 'Apple',
            'd4:81:d7': 'Amazon',
            'd8:bb:c1': 'Google',
            'd8:f1:5b': 'Amazon',
            'dc:2c:6e': 'Raspberry Pi',
            'dc:a6:32': 'Raspberry Pi',
            'e0:63:da': 'Ubiquiti',
            'e4:5f:01': 'Raspberry Pi',
            'e8:78:29': 'Amazon',
            'e8:9f:80': 'Belkin',
            'ec:71:db': 'Amazon Ring',
            'ec:f4:bb': 'Dell',
            'f0:18:98': 'Apple',
            'f0:27:2d': 'Amazon',
            'f0:81:73': 'Amazon',
            'f4:b8:5e': 'Amazon',
            'f4:f5:d8': 'Google',
            'fc:65:de': 'Amazon',
            'fc:a1:83': 'Amazon'
        }
    
    def _load_oui_file(self, oui_file: str):
        """Load OUI database from file.
        
        File format: MAC_PREFIX<tab>VENDOR_NAME
        """
        try:
            with open(oui_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        parts = line.split('\t', 1)
                        if len(parts) == 2:
                            mac_prefix = parts[0].lower()
                            vendor = parts[1]
                            self.oui_db[mac_prefix] = vendor
            
            logger.info(f"Loaded {len(self.oui_db)} OUI entries")
        except Exception as e:
            logger.error(f"Error loading OUI file: {e}")
            self._load_default_oui()
    
    def _load_common_services(self) -> Dict[int, str]:
        """Load common network services by port."""
        return {
            20: 'FTP-DATA',
            21: 'FTP',
            22: 'SSH',
            23: 'TELNET',
            25: 'SMTP',
            53: 'DNS',
            67: 'DHCP',
            68: 'DHCP',
            80: 'HTTP',
            110: 'POP3',
            123: 'NTP',
            135: 'RPC',
            137: 'NETBIOS',
            138: 'NETBIOS',
            139: 'NETBIOS',
            143: 'IMAP',
            161: 'SNMP',
            443: 'HTTPS',
            445: 'SMB',
            465: 'SMTPS',
            514: 'SYSLOG',
            515: 'PRINTER',
            548: 'AFP',
            554: 'RTSP',
            587: 'SMTP',
            631: 'IPP',
            853: 'DNS-TLS',
            993: 'IMAPS',
            995: 'POP3S',
            1433: 'MSSQL',
            1434: 'MSSQL',
            1521: 'ORACLE',
            1723: 'PPTP',
            1883: 'MQTT',
            1900: 'UPNP',
            2323: 'TELNET-ALT',
            3306: 'MYSQL',
            3389: 'RDP',
            5000: 'UPNP',
            5353: 'MDNS',
            5432: 'POSTGRES',
            5900: 'VNC',
            6379: 'REDIS',
            7547: 'CWMP',
            8000: 'HTTP-ALT',
            8080: 'HTTP-PROXY',
            8443: 'HTTPS-ALT',
            8883: 'MQTT-TLS',
            8888: 'HTTP-ALT',
            9200: 'ELASTICSEARCH',
            10000: 'WEBMIN',
            27017: 'MONGODB'
        }
    
    def get_vendor(self, mac: str) -> Optional[str]:
        """Get vendor name from MAC address.
        
        Args:
            mac: MAC address
            
        Returns:
            Vendor name or None
        """
        if not mac:
            return None
        
        # Normalize MAC
        mac_clean = mac.lower().replace(':', '').replace('-', '')
        
        # Check first 6 characters (3 bytes) for OUI
        if len(mac_clean) >= 6:
            oui = f"{mac_clean[0:2]}:{mac_clean[2:4]}:{mac_clean[4:6]}"
            vendor = self.oui_db.get(oui)
            if vendor:
                return vendor
        
        # Check if it's a locally administered address
        if len(mac_clean) >= 2:
            first_byte = int(mac_clean[0:2], 16)
            if first_byte & 0x02:  # Locally administered bit
                return "Locally Administered"
        
        return None
    
    def fingerprint_device(self, mac: str, traffic_stats: Dict) -> Dict[str, any]:
        """Fingerprint a device based on MAC and traffic patterns.
        
        Args:
            mac: Device MAC address
            traffic_stats: Traffic statistics for the device
            
        Returns:
            Device profile with role and characteristics
        """
        profile = {
            'mac': mac,
            'vendor': self.get_vendor(mac),
            'role': 'Unknown',
            'confidence': 0.0,
            'characteristics': [],
            'risk_factors': []
        }
        
        # Analyze traffic patterns
        if traffic_stats:
            profile.update(self._analyze_traffic_patterns(traffic_stats))
        
        # Guess device role based on vendor and patterns
        profile['role'] = self._guess_device_role(profile)
        
        return profile
    
    def _analyze_traffic_patterns(self, stats: Dict) -> Dict:
        """Analyze traffic patterns to identify device characteristics.
        
        Args:
            stats: Traffic statistics
            
        Returns:
            Analysis results
        """
        characteristics = []
        risk_factors = []
        
        # Check port usage
        ports = stats.get('ports', {})
        protocols = stats.get('protocols', {})
        dns_queries = stats.get('dns_queries', set())
        
        # IoT device indicators
        if 1883 in ports or 8883 in ports:  # MQTT
            characteristics.append('Uses MQTT (IoT)')
        
        if 5353 in ports:  # mDNS
            characteristics.append('Uses mDNS (local discovery)')
        
        if 1900 in ports or 5000 in ports:  # UPnP
            characteristics.append('Uses UPnP')
        
        if 554 in ports:  # RTSP
            characteristics.append('Streams video (RTSP)')
        
        # Security concerns
        if 23 in ports or 2323 in ports:  # Telnet
            risk_factors.append('Uses insecure Telnet')
        
        if 21 in ports:  # FTP
            risk_factors.append('Uses insecure FTP')
        
        if 445 in ports or 139 in ports:  # SMB
            risk_factors.append('Exposes SMB/NetBIOS')
        
        # Check DNS patterns
        if len(dns_queries) > 100:
            characteristics.append('High DNS activity')
            
            # Check for suspicious patterns
            suspicious_domains = [d for d in dns_queries if self._is_suspicious_domain(d)]
            if suspicious_domains:
                risk_factors.append(f'Queries suspicious domains: {len(suspicious_domains)}')
        
        # Protocol analysis
        tcp_count = protocols.get('TCP', 0)
        udp_count = protocols.get('UDP', 0)
        
        if udp_count > tcp_count * 2:
            characteristics.append('UDP-heavy (streaming/gaming)')
        
        return {
            'characteristics': characteristics,
            'risk_factors': risk_factors
        }
    
    def _guess_device_role(self, profile: Dict) -> str:
        """Guess device role based on profile.
        
        Args:
            profile: Device profile
            
        Returns:
            Guessed role
        """
        vendor = profile.get('vendor', '').lower()
        characteristics = profile.get('characteristics', [])
        
        # Check vendor-based roles
        if vendor:
            if 'amazon' in vendor:
                if 'ring' in vendor:
                    return 'Security Camera'
                else:
                    return 'Smart Speaker'
            elif 'google' in vendor:
                if 'nest' in vendor:
                    return 'Smart Home'
                else:
                    return 'Streaming Device'
            elif 'apple' in vendor:
                return 'Apple Device'
            elif 'raspberry' in vendor:
                return 'Raspberry Pi'
            elif 'roku' in vendor:
                return 'Streaming Device'
            elif 'tp-link' in vendor or 'ubiquiti' in vendor:
                return 'Network Equipment'
            elif 'dell' in vendor or 'hp' in vendor or 'lenovo' in vendor:
                return 'Computer'
            elif 'samsung' in vendor or 'lg' in vendor:
                return 'Smart TV'
            elif 'espressif' in vendor:
                return 'IoT Device'
        
        # Check characteristics-based roles
        for char in characteristics:
            if 'MQTT' in char:
                return 'IoT Device'
            elif 'RTSP' in char:
                return 'IP Camera'
            elif 'streaming' in char.lower():
                return 'Streaming Device'
            elif 'gaming' in char.lower():
                return 'Gaming Console'
        
        # Default roles based on patterns
        if 'Uses UPnP' in characteristics:
            return 'Media Device'
        
        return 'Unknown Device'
    
    def _is_suspicious_domain(self, domain: str) -> bool:
        """Check if domain appears suspicious.
        
        Args:
            domain: Domain name
            
        Returns:
            True if suspicious
        """
        # Check for DGA-like patterns
        if len(domain) > 20 and domain.count('.') == 1:
            # Long single-level domain
            return True
        
        # Check for excessive subdomains
        if domain.count('.') > 4:
            return True
        
        # Check for IP addresses as domains
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
            return True
        
        # Known suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.click', '.download']
        for tld in suspicious_tlds:
            if domain.endswith(tld):
                return True
        
        return False
    
    def identify_device_category(self, vendor: str, ports: List[int]) -> str:
        """Identify broad device category.
        
        Args:
            vendor: Vendor name
            ports: List of ports device uses
            
        Returns:
            Device category
        """
        if not vendor:
            vendor = ""
        
        vendor_lower = vendor.lower()
        
        # Vendor-based categorization
        categories = {
            'IoT': ['espressif', 'tuya', 'sonoff', 'shelly', 'tasmota'],
            'Camera': ['hikvision', 'dahua', 'axis', 'foscam', 'amcrest', 'ring', 'arlo', 'wyze'],
            'Network': ['cisco', 'juniper', 'ubiquiti', 'tp-link', 'netgear', 'asus', 'mikrotik'],
            'Smart Home': ['nest', 'ecobee', 'philips', 'lutron', 'wemo', 'kasa'],
            'Streaming': ['roku', 'chromecast', 'fire tv', 'apple tv'],
            'Computer': ['dell', 'hp', 'lenovo', 'apple', 'microsoft', 'intel'],
            'Mobile': ['samsung', 'apple', 'google', 'oneplus', 'xiaomi'],
            'Printer': ['hp', 'epson', 'canon', 'brother', 'xerox']
        }
        
        for category, keywords in categories.items():
            if any(kw in vendor_lower for kw in keywords):
                return category
        
        # Port-based categorization if vendor unknown
        if 554 in ports or 8554 in ports:  # RTSP
            return 'Camera'
        elif 515 in ports or 631 in ports:  # Printing
            return 'Printer'
        elif 1883 in ports or 8883 in ports:  # MQTT
            return 'IoT'
        elif 3389 in ports:  # RDP
            return 'Computer'
        
        return 'Unknown'
