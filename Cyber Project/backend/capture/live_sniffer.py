"""Live packet capture module using Scapy."""

import asyncio
import logging
from typing import Dict, List, Optional, Callable, Any
from datetime import datetime, timedelta
from collections import defaultdict
import threading
import queue

from scapy.all import (
    sniff, Ether, IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR, DNSRR,
    Raw, get_if_list, get_if_hwaddr, conf
)
try:
    from scapy.layers.http import HTTPRequest, HTTPResponse
except ImportError:
    HTTPRequest = None
    HTTPResponse = None

try:
    from scapy.layers.tls.record import TLS
    from scapy.layers.tls.extensions import TLS_Ext_ServerName
except ImportError:
    TLS = None
    TLS_Ext_ServerName = None

from core.config import settings
from core.security import SecurityUtils
from db.models import Flow, Device
from capture.device_fingerprint import DeviceFingerprinter

logger = logging.getLogger(__name__)


class PacketProcessor:
    """Process captured packets into flows and events."""
    
    def __init__(self, callback: Optional[Callable] = None):
        """Initialize packet processor.
        
        Args:
            callback: Async callback function to handle processed data
        """
        self.callback = callback
        self.flows = defaultdict(lambda: {
            'packets': 0,
            'bytes': 0,
            'start_time': None,
            'last_time': None,
            'dns_queries': [],
            'sni': None,
            'src_mac': None,
            'dst_mac': None
        })
        self.devices = {}
        self.fingerprinter = DeviceFingerprinter()
        self.last_flush = datetime.utcnow()
        self.flow_window = timedelta(seconds=settings.flow_window_seconds)
        self.flush_scheduled = False
        
    def process_packet(self, packet) -> Optional[Dict[str, Any]]:
        """Process a single packet.
        
        Args:
            packet: Scapy packet object
            
        Returns:
            Processed packet data or None
        """
        try:
            # Skip non-Ethernet packets
            if not packet.haslayer(Ether):
                return None
            
            eth = packet[Ether]
            src_mac = SecurityUtils.normalize_mac(eth.src)
            dst_mac = SecurityUtils.normalize_mac(eth.dst)
            
            # Update device info
            self._update_device(src_mac, packet)
            
            # Process IP layer
            if packet.haslayer(IP):
                ip = packet[IP]
                src_ip = ip.src
                dst_ip = ip.dst
                protocol = ip.proto
            elif packet.haslayer(IPv6):
                ip = packet[IPv6]
                src_ip = ip.src
                dst_ip = ip.dst
                protocol = ip.nh
            else:
                return None
            
            # Get ports and protocol name
            src_port = 0
            dst_port = 0
            proto_name = "OTHER"
            
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                src_port = tcp.sport
                dst_port = tcp.dport
                proto_name = "TCP"
            elif packet.haslayer(UDP):
                udp = packet[UDP]
                src_port = udp.sport
                dst_port = udp.dport
                proto_name = "UDP"
            elif packet.haslayer(ICMP):
                proto_name = "ICMP"
            
            # Create flow key
            flow_key = self._get_flow_key(src_ip, dst_ip, src_port, dst_port, protocol)
            
            # Update flow
            now = datetime.utcnow()
            flow = self.flows[flow_key]
            
            if flow['start_time'] is None:
                flow['start_time'] = now
                flow['src_mac'] = src_mac
                flow['dst_mac'] = dst_mac
            
            flow['last_time'] = now
            flow['packets'] += 1
            flow['bytes'] += len(packet)
            
            # Extract application layer data
            self._extract_app_data(packet, flow)
            
            # Check if we should flush flows
            if now - self.last_flush > self.flow_window:
                # Schedule flush for next event loop iteration
                self._schedule_flush()
            
            return {
                'timestamp': now.isoformat(),
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'protocol': proto_name,
                'size': len(packet),
                'src_mac': src_mac,
                'dst_mac': dst_mac
            }
            
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
            return None
    
    def _get_flow_key(self, src_ip: str, dst_ip: str, src_port: int,
                      dst_port: int, protocol: int) -> str:
        """Generate flow key for aggregation."""
        # Sort IPs and ports to create bidirectional flow key
        if src_ip < dst_ip:
            return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
        else:
            return f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"
    
    def _update_device(self, mac: str, packet):
        """Update device information from packet."""
        if mac not in self.devices:
            self.devices[mac] = {
                'mac': mac,
                'vendor': self.fingerprinter.get_vendor(mac),
                'first_seen': datetime.utcnow(),
                'last_seen': datetime.utcnow(),
                'ips': set(),
                'ports': defaultdict(int),
                'protocols': defaultdict(int),
                'dns_queries': set()
            }
        
        device = self.devices[mac]
        device['last_seen'] = datetime.utcnow()
        
        # Extract IP if present
        if packet.haslayer(IP):
            device['ips'].add(packet[IP].src)
        elif packet.haslayer(IPv6):
            device['ips'].add(packet[IPv6].src)
        
        # Track ports and protocols
        if packet.haslayer(TCP):
            device['ports'][packet[TCP].sport] += 1
            device['protocols']['TCP'] += 1
        elif packet.haslayer(UDP):
            device['ports'][packet[UDP].sport] += 1
            device['protocols']['UDP'] += 1
    
    def _extract_app_data(self, packet, flow: dict):
        """Extract application layer data from packet."""
        # DNS
        if packet.haslayer(DNS):
            dns = packet[DNS]
            if dns.qr == 0:  # Query
                for i in range(dns.qdcount):
                    try:
                        qname = dns.qd[i].qname.decode('utf-8').rstrip('.')
                        flow['dns_queries'].append(qname)
                        
                        # Update device DNS queries
                        if flow['src_mac'] in self.devices:
                            self.devices[flow['src_mac']]['dns_queries'].add(qname)
                    except:
                        pass
        
        # TLS SNI
        if packet.haslayer(TLS):
            try:
                for ext in packet[TLS].msg:
                    if hasattr(ext, 'ext') and isinstance(ext.ext, TLS_Ext_ServerName):
                        for sni in ext.ext.servernames:
                            if sni.servername:
                                flow['sni'] = sni.servername.decode('utf-8')
                                break
            except:
                pass
        
        # HTTP (if not encrypted)
        if packet.haslayer(HTTPRequest):
            try:
                http = packet[HTTPRequest]
                flow['http_method'] = http.Method.decode('utf-8') if http.Method else None
                flow['http_host'] = http.Host.decode('utf-8') if http.Host else None
                flow['http_path'] = http.Path.decode('utf-8') if http.Path else None
            except:
                pass
    
    def _schedule_flush(self):
        """Schedule async flush in a thread-safe way."""
        if not self.flush_scheduled and self.callback:
            self.flush_scheduled = True
            # Use threading to handle the async callback
            import threading
            threading.Thread(target=self._async_flush_wrapper, daemon=True).start()
    
    def _async_flush_wrapper(self):
        """Wrapper to run async flush in new event loop."""
        try:
            import asyncio
            # Create new event loop for this thread
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(self._flush_flows())
            loop.close()
        except Exception as e:
            logger.error(f"Error in async flush wrapper: {e}")
        finally:
            self.flush_scheduled = False
    
    async def _flush_flows(self, force_all: bool = False):
        """Flush aggregated flows to callback.
        
        Args:
            force_all: If True, flush all flows regardless of age (for PCAP end-of-file)
        """
        now = datetime.utcnow()
        flows_to_flush = []
        
        # Find flows to flush
        keys_to_remove = []
        for key, flow in self.flows.items():
            # Flush if old OR if force_all is True
            should_flush = force_all or (flow['last_time'] and (now - flow['last_time'] > self.flow_window))
            
            if should_flush and flow['start_time'] and flow['last_time']:
                # Parse flow key
                parts = key.rsplit('-', 1)
                if len(parts) == 2:
                    endpoints, protocol = parts
                    ips_ports = endpoints.split('-')
                    if len(ips_ports) == 2:
                        src = ips_ports[0].rsplit(':', 1)
                        dst = ips_ports[1].rsplit(':', 1)
                        
                        if len(src) == 2 and len(dst) == 2:
                            flow_data = {
                                'timestamp': flow['start_time'].isoformat(),
                                'src_ip': src[0],
                                'dst_ip': dst[0],
                                'src_port': int(src[1]),
                                'dst_port': int(dst[1]),
                                'protocol': self._proto_num_to_name(int(protocol)),
                                'bytes_total': flow['bytes'],
                                'packets_total': flow['packets'],
                                'duration': (flow['last_time'] - flow['start_time']).total_seconds(),
                                'src_mac': flow.get('src_mac'),
                                'dst_mac': flow.get('dst_mac'),
                                'dns_queries': flow.get('dns_queries', []),
                                'sni': flow.get('sni'),
                                'is_external': not SecurityUtils.is_private_ip(dst[0])
                            }
                            flows_to_flush.append(flow_data)
                            keys_to_remove.append(key)
        
        # Remove flushed flows
        for key in keys_to_remove:
            del self.flows[key]
        
        self.last_flush = now
        
        # Send to callback
        if self.callback and flows_to_flush:
            await self.callback({
                'type': 'flows',
                'data': flows_to_flush,
                'devices': list(self.devices.values())
            })
    
    def _proto_num_to_name(self, proto: int) -> str:
        """Convert protocol number to name."""
        proto_map = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP',
            41: 'IPv6',
            47: 'GRE',
            50: 'ESP',
            51: 'AH',
            58: 'ICMPv6',
            89: 'OSPF',
            132: 'SCTP'
        }
        return proto_map.get(proto, f'PROTO_{proto}')


class LiveSniffer:
    """Live packet capture using Scapy."""
    
    def __init__(self, interface: str, callback: Optional[Callable] = None):
        """Initialize live sniffer.
        
        Args:
            interface: Network interface to capture from
            callback: Async callback for processed data
        """
        self.interface = interface
        self.processor = PacketProcessor(callback)
        self.is_running = False
        self.packet_queue = queue.Queue(maxsize=10000)
        self.sniffer_thread = None
        self.processor_thread = None
        
        # Validate and select interface
        available_interfaces = get_if_list()
        if interface not in available_interfaces:
            logger.warning(f"Interface {interface} not found. Available: {available_interfaces}")
            # Try to find a suitable interface
            suitable_interfaces = [iface for iface in available_interfaces 
                                 if iface not in ['lo', 'Loopback']]
            if suitable_interfaces:
                self.interface = suitable_interfaces[0]
                logger.info(f"Using alternative interface: {self.interface}")
            else:
                # Fall back to first available interface
                self.interface = available_interfaces[0] if available_interfaces else 'eth0'
                logger.warning(f"Using fallback interface: {self.interface}")
        else:
            self.interface = interface
        
        # Configure Scapy
        conf.verbose = 0
        conf.sniff_promisc = True
        
    def start(self):
        """Start packet capture."""
        if self.is_running:
            logger.warning("Sniffer already running")
            return
        
        self.is_running = True
        
        # Start sniffer thread
        self.sniffer_thread = threading.Thread(
            target=self._sniff_packets,
            daemon=True
        )
        self.sniffer_thread.start()
        
        # Start processor thread
        self.processor_thread = threading.Thread(
            target=self._process_packets,
            daemon=True
        )
        self.processor_thread.start()
        
        logger.info(f"Started live capture on interface {self.interface}")
    
    def stop(self):
        """Stop packet capture."""
        self.is_running = False
        
        if self.sniffer_thread:
            self.sniffer_thread.join(timeout=5)
        if self.processor_thread:
            self.processor_thread.join(timeout=5)
        
        logger.info("Stopped live capture")
    
    def _sniff_packets(self):
        """Sniff packets in a separate thread."""
        try:
            sniff(
                iface=self.interface,
                prn=self._packet_handler,
                store=False,
                stop_filter=lambda x: not self.is_running
            )
        except PermissionError:
            logger.error("Permission denied. Try running with sudo or setting capabilities:")
            logger.error("sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)")
        except Exception as e:
            logger.error(f"Sniffing error: {e}")
    
    def _packet_handler(self, packet):
        """Handle captured packet."""
        try:
            # Add to queue for processing
            if not self.packet_queue.full():
                self.packet_queue.put(packet, block=False)
        except queue.Full:
            logger.warning("Packet queue full, dropping packet")
    
    def _process_packets(self):
        """Process packets from queue."""
        while self.is_running:
            try:
                packet = self.packet_queue.get(timeout=1)
                self.processor.process_packet(packet)
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Packet processing error: {e}")
    
    def get_stats(self) -> dict:
        """Get capture statistics."""
        return {
            'interface': self.interface,
            'is_running': self.is_running,
            'queue_size': self.packet_queue.qsize(),
            'devices_discovered': len(self.processor.devices),
            'active_flows': len(self.processor.flows)
        }
