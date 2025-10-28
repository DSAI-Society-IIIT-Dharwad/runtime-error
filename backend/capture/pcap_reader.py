"""PCAP file reader for offline packet analysis."""

import asyncio
import logging
from typing import Optional, Callable, List, Dict, Any
from pathlib import Path
from datetime import datetime, timedelta

from scapy.all import rdpcap, PcapReader, Ether, IP, IPv6, TCP, UDP, ICMP, DNS
from scapy.utils import PcapWriter

from capture.live_sniffer import PacketProcessor
from core.config import settings

logger = logging.getLogger(__name__)


class PcapFileReader:
    """Read and process PCAP files."""
    
    def __init__(self, pcap_path: str, callback: Optional[Callable] = None):
        """Initialize PCAP reader.
        
        Args:
            pcap_path: Path to PCAP file
            callback: Async callback for processed data
        """
        self.pcap_path = Path(pcap_path)
        self.processor = PacketProcessor(callback)
        self.total_packets = 0
        self.processed_packets = 0
        self.start_time = None
        self.end_time = None
        self.is_processing = False
        
        if not self.pcap_path.exists():
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")
    
    async def process_file(self, chunk_size: int = 1000, realtime: bool = False):
        """Process PCAP file.
        
        Args:
            chunk_size: Number of packets to process at once
            realtime: If True, simulate real-time playback based on packet timestamps
        """
        if self.is_processing:
            logger.warning("Already processing PCAP file")
            return
        
        self.is_processing = True
        logger.info(f"Starting PCAP processing: {self.pcap_path}")
        
        try:
            # Get file info
            file_size = self.pcap_path.stat().st_size
            logger.info(f"PCAP file size: {file_size / 1024 / 1024:.2f} MB")
            
            # Process packets in chunks
            with PcapReader(str(self.pcap_path)) as pcap:
                chunk = []
                last_packet_time = None
                
                for packet in pcap:
                    self.total_packets += 1
                    
                    # Track timing
                    if hasattr(packet, 'time'):
                        packet_time = datetime.fromtimestamp(float(packet.time))
                        if self.start_time is None:
                            self.start_time = packet_time
                        self.end_time = packet_time
                        
                        # Simulate realtime playback
                        if realtime and last_packet_time:
                            delay = (packet_time - last_packet_time).total_seconds()
                            if delay > 0 and delay < 10:  # Cap at 10 seconds
                                await asyncio.sleep(min(delay, 0.1))  # Cap individual delays
                        
                        last_packet_time = packet_time
                    
                    # Process packet
                    result = self.processor.process_packet(packet)
                    if result:
                        chunk.append(result)
                        self.processed_packets += 1
                    
                    # Send chunk if full
                    if len(chunk) >= chunk_size:
                        await self._send_chunk(chunk)
                        chunk = []
                        
                        # Progress update
                        if self.processed_packets % 10000 == 0:
                            logger.info(f"Processed {self.processed_packets}/{self.total_packets} packets")
                
                # Send remaining packets
                if chunk:
                    await self._send_chunk(chunk)
                
                # Final flow flush
                await self.processor._flush_flows()
            
            duration = (self.end_time - self.start_time).total_seconds() if self.start_time and self.end_time else 0
            logger.info(f"PCAP processing complete: {self.total_packets} packets, {duration:.2f} seconds of capture")
            
        except Exception as e:
            logger.error(f"Error processing PCAP: {e}")
            raise
        finally:
            self.is_processing = False
    
    async def _send_chunk(self, chunk: List[Dict[str, Any]]):
        """Send chunk of processed packets to callback."""
        if self.processor.callback:
            await self.processor.callback({
                'type': 'packets',
                'data': chunk,
                'progress': {
                    'total': self.total_packets,
                    'processed': self.processed_packets,
                    'percentage': (self.processed_packets / max(self.total_packets, 1)) * 100
                }
            })
    
    def get_file_info(self) -> Dict[str, Any]:
        """Get PCAP file information."""
        try:
            stats = self.pcap_path.stat()
            
            # Quick scan for packet count (without full processing)
            packet_count = 0
            first_timestamp = None
            last_timestamp = None
            
            with PcapReader(str(self.pcap_path)) as pcap:
                for i, packet in enumerate(pcap):
                    if i == 0 and hasattr(packet, 'time'):
                        first_timestamp = datetime.fromtimestamp(packet.time)
                    if hasattr(packet, 'time'):
                        last_timestamp = datetime.fromtimestamp(packet.time)
                    packet_count += 1
                    
                    # Limit scan for large files
                    if i > 100000:
                        packet_count = -1  # Indicate incomplete count
                        break
            
            duration = None
            if first_timestamp and last_timestamp:
                duration = (last_timestamp - first_timestamp).total_seconds()
            
            return {
                'path': str(self.pcap_path),
                'size_bytes': stats.st_size,
                'size_mb': stats.st_size / 1024 / 1024,
                'modified': datetime.fromtimestamp(stats.st_mtime).isoformat(),
                'packet_count': packet_count if packet_count > 0 else 'Unknown (file too large)',
                'first_packet': first_timestamp.isoformat() if first_timestamp else None,
                'last_packet': last_timestamp.isoformat() if last_timestamp else None,
                'capture_duration': duration
            }
            
        except Exception as e:
            logger.error(f"Error getting PCAP info: {e}")
            return {
                'path': str(self.pcap_path),
                'error': str(e)
            }
    
    def extract_subset(self, output_path: str, filter_expr: Optional[str] = None,
                       max_packets: Optional[int] = None) -> str:
        """Extract subset of packets to new PCAP file.
        
        Args:
            output_path: Output PCAP file path
            filter_expr: BPF filter expression
            max_packets: Maximum packets to extract
            
        Returns:
            Path to output file
        """
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        
        packet_count = 0
        with PcapWriter(str(output)) as writer:
            with PcapReader(str(self.pcap_path)) as pcap:
                for packet in pcap:
                    # Apply filter if specified
                    if filter_expr:
                        # Simple filter implementation (can be enhanced)
                        if not self._matches_filter(packet, filter_expr):
                            continue
                    
                    writer.write(packet)
                    packet_count += 1
                    
                    if max_packets and packet_count >= max_packets:
                        break
        
        logger.info(f"Extracted {packet_count} packets to {output}")
        return str(output)
    
    def _matches_filter(self, packet, filter_expr: str) -> bool:
        """Simple packet filter matcher.
        
        Args:
            packet: Scapy packet
            filter_expr: Filter expression (simplified BPF-like)
            
        Returns:
            True if packet matches filter
        """
        try:
            # Simple filter parsing (can be enhanced with proper BPF)
            if 'tcp' in filter_expr.lower() and not packet.haslayer(TCP):
                return False
            if 'udp' in filter_expr.lower() and not packet.haslayer(UDP):
                return False
            if 'dns' in filter_expr.lower() and not packet.haslayer(DNS):
                return False
            
            # Port filters
            if 'port' in filter_expr:
                import re
                port_match = re.search(r'port\s+(\d+)', filter_expr)
                if port_match:
                    port = int(port_match.group(1))
                    if packet.haslayer(TCP):
                        if packet[TCP].sport != port and packet[TCP].dport != port:
                            return False
                    elif packet.haslayer(UDP):
                        if packet[UDP].sport != port and packet[UDP].dport != port:
                            return False
            
            # IP filters
            if 'host' in filter_expr:
                import re
                host_match = re.search(r'host\s+([\d\.]+)', filter_expr)
                if host_match and packet.haslayer(IP):
                    host = host_match.group(1)
                    if packet[IP].src != host and packet[IP].dst != host:
                        return False
            
            return True
            
        except Exception as e:
            logger.warning(f"Filter error: {e}")
            return True  # Default to include packet on error
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get PCAP processing statistics."""
        return {
            'file': str(self.pcap_path),
            'total_packets': self.total_packets,
            'processed_packets': self.processed_packets,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'duration': (self.end_time - self.start_time).total_seconds() if self.start_time and self.end_time else 0,
            'is_processing': self.is_processing,
            'devices_found': len(self.processor.devices),
            'flows_active': len(self.processor.flows)
        }
