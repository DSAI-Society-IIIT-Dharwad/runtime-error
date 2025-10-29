"""Docker container monitoring for Home Net Guardian."""

import asyncio
import logging
import json
import psutil
import platform
from typing import Dict, Any, Optional, Callable
from datetime import datetime, timedelta
import socket
import subprocess
import os

logger = logging.getLogger(__name__)


class DockerMonitor:
    """Monitor Docker containers and system as network devices."""
    
    def __init__(self, callback: Optional[Callable] = None):
        """Initialize Docker monitor.
        
        Args:
            callback: Async callback for processed data
        """
        self.callback = callback
        self.is_running = False
        self.monitor_task = None
        self.container_info = {}
        self.system_info = {}
        
    async def start_monitoring(self, interval: int = 3):
        """Start Docker container monitoring.
        
        Args:
            interval: Update interval in seconds (default 3-4 seconds)
        """
        if self.is_running:
            logger.warning("Docker monitoring already running")
            return
        
        self.is_running = True
        logger.info(f"Starting Docker container monitoring (interval: {interval}s)")
        
        async def monitor_loop():
            while self.is_running:
                try:
                    # Get container and system information
                    containers = await self._get_container_info()
                    system = await self._get_system_info()
                    
                    # Create device entries for containers
                    devices = []
                    
                    # Add each container as a device
                    for container in containers:
                        container_device = {
                            'mac': container.get('mac', f"02:42:{container['id'][:12]}"),
                            'ip': container.get('ip', '172.17.0.1'),
                            'hostname': container.get('name', 'unknown'),
                            'vendor': 'Docker Container',
                            'role': 'container',
                            'device_type': 'container',
                            'last_seen': datetime.utcnow().isoformat(),
                            'metadata': {
                                'container_id': container.get('id'),
                                'image': container.get('image'),
                                'status': container.get('status'),
                                'ports': container.get('ports', []),
                                'cpu_percent': container.get('cpu_percent', 0),
                                'memory_usage': container.get('memory_usage', 0),
                                'network_rx': container.get('network_rx', 0),
                                'network_tx': container.get('network_tx', 0)
                            }
                        }
                        devices.append(container_device)
                    
                    # Generate synthetic network flows for containers
                    flows = await self._generate_container_flows(containers)
                    
                    # Send data via callback
                    if self.callback and devices:
                        await self.callback({
                            'type': 'devices',
                            'data': devices,
                            'timestamp': datetime.utcnow().isoformat()
                        })
                    
                    if self.callback and flows:
                        await self.callback({
                            'type': 'flows',
                            'data': flows,
                            'timestamp': datetime.utcnow().isoformat()
                        })
                    
                    logger.debug(f"Docker monitor: {len(devices)} devices, {len(flows)} flows")
                    
                except Exception as e:
                    logger.error(f"Error in Docker monitoring loop: {e}")
                
                # Wait for next interval
                await asyncio.sleep(interval)
        
        self.monitor_task = asyncio.create_task(monitor_loop())
    
    def stop_monitoring(self):
        """Stop Docker monitoring."""
        self.is_running = False
        if self.monitor_task:
            self.monitor_task.cancel()
        logger.info("Stopped Docker container monitoring")
    
    async def _get_container_info(self) -> list:
        """Get Docker container information."""
        containers = []
        
        try:
            # Check if Docker is available
            docker_available = False
            
            # Try multiple ways to detect Docker
            if os.path.exists('/var/run/docker.sock'):
                docker_available = True
            elif os.path.exists('/usr/bin/docker') or os.path.exists('/usr/local/bin/docker'):
                docker_available = True
            
            if docker_available:
                try:
                    # Try to get Docker container info
                    result = await asyncio.create_subprocess_exec(
                        'docker', 'ps', '--format', 'json',
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    stdout, stderr = await result.communicate()
                    
                    if result.returncode == 0 and stdout:
                        for line in stdout.decode().strip().split('\n'):
                            if line.strip():
                                try:
                                    container_data = json.loads(line)
                                    container_info = {
                                        'id': container_data.get('ID', ''),
                                        'name': container_data.get('Names', '').replace('/', ''),
                                        'image': container_data.get('Image', ''),
                                        'status': container_data.get('Status', ''),
                                        'ports': container_data.get('Ports', ''),
                                        'mac': f"02:42:{container_data.get('ID', '')[:12]}",
                                        'ip': '172.17.0.' + str(len(containers) + 2),
                                        'cpu_percent': 0,
                                        'memory_usage': 0,
                                        'network_rx': 0,
                                        'network_tx': 0
                                    }
                                    containers.append(container_info)
                                except json.JSONDecodeError:
                                    continue
                    else:
                        logger.debug(f"Docker command failed: {stderr.decode() if stderr else 'No output'}")
                except FileNotFoundError:
                    logger.debug("Docker command not found")
                except Exception as e:
                    logger.debug(f"Docker command error: {e}")
            
            # If no containers found, create single mock container
            if not containers:
                containers = [
                    {
                        'id': 'home-net-guardian-system',
                        'name': 'guardian-system',
                        'image': 'home-net-guardian',
                        'status': 'Running',
                        'ports': '8000:8000,5173:5173',
                        'mac': '02:42:ac:11:00:02',
                        'ip': '172.17.0.2',
                        'cpu_percent': psutil.cpu_percent(interval=0.1),
                        'memory_usage': psutil.virtual_memory().percent,
                        'network_rx': 2048,
                        'network_tx': 4096
                    }
                ]
        
        except Exception as e:
            logger.debug(f"Error getting container info: {e}")
            # Return single mock container on error
            containers = [
                {
                    'id': 'guardian-system',
                    'name': 'guardian-system',
                    'image': 'home-net-guardian',
                    'status': 'Running',
                    'ports': '8000:8000,5173:5173',
                    'mac': '02:42:ac:11:00:02',
                    'ip': '172.17.0.2',
                    'cpu_percent': psutil.cpu_percent(interval=0.1) if hasattr(psutil, 'cpu_percent') else 5.0,
                    'memory_usage': psutil.virtual_memory().percent if hasattr(psutil, 'virtual_memory') else 25.0,
                    'network_rx': 2048,
                    'network_tx': 4096
                }
            ]
        
        return containers
    
    async def _get_system_info(self) -> Dict[str, Any]:
        """Get system information."""
        try:
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            # Get network connections count
            connections = len(psutil.net_connections())
            
            # Get uptime
            boot_time = psutil.boot_time()
            uptime = datetime.now().timestamp() - boot_time
            
            return {
                'cpu_percent': cpu_percent,
                'memory_percent': memory.percent,
                'memory_used': memory.used,
                'memory_total': memory.total,
                'disk_usage': (disk.used / disk.total) * 100,
                'disk_free': disk.free,
                'disk_total': disk.total,
                'network_connections': connections,
                'uptime': uptime
            }
        
        except Exception as e:
            logger.error(f"Error getting system info: {e}")
            return {
                'cpu_percent': 0,
                'memory_percent': 0,
                'disk_usage': 0,
                'network_connections': 0,
                'uptime': 0
            }
    
    async def _get_host_mac(self) -> str:
        """Get host MAC address."""
        try:
            # Get the MAC address of the first network interface
            import uuid
            mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) 
                           for elements in range(0, 2*6, 2)][::-1])
            return mac
        except Exception:
            return "02:42:ac:11:00:01"  # Default Docker host MAC
    
    async def _get_host_ip(self) -> str:
        """Get host IP address."""
        try:
            # Get local IP address
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "172.17.0.1"  # Default Docker host IP
    
    async def _generate_container_flows(self, containers: list) -> list:
        """Generate synthetic network flows for containers."""
        flows = []
        
        try:
            current_time = datetime.utcnow()
            
            for container in containers:
                # Generate some synthetic flows for each container
                container_flows = [
                    {
                        'timestamp': current_time.isoformat(),
                        'src_ip': container['ip'],
                        'dst_ip': '8.8.8.8',
                        'src_port': 80,
                        'dst_port': 53,
                        'protocol': 'UDP',
                        'bytes_total': 64,
                        'packets_total': 1,
                        'src_mac': container['mac'],
                        'dst_mac': '02:42:ac:11:00:01',
                        'sni': None,
                        'is_external': True,
                        'flow_type': 'dns_query'
                    },
                    {
                        'timestamp': current_time.isoformat(),
                        'src_ip': container['ip'],
                        'dst_ip': '172.17.0.1',
                        'src_port': int(container.get('ports', '8000').split(':')[0]) if ':' in container.get('ports', '') else 8000,
                        'dst_port': 80,
                        'protocol': 'TCP',
                        'bytes_total': container.get('network_tx', 1024),
                        'packets_total': 10,
                        'src_mac': container['mac'],
                        'dst_mac': '02:42:ac:11:00:01',
                        'sni': None,
                        'is_external': False,
                        'flow_type': 'container_traffic'
                    }
                ]
                flows.extend(container_flows)
        
        except Exception as e:
            logger.error(f"Error generating container flows: {e}")
        
        return flows
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get Docker monitoring statistics."""
        return {
            'is_running': self.is_running,
            'containers_monitored': len(self.container_info),
            'last_update': datetime.utcnow().isoformat()
        }
