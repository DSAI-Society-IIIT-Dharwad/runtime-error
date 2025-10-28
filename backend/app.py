"""Main FastAPI application for Home Net Guardian."""

import asyncio
import logging
import json
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from pathlib import Path
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException, UploadFile, File, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlmodel import Session, select

# Local imports
from core.config import settings
from core.security import RateLimiter
from db.models import get_session, create_tables, Device, Flow, Alert
from db.repo import Repository
from capture.live_sniffer import LiveSniffer
from capture.pcap_reader import PcapFileReader
from capture.device_fingerprint import DeviceFingerprinter
from detection.model import AnomalyDetector
from detection.friendly_text import explain
from schemas.traffic import (
    FlowResponse, FlowListResponse, FlowStatistics,
    CaptureMode, CaptureConfig, CaptureStatus, PcapUpload,
    TopTalker
)
from schemas.alerts import (
    AlertResponse, AlertListResponse, AlertStatistics,
    AlertCreate, AlertUpdate, AnomalyScore
)
from schemas.devices import (
    DeviceResponse, DeviceListResponse, DeviceActivity,
    DeviceRiskAssessment
)

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.log_level),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Global state
capture_manager = None
anomaly_detector = None
websocket_manager = None
rate_limiter = RateLimiter(max_requests=100, window_seconds=60)


def build_alert_response(alert: Alert) -> AlertResponse:
    """Build enriched alert response with professional guidance."""
    response = AlertResponse.model_validate(alert)

    # Normalize details payload
    details: Dict[str, Any] = {}
    if hasattr(alert, "get_details"):
        details = alert.get_details()
    elif isinstance(response.details, dict):
        details = response.details or {}

    if not isinstance(details, dict):
        details = {"raw": details}

    response.details = details

    alert_type = (
        details.get("rule")
        or details.get("alert_type")
        or details.get("type")
        or alert.category
    )

    explanation, recommendation = explain(alert_type or "")
    response.explanation = explanation
    response.recommendation = recommendation
    return response


class WebSocketManager:
    """Manage WebSocket connections."""
    
    def __init__(self):
        """Initialize WebSocket manager."""
        self.active_connections: List[WebSocket] = []
        self.update_task = None
    
    async def connect(self, websocket: WebSocket):
        """Accept WebSocket connection."""
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"WebSocket client connected. Total connections: {len(self.active_connections)}")
    
    def disconnect(self, websocket: WebSocket):
        """Remove WebSocket connection."""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        logger.info(f"WebSocket client disconnected. Total connections: {len(self.active_connections)}")
    
    async def send_personal_message(self, message: str, websocket: WebSocket):
        """Send message to specific client."""
        try:
            await websocket.send_text(message)
        except Exception as e:
            logger.error(f"Error sending message to client: {e}")
    
    async def broadcast(self, message: str):
        """Broadcast message to all connected clients."""
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception as e:
                logger.error(f"Error broadcasting to client: {e}")
                disconnected.append(connection)
        
        # Remove disconnected clients
        for conn in disconnected:
            self.disconnect(conn)
    
    async def start_updates(self, session: Session):
        """Start periodic updates to WebSocket clients."""
        async def update_loop():
            while True:
                try:
                    await asyncio.sleep(settings.ws_update_interval)
                    
                    # Get latest data
                    repo = Repository(session)
                    
                    # Get recent data
                    since = datetime.utcnow() - timedelta(minutes=5)
                    flows = repo.get_flows_since(since, limit=100)
                    alerts = repo.get_alerts_since(since, limit=50)
                    devices = repo.get_active_devices(minutes=15)
                    
                    # Prepare update message
                    update = {
                        "type": "update",
                        "timestamp": datetime.utcnow().isoformat(),
                        "data": {
                            "devices": [self._device_to_dict(d) for d in devices],
                            "flows": [self._flow_to_dict(f) for f in flows[-20:]],  # Last 20 flows
                            "alerts": [self._alert_to_dict(a) for a in alerts[-10:]]  # Last 10 alerts
                        }
                    }
                    
                    # Broadcast update
                    await self.broadcast(json.dumps(update))
                    
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.error(f"Error in WebSocket update loop: {e}")
        
        self.update_task = asyncio.create_task(update_loop())
    
    def stop_updates(self):
        """Stop periodic updates."""
        if self.update_task:
            self.update_task.cancel()
    
    def _device_to_dict(self, device: Device) -> dict:
        """Convert device to dictionary."""
        return {
            "id": device.id,
            "mac": device.mac,
            "ip": device.ip,
            "vendor": device.vendor,
            "hostname": device.hostname,
            "role": device.role,
            "score": device.score,
            "first_seen": device.first_seen.isoformat() if device.first_seen else None,
            "last_seen": device.last_seen.isoformat() if device.last_seen else None
        }
    
    def _flow_to_dict(self, flow: Flow) -> dict:
        """Convert flow to dictionary."""
        return {
            "id": flow.id,
            "timestamp": flow.timestamp.isoformat() if flow.timestamp else None,
            "src_ip": flow.src_ip,
            "dst_ip": flow.dst_ip,
            "src_port": flow.src_port,
            "dst_port": flow.dst_port,
            "protocol": flow.protocol,
            "bytes_total": flow.bytes_total,
            "packets_total": flow.packets_total
        }
    
    def _alert_to_dict(self, alert: Alert) -> dict:
        """Convert alert to dictionary."""
        response = build_alert_response(alert)
        if hasattr(response, "model_dump"):
            return response.model_dump()
        return response.dict()


class CaptureManager:
    """Manage packet capture operations."""
    
    def __init__(self):
        """Initialize capture manager."""
        self.mode = CaptureMode(settings.capture_mode)
        self.sniffer = None
        self.pcap_reader = None
        self.is_running = False
    
    async def start_capture(self, session: Session):
        """Start packet capture based on mode."""
        if self.is_running:
            logger.warning("Capture already running")
            return
        
        repo = Repository(session)
        
        # Define callback for processing captured data
        async def process_capture_data(data: Dict):
            try:
                data_type = data.get('type')
                
                if data_type == 'flows':
                    # Process flows
                    for flow_data in data.get('data', []):
                        # Create or update devices
                        if flow_data.get('src_mac'):
                            repo.create_or_update_device(
                                mac=flow_data['src_mac'],
                                ip=flow_data.get('src_ip')
                            )
                        
                        # Create flow record
                        flow = repo.create_flow(
                            timestamp=datetime.fromisoformat(flow_data['timestamp']),
                            src_ip=flow_data['src_ip'],
                            dst_ip=flow_data['dst_ip'],
                            src_port=flow_data['src_port'],
                            dst_port=flow_data['dst_port'],
                            protocol=flow_data['protocol'],
                            bytes_total=flow_data['bytes_total'],
                            packets_total=flow_data['packets_total'],
                            src_mac=flow_data.get('src_mac'),
                            dst_mac=flow_data.get('dst_mac'),
                            sni=flow_data.get('sni'),
                            is_external=flow_data.get('is_external', False)
                        )
                        
                        # Run anomaly detection
                        if flow_data.get('src_mac'):
                            await self._detect_anomalies(
                                flow_data['src_mac'],
                                [flow_data],
                                repo
                            )
                
                # Update devices from capture data
                for device_info in data.get('devices', []):
                    repo.create_or_update_device(
                        mac=device_info['mac'],
                        ip=list(device_info.get('ips', []))[0] if device_info.get('ips') else None,
                        vendor=device_info.get('vendor')
                    )
                
            except Exception as e:
                logger.error(f"Error processing capture data: {e}")
        
        if self.mode == CaptureMode.LIVE:
            # Start live capture
            self.sniffer = LiveSniffer(settings.iface, process_capture_data)
            self.sniffer.start()
            self.is_running = True
            logger.info(f"Started live capture on interface {settings.iface}")
            
        elif self.mode == CaptureMode.PCAP:
            # Start PCAP processing
            pcap_path = settings.pcap_path
            if not Path(pcap_path).exists():
                logger.error(f"PCAP file not found: {pcap_path}")
                return
            
            self.pcap_reader = PcapFileReader(pcap_path, process_capture_data)
            asyncio.create_task(self.pcap_reader.process_file(chunk_size=1000, realtime=False))
            self.is_running = True
            logger.info(f"Started PCAP processing: {pcap_path}")
    
    def stop_capture(self):
        """Stop packet capture."""
        if self.sniffer:
            self.sniffer.stop()
            self.sniffer = None
        
        self.is_running = False
        logger.info("Stopped packet capture")
    
    def get_status(self) -> CaptureStatus:
        """Get capture status."""
        status = CaptureStatus(
            mode=self.mode,
            is_running=self.is_running
        )
        
        if self.mode == CaptureMode.LIVE:
            status.interface = settings.iface
            if self.sniffer:
                stats = self.sniffer.get_stats()
                status.packets_captured = stats.get('queue_size', 0)
                status.devices_discovered = stats.get('devices_discovered', 0)
                status.active_flows = stats.get('active_flows', 0)
        
        elif self.mode == CaptureMode.PCAP:
            status.pcap_path = settings.pcap_path
            if self.pcap_reader:
                stats = self.pcap_reader.get_statistics()
                status.packets_captured = stats.get('processed_packets', 0)
                status.devices_discovered = stats.get('devices_found', 0)
                status.active_flows = stats.get('flows_active', 0)
        
        return status
    
    async def _detect_anomalies(self, device_mac: str, flows: List[Dict], repo: Repository):
        """Run anomaly detection for device."""
        global anomaly_detector
        
        if not anomaly_detector:
            return
        
        try:
            # Get detection results
            score, severity, details = anomaly_detector.predict(device_mac, flows)
            
            # Update device score
            repo.update_device_score(device_mac, score * 100)
            
            # Create alerts for significant anomalies
            if severity in ['HIGH', 'CRITICAL']:
                # Check for heuristic results
                heuristic_results = details.get('heuristic_results', [])
                
                for result in heuristic_results:
                    result_details = result.get('details', {})
                    if isinstance(result_details, dict):
                        details_payload = dict(result_details)
                    else:
                        details_payload = {"details": result_details}
                    if result.get('rule'):
                        details_payload.setdefault('rule', result.get('rule'))
                    
                    alert = repo.create_alert(
                        timestamp=datetime.utcnow(),
                        severity=result['severity'],
                        category='anomaly',
                        title=result['title'],
                        description=result['description'],
                        device_mac=device_mac,
                        details=json.dumps(details_payload)
                    )
                    logger.info(f"Created alert: {alert.title} for device {device_mac}")
                
                # Create general anomaly alert if no specific rules triggered
                if not heuristic_results and score > 0.7:
                    alert = repo.create_alert(
                        timestamp=datetime.utcnow(),
                        severity=severity,
                        category='anomaly',
                        title='Anomalous Network Behavior Detected',
                        description=f'Device {device_mac} showing unusual network patterns',
                        device_mac=device_mac,
                        details=json.dumps({
                            'alert_type': 'anomaly_general',
                            'anomaly_score': score,
                            'top_features': details.get('top_features', [])
                        })
                    )
                    logger.info(f"Created anomaly alert for device {device_mac} with score {score:.2f}")
            
            # Add to training buffer for future retraining
            anomaly_detector.add_training_data(device_mac, flows)
            
        except Exception as e:
            logger.error(f"Error in anomaly detection for {device_mac}: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    global capture_manager, anomaly_detector, websocket_manager
    
    # Startup
    logger.info("Starting Home Net Guardian backend...")
    
    # Create database tables
    create_tables()
    logger.info("Database initialized")
    
    # Initialize managers
    capture_manager = CaptureManager()
    anomaly_detector = AnomalyDetector()
    websocket_manager = WebSocketManager()
    
    # Get a session for startup tasks
    from sqlmodel import Session, create_engine
    engine = create_engine(settings.db_url)
    
    with Session(engine) as session:
        # Start capture
        await capture_manager.start_capture(session)
        
        # Start WebSocket updates
        await websocket_manager.start_updates(session)
    
    logger.info("Home Net Guardian backend started successfully")
    
    yield
    
    # Shutdown
    logger.info("Shutting down Home Net Guardian backend...")
    
    # Stop capture
    if capture_manager:
        capture_manager.stop_capture()
    
    # Stop model retraining
    if anomaly_detector:
        anomaly_detector.stop_retrain_scheduler()
    
    # Stop WebSocket updates
    if websocket_manager:
        websocket_manager.stop_updates()
    
    logger.info("Home Net Guardian backend shut down")


# Create FastAPI app
app = FastAPI(
    title="Home Net Guardian",
    description="Home network security monitoring system",
    version="1.0.0",
    lifespan=lifespan
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Health check
@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "capture_mode": settings.capture_mode,
        "capture_running": capture_manager.is_running if capture_manager else False
    }


# Device endpoints
@app.get("/api/devices", response_model=DeviceListResponse)
async def get_devices(
    session: Session = Depends(get_session),
    active_only: bool = False
):
    """Get all devices."""
    repo = Repository(session)
    
    if active_only:
        devices = repo.get_active_devices(minutes=15)
    else:
        devices = repo.get_all_devices()
    
    active_count = len(repo.get_active_devices(minutes=15))
    
    return DeviceListResponse(
        devices=[DeviceResponse.model_validate(d) for d in devices],
        total=len(devices),
        active_count=active_count
    )


@app.get("/api/devices/{mac}", response_model=DeviceResponse)
async def get_device(
    mac: str,
    session: Session = Depends(get_session)
):
    """Get specific device by MAC."""
    repo = Repository(session)
    device = repo.get_device_by_mac(mac)
    
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    
    return DeviceResponse.model_validate(device)


@app.get("/api/devices/{mac}/activity", response_model=DeviceActivity)
async def get_device_activity(
    mac: str,
    hours: int = 24,
    session: Session = Depends(get_session)
):
    """Get device activity summary."""
    repo = Repository(session)
    device = repo.get_device_by_mac(mac)
    
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    
    # Get recent flows
    flows = repo.get_flows_for_device(mac, limit=1000)
    
    # Calculate activity
    cutoff = datetime.utcnow() - timedelta(hours=hours)
    recent_flows = [f for f in flows if f.timestamp >= cutoff]
    
    bytes_sent = sum(f.bytes_total for f in recent_flows if f.src_mac == mac)
    bytes_received = sum(f.bytes_total for f in recent_flows if f.dst_mac == mac)
    unique_dests = list(set(f.dst_ip for f in recent_flows if f.src_mac == mac))[:10]
    
    # Get top ports
    from collections import Counter
    port_counter = Counter(f.dst_port for f in recent_flows if f.src_mac == mac)
    top_ports = [port for port, _ in port_counter.most_common(10)]
    
    # Get alerts count
    alerts = repo.get_alerts_for_device(mac, limit=100)
    recent_alerts = [a for a in alerts if a.timestamp >= cutoff]
    
    return DeviceActivity(
        mac=mac,
        time_window=f"{hours}h",
        flows_count=len(recent_flows),
        bytes_sent=bytes_sent,
        bytes_received=bytes_received,
        unique_destinations=unique_dests,
        top_ports=top_ports,
        alerts_count=len(recent_alerts),
        risk_score=device.score
    )


@app.get("/api/devices/{mac}/risk", response_model=DeviceRiskAssessment)
async def assess_device_risk(
    mac: str,
    session: Session = Depends(get_session)
):
    """Get device risk assessment."""
    repo = Repository(session)
    device = repo.get_device_by_mac(mac)
    
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    
    # Get recent alerts
    alerts = repo.get_alerts_for_device(mac, limit=50)
    unresolved = [a for a in alerts if a.status != 'resolved']
    
    # Determine risk factors
    risk_factors = []
    
    if unresolved:
        risk_factors.append({
            "factor": "unresolved_alerts",
            "count": len(unresolved),
            "severity": max(a.severity for a in unresolved)
        })
    
    # Get recent flows for analysis
    flows = repo.get_flows_for_device(mac, limit=100)
    
    # Check for suspicious ports
    suspicious_ports = [f.dst_port for f in flows 
                       if f.dst_port in settings.high_risk_ports]
    if suspicious_ports:
        risk_factors.append({
            "factor": "high_risk_ports",
            "ports": list(set(suspicious_ports)),
            "severity": "HIGH"
        })
    
    # Determine overall risk
    if device.score >= 70:
        overall_risk = "Critical"
    elif device.score >= 50:
        overall_risk = "High"
    elif device.score >= 30:
        overall_risk = "Medium"
    else:
        overall_risk = "Low"
    
    # Generate recommendations
    recommendations = []
    if overall_risk in ["High", "Critical"]:
        recommendations.append("Investigate recent network activity immediately")
        recommendations.append("Consider isolating device from network")
    if suspicious_ports:
        recommendations.append("Review connections to high-risk ports")
    if len(unresolved) > 5:
        recommendations.append("Address unresolved security alerts")
    
    return DeviceRiskAssessment(
        mac=mac,
        overall_risk=overall_risk,
        risk_score=device.score,
        risk_factors=risk_factors,
        recommendations=recommendations
    )


# Flow endpoints
@app.get("/api/flows", response_model=FlowListResponse)
async def get_flows(
    since: Optional[datetime] = None,
    limit: int = 100,
    session: Session = Depends(get_session)
):
    """Get network flows."""
    repo = Repository(session)
    
    if not since:
        since = datetime.utcnow() - timedelta(minutes=5)
    
    flows = repo.get_flows_since(since, limit=limit)
    
    return FlowListResponse(
        flows=[FlowResponse.model_validate(f) for f in flows],
        total=len(flows),
        since=since
    )


@app.get("/api/flows/statistics", response_model=FlowStatistics)
async def get_flow_statistics(
    window_minutes: int = 60,
    session: Session = Depends(get_session)
):
    """Get flow statistics."""
    repo = Repository(session)
    stats = repo.get_flow_statistics(window_minutes)
    
    return FlowStatistics(**stats)


@app.get("/api/flows/top-talkers", response_model=List[TopTalker])
async def get_top_talkers(
    limit: int = 10,
    window_minutes: int = 60,
    session: Session = Depends(get_session)
):
    """Get top talking devices by bytes."""
    repo = Repository(session)
    talkers = repo.get_top_talkers(limit, window_minutes)
    
    # Calculate percentages
    total_bytes = sum(t['total_bytes'] for t in talkers)
    
    result = []
    for talker in talkers:
        percentage = (talker['total_bytes'] / total_bytes * 100) if total_bytes > 0 else 0
        result.append(TopTalker(
            mac=talker['mac'],
            vendor=talker.get('vendor'),
            total_bytes=talker['total_bytes'],
            flow_count=talker['flow_count'],
            percentage=percentage
        ))
    
    return result


# Alert endpoints
@app.get("/api/alerts", response_model=AlertListResponse)
async def get_alerts(
    since: Optional[datetime] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 100,
    session: Session = Depends(get_session)
):
    """Get security alerts."""
    repo = Repository(session)
    
    if since:
        alerts = repo.get_alerts_since(since, limit=limit)
    else:
        alerts = repo.get_unresolved_alerts(limit=limit)
    
    # Filter by severity if specified
    if severity:
        alerts = [a for a in alerts if a.severity == severity]
    
    # Filter by status if specified
    if status:
        alerts = [a for a in alerts if a.status == status]
    
    unresolved_count = len([a for a in alerts if a.status != 'resolved'])
    
    return AlertListResponse(
        alerts=[build_alert_response(a) for a in alerts],
        total=len(alerts),
        unresolved=unresolved_count,
        since=since
    )


@app.post("/api/alerts", response_model=AlertResponse)
async def create_alert(
    alert: AlertCreate,
    session: Session = Depends(get_session)
):
    """Create a new alert."""
    repo = Repository(session)
    
    new_alert = repo.create_alert(
        timestamp=datetime.utcnow(),
        severity=alert.severity,
        category=alert.category,
        title=alert.title,
        description=alert.description,
        device_mac=alert.device_mac,
        flow_id=alert.flow_id,
        details=json.dumps(alert.details) if alert.details else None
    )
    
    return build_alert_response(new_alert)


@app.patch("/api/alerts/{alert_id}", response_model=AlertResponse)
async def update_alert(
    alert_id: int,
    update: AlertUpdate,
    session: Session = Depends(get_session)
):
    """Update alert status."""
    repo = Repository(session)
    
    alert = repo.update_alert_status(
        alert_id,
        update.status,
        update.notes
    )
    
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    return build_alert_response(alert)


@app.get("/api/alerts/statistics", response_model=AlertStatistics)
async def get_alert_statistics(
    window_hours: int = 24,
    session: Session = Depends(get_session)
):
    """Get alert statistics."""
    repo = Repository(session)
    stats = repo.get_alert_statistics(window_hours)
    
    return AlertStatistics(**stats)


# Capture control endpoints
@app.get("/api/capture/status", response_model=CaptureStatus)
async def get_capture_status():
    """Get capture status."""
    if not capture_manager:
        raise HTTPException(status_code=500, detail="Capture manager not initialized")
    
    return capture_manager.get_status()


@app.get("/api/mode")
async def get_mode():
    """Get current capture mode and configuration."""
    if not capture_manager:
        return {
            "mode": settings.capture_mode,
            "iface": settings.iface,
            "pcap_path": settings.pcap_path
        }
    
    return {
        "mode": capture_manager.mode.value if hasattr(capture_manager.mode, 'value') else capture_manager.mode,
        "iface": settings.iface,
        "pcap_path": settings.pcap_path
    }


@app.get("/api/interfaces")
async def list_interfaces():
    """Get list of network interfaces for live capture."""
    try:
        from scapy.all import get_if_list
        interfaces = get_if_list()
        return list(interfaces) if interfaces else []
    except Exception as e:
        logger.warning(f"Could not get interface list: {e}")
        return []


from pydantic import BaseModel as PydanticBaseModel

class ModeRequest(PydanticBaseModel):
    """Request to change capture mode."""
    mode: str
    iface: Optional[str] = None
    pcap_path: Optional[str] = None


@app.post("/api/mode")
async def set_mode(
    req: ModeRequest,
    background_tasks: BackgroundTasks,
    session: Session = Depends(get_session)
):
    """Switch capture mode dynamically."""
    global capture_manager
    
    # Validate mode
    req.mode = req.mode.lower()
    if req.mode not in ("live", "pcap"):
        raise HTTPException(status_code=400, detail="mode must be 'live' or 'pcap'")
    
    # Validate parameters based on mode
    if req.mode == "live":
        iface = req.iface or settings.iface
        if not iface:
            raise HTTPException(status_code=400, detail="iface is required for live mode")
        settings.iface = iface
    
    if req.mode == "pcap":
        path = req.pcap_path or settings.pcap_path
        if not path:
            raise HTTPException(status_code=400, detail="pcap_path is required for pcap mode")
        settings.pcap_path = path
    
    # Update settings
    settings.capture_mode = req.mode
    
    # Stop current capture
    if capture_manager:
        capture_manager.stop_capture()
        
        # Update mode and restart
        capture_manager.mode = CaptureMode(req.mode)
        background_tasks.add_task(capture_manager.start_capture, session)
    
    logger.info(f"Switched to {req.mode} mode")
    
    return {
        "mode": req.mode,
        "iface": settings.iface if req.mode == "live" else None,
        "pcap_path": settings.pcap_path if req.mode == "pcap" else None
    }


@app.post("/api/capture/mode")
async def switch_capture_mode(
    config: CaptureConfig,
    background_tasks: BackgroundTasks,
    session: Session = Depends(get_session)
):
    """Switch capture mode."""
    global capture_manager
    
    if not capture_manager:
        raise HTTPException(status_code=500, detail="Capture manager not initialized")
    
    # Stop current capture
    capture_manager.stop_capture()
    
    # Update configuration
    settings.capture_mode = config.mode.value
    if config.interface:
        settings.iface = config.interface
    if config.pcap_path:
        settings.pcap_path = config.pcap_path
    
    # Reinitialize and start new capture
    capture_manager.mode = config.mode
    background_tasks.add_task(capture_manager.start_capture, session)
    
    return {
        "status": "success",
        "message": f"Switched to {config.mode.value} mode",
        "config": config.dict()
    }


@app.post("/api/capture/pcap", response_model=PcapUpload)
async def upload_pcap(
    file: UploadFile = File(...),
    background_tasks: BackgroundTasks = BackgroundTasks(),
    session: Session = Depends(get_session)
):
    """Upload PCAP file for analysis."""
    # Validate file extension
    if not file.filename.endswith(('.pcap', '.pcapng')):
        raise HTTPException(status_code=400, detail="Invalid file format. Only PCAP files accepted.")
    
    # Save uploaded file
    upload_dir = Path("data")
    upload_dir.mkdir(exist_ok=True)
    
    file_path = upload_dir / file.filename
    
    try:
        contents = await file.read()
        with open(file_path, 'wb') as f:
            f.write(contents)
        
        # Switch to PCAP mode and process file
        settings.capture_mode = "pcap"
        settings.pcap_path = str(file_path)
        
        if capture_manager:
            capture_manager.stop_capture()
            capture_manager.mode = CaptureMode.PCAP
            background_tasks.add_task(capture_manager.start_capture, session)
        
        # Get file info
        pcap_reader = PcapFileReader(str(file_path), None)
        file_info = pcap_reader.get_file_info()
        
        return PcapUpload(
            filename=file.filename,
            size_bytes=len(contents),
            size_mb=len(contents) / 1048576,
            status="success",
            message="PCAP file uploaded and processing started",
            packet_count=file_info.get('packet_count')
        )
        
    except Exception as e:
        logger.error(f"Error uploading PCAP: {e}")
        raise HTTPException(status_code=500, detail=f"Error processing PCAP file: {str(e)}")


@app.post("/api/pcap")
async def upload_pcap_simple(
    file: UploadFile = File(...),
    session: Session = Depends(get_session)
):
    """Simple PCAP upload endpoint (for Settings component)."""
    # Validate file extension
    if not file.filename.endswith(('.pcap', '.pcapng')):
        raise HTTPException(status_code=400, detail="Invalid file format. Only PCAP files accepted.")
    
    # Save uploaded file
    upload_dir = Path("data")
    upload_dir.mkdir(exist_ok=True)
    
    file_path = upload_dir / file.filename
    
    try:
        contents = await file.read()
        with open(file_path, 'wb') as f:
            f.write(contents)
        
        return {
            "ok": True,
            "pcap_path": str(file_path),
            "filename": file.filename,
            "size_bytes": len(contents)
        }
        
    except Exception as e:
        logger.error(f"Error uploading PCAP: {e}")
        raise HTTPException(status_code=500, detail=f"Error uploading PCAP file: {str(e)}")


# Detection endpoints
@app.post("/api/detect/anomaly", response_model=AnomalyScore)
async def detect_anomaly(
    device_mac: str,
    session: Session = Depends(get_session)
):
    """Run anomaly detection for a device."""
    global anomaly_detector
    
    if not anomaly_detector:
        raise HTTPException(status_code=500, detail="Anomaly detector not initialized")
    
    repo = Repository(session)
    
    # Check device exists
    device = repo.get_device_by_mac(device_mac)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    
    # Get recent flows
    flows = repo.get_flows_for_device(device_mac, limit=100)
    
    # Convert to dict format
    flow_dicts = []
    for flow in flows:
        flow_dicts.append({
            'timestamp': flow.timestamp.isoformat(),
            'src_ip': flow.src_ip,
            'dst_ip': flow.dst_ip,
            'src_port': flow.src_port,
            'dst_port': flow.dst_port,
            'protocol': flow.protocol,
            'bytes_total': flow.bytes_total,
            'packets_total': flow.packets_total,
            'src_mac': flow.src_mac,
            'dst_mac': flow.dst_mac
        })
    
    # Run detection
    score, severity, details = anomaly_detector.predict(device_mac, flow_dicts)
    
    # Update device score
    repo.update_device_score(device_mac, score * 100)
    
    return AnomalyScore(
        device_mac=device_mac,
        score=score,
        severity=severity,
        model_based=details.get('model_based', False),
        heuristic_based=details.get('heuristic_based', False),
        features=details.get('features', {}),
        detections=[]  # Would need to convert heuristic results
    )


@app.post("/api/model/train")
async def train_model(
    background_tasks: BackgroundTasks,
    session: Session = Depends(get_session)
):
    """Trigger model training."""
    global anomaly_detector
    
    if not anomaly_detector:
        raise HTTPException(status_code=500, detail="Anomaly detector not initialized")
    
    # Get training data
    repo = Repository(session)
    flows = repo.get_flows_since(
        datetime.utcnow() - timedelta(hours=24),
        limit=10000
    )
    
    if len(flows) < 100:
        raise HTTPException(status_code=400, detail="Insufficient data for training")
    
    # Get device MACs
    device_macs = list(set(f.src_mac for f in flows if f.src_mac))
    
    # Convert flows to dict format
    flow_dicts = []
    for flow in flows:
        flow_dicts.append({
            'timestamp': flow.timestamp.isoformat(),
            'src_ip': flow.src_ip,
            'dst_ip': flow.dst_ip,
            'src_port': flow.src_port,
            'dst_port': flow.dst_port,
            'protocol': flow.protocol,
            'bytes_total': flow.bytes_total,
            'packets_total': flow.packets_total,
            'src_mac': flow.src_mac,
            'dst_mac': flow.dst_mac
        })
    
    # Train in background
    background_tasks.add_task(
        anomaly_detector.train,
        flow_dicts,
        device_macs
    )
    
    return {
        "status": "training_started",
        "message": f"Model training started with {len(flows)} flows from {len(device_macs)} devices"
    }


@app.get("/api/model/info")
async def get_model_info():
    """Get model information."""
    global anomaly_detector
    
    if not anomaly_detector:
        raise HTTPException(status_code=500, detail="Anomaly detector not initialized")
    
    return anomaly_detector.get_model_info()


# WebSocket endpoint
@app.websocket("/ws/stream")
async def websocket_endpoint(
    websocket: WebSocket,
    session: Session = Depends(get_session)
):
    """WebSocket endpoint for real-time updates."""
    global websocket_manager
    
    await websocket_manager.connect(websocket)
    
    try:
        # Send initial data
        repo = Repository(session)
        devices = repo.get_active_devices(minutes=15)
        
        initial_data = {
            "type": "initial",
            "timestamp": datetime.utcnow().isoformat(),
            "data": {
                "devices": [websocket_manager._device_to_dict(d) for d in devices],
                "capture_status": capture_manager.get_status().dict() if capture_manager else {}
            }
        }
        
        await websocket.send_text(json.dumps(initial_data))
        
        # Keep connection alive
        while True:
            # Wait for messages from client (ping/pong)
            data = await websocket.receive_text()
            
            # Echo back as pong
            if data == "ping":
                await websocket.send_text("pong")
            
    except WebSocketDisconnect:
        websocket_manager.disconnect(websocket)
        logger.info("WebSocket client disconnected")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        websocket_manager.disconnect(websocket)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host=settings.api_host,
        port=settings.api_port,
        log_level=settings.log_level.lower()
    )
