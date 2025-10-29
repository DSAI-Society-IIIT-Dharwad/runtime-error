"""Database repository for CRUD operations."""

from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from sqlmodel import Session, select, func, and_, or_
from db.models import Device, Flow, Alert, ModelState, get_session
import json


class Repository:
    """Database repository for all models."""
    
    def __init__(self, session: Session):
        """Initialize repository with session."""
        self.session = session
    
    # Device operations
    def get_device_by_mac(self, mac: str) -> Optional[Device]:
        """Get device by MAC address."""
        statement = select(Device).where(Device.mac == mac)
        return self.session.exec(statement).first()
    
    def get_all_devices(self) -> List[Device]:
        """Get all devices."""
        statement = select(Device).order_by(Device.last_seen.desc())
        return list(self.session.exec(statement).all())
    
    def get_active_devices(self, minutes: int = 15) -> List[Device]:
        """Get recently active devices."""
        cutoff = datetime.utcnow() - timedelta(minutes=minutes)
        statement = select(Device).where(Device.last_seen >= cutoff)
        return list(self.session.exec(statement).all())
    
    def create_or_update_device(
        self,
        mac: str,
        ip: Optional[str] = None,
        vendor: Optional[str] = None,
        hostname: Optional[str] = None,
        role: Optional[str] = None
    ) -> Device:
        """Create or update device."""
        device = self.get_device_by_mac(mac)
        
        if device:
            # Update existing device
            device.last_seen = datetime.utcnow()
            if ip:
                device.ip = ip
            if vendor and not device.vendor:
                device.vendor = vendor
            if hostname and not device.hostname:
                device.hostname = hostname
            if role and not device.role:
                device.role = role
        else:
            # Create new device
            device = Device(
                mac=mac,
                ip=ip,
                vendor=vendor,
                hostname=hostname,
                role=role,
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow()
            )
            self.session.add(device)
        
        self.session.commit()
        self.session.refresh(device)
        return device
    
    def update_device_score(self, mac: str, score: float) -> Optional[Device]:
        """Update device risk score."""
        device = self.get_device_by_mac(mac)
        if device:
            device.score = max(0.0, min(100.0, score))  # Clamp to 0-100
            self.session.commit()
            self.session.refresh(device)
        return device
    
    def update_device_stats(self, mac: str, stats: dict) -> Optional[Device]:
        """Update device statistics."""
        device = self.get_device_by_mac(mac)
        if device:
            device.set_stats(stats)
            self.session.commit()
            self.session.refresh(device)
        return device
    
    # Flow operations
    def create_flow(self, **kwargs) -> Flow:
        """Create a new flow."""
        flow = Flow(**kwargs)
        self.session.add(flow)
        self.session.commit()
        self.session.refresh(flow)
        return flow
    
    def get_flows_since(self, since: datetime, limit: int = 1000) -> List[Flow]:
        """Get flows since timestamp."""
        statement = (
            select(Flow)
            .where(Flow.timestamp >= since)
            .order_by(Flow.timestamp.desc())
            .limit(limit)
        )
        return list(self.session.exec(statement).all())
    
    def get_flows_for_device(self, mac: str, limit: int = 100) -> List[Flow]:
        """Get flows for a specific device."""
        statement = (
            select(Flow)
            .where(or_(Flow.src_mac == mac, Flow.dst_mac == mac))
            .order_by(Flow.timestamp.desc())
            .limit(limit)
        )
        return list(self.session.exec(statement).all())
    
    def get_flow_statistics(self, window_minutes: int = 60) -> Dict[str, Any]:
        """Get flow statistics for time window."""
        cutoff = datetime.utcnow() - timedelta(minutes=window_minutes)
        
        # Total flows
        total_stmt = select(func.count(Flow.id)).where(Flow.timestamp >= cutoff)
        total_flows = self.session.exec(total_stmt).first()
        
        # External flows
        ext_stmt = select(func.count(Flow.id)).where(
            and_(Flow.timestamp >= cutoff, Flow.is_external == True)
        )
        external_flows = self.session.exec(ext_stmt).first()
        
        # Total bytes
        bytes_stmt = select(func.sum(Flow.bytes_total)).where(Flow.timestamp >= cutoff)
        total_bytes = self.session.exec(bytes_stmt).first() or 0
        
        # Unique source IPs
        src_ips_stmt = select(func.count(func.distinct(Flow.src_ip))).where(
            Flow.timestamp >= cutoff
        )
        unique_sources = self.session.exec(src_ips_stmt).first()
        
        return {
            "total_flows": total_flows or 0,
            "external_flows": external_flows or 0,
            "total_bytes": total_bytes,
            "unique_sources": unique_sources or 0,
            "window_minutes": window_minutes
        }
    
    def get_top_talkers(self, limit: int = 10, window_minutes: int = 60) -> List[Dict]:
        """Get top talking devices by bytes."""
        cutoff = datetime.utcnow() - timedelta(minutes=window_minutes)
        
        # Query for top source MACs
        statement = (
            select(
                Flow.src_mac,
                func.sum(Flow.bytes_total).label("total_bytes"),
                func.count(Flow.id).label("flow_count")
            )
            .where(and_(Flow.timestamp >= cutoff, Flow.src_mac.is_not(None)))
            .group_by(Flow.src_mac)
            .order_by(func.sum(Flow.bytes_total).desc())
            .limit(limit)
        )
        
        results = []
        for row in self.session.exec(statement):
            device = self.get_device_by_mac(row[0])
            results.append({
                "mac": row[0],
                "vendor": device.vendor if device else None,
                "total_bytes": row[1],
                "flow_count": row[2]
            })
        
        return results
    
    # Alert operations
    def create_alert(self, **kwargs) -> Alert:
        """Create a new alert."""
        alert = Alert(**kwargs)
        self.session.add(alert)
        self.session.commit()
        self.session.refresh(alert)
        return alert
    
    def get_alerts_since(self, since: datetime, limit: int = 100) -> List[Alert]:
        """Get alerts since timestamp."""
        statement = (
            select(Alert)
            .where(Alert.timestamp >= since)
            .order_by(Alert.timestamp.desc())
            .limit(limit)
        )
        return list(self.session.exec(statement).all())
    
    def get_unresolved_alerts(self, limit: int = 100) -> List[Alert]:
        """Get unresolved alerts."""
        statement = (
            select(Alert)
            .where(Alert.status != "resolved")
            .order_by(Alert.severity_score.desc(), Alert.timestamp.desc())
            .limit(limit)
        )
        return list(self.session.exec(statement).all())
    
    def get_alerts_for_device(self, mac: str, limit: int = 50) -> List[Alert]:
        """Get alerts for a specific device."""
        statement = (
            select(Alert)
            .where(Alert.device_mac == mac)
            .order_by(Alert.timestamp.desc())
            .limit(limit)
        )
        return list(self.session.exec(statement).all())
    
    def update_alert_status(
        self,
        alert_id: int,
        status: str,
        notes: Optional[str] = None
    ) -> Optional[Alert]:
        """Update alert status."""
        statement = select(Alert).where(Alert.id == alert_id)
        alert = self.session.exec(statement).first()
        
        if alert:
            alert.status = status
            if notes:
                alert.notes = notes
            if status == "resolved":
                alert.resolved_at = datetime.utcnow()
            self.session.commit()
            self.session.refresh(alert)
        
        return alert
    
    def get_alert_statistics(self, window_hours: int = 24) -> Dict[str, Any]:
        """Get alert statistics."""
        cutoff = datetime.utcnow() - timedelta(hours=window_hours)
        
        # Total alerts
        total_stmt = select(func.count(Alert.id)).where(Alert.timestamp >= cutoff)
        total_alerts = self.session.exec(total_stmt).first()
        
        # By severity
        severity_stmt = (
            select(Alert.severity, func.count(Alert.id))
            .where(Alert.timestamp >= cutoff)
            .group_by(Alert.severity)
        )
        
        severity_counts = {}
        for severity, count in self.session.exec(severity_stmt):
            severity_counts[severity] = count
        
        # Unresolved count
        unresolved_stmt = select(func.count(Alert.id)).where(
            and_(Alert.timestamp >= cutoff, Alert.status != "resolved")
        )
        unresolved_count = self.session.exec(unresolved_stmt).first()
        
        return {
            "total_alerts": total_alerts or 0,
            "severity_counts": severity_counts,
            "unresolved_count": unresolved_count or 0,
            "window_hours": window_hours
        }
    
    # Model state operations
    def save_model_state(
        self,
        name: str,
        model_data: bytes,
        version: str,
        metrics: Optional[dict] = None,
        parameters: Optional[dict] = None
    ) -> ModelState:
        """Save ML model state."""
        # Check if model exists
        statement = select(ModelState).where(ModelState.name == name)
        model_state = self.session.exec(statement).first()
        
        if model_state:
            # Update existing
            model_state.model_data = model_data
            model_state.version = version
            model_state.updated_at = datetime.utcnow()
            if metrics:
                model_state.set_metrics(metrics)
            if parameters:
                model_state.parameters = json.dumps(parameters)
        else:
            # Create new
            model_state = ModelState(
                name=name,
                model_data=model_data,
                version=version,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
            )
            if metrics:
                model_state.set_metrics(metrics)
            if parameters:
                model_state.parameters = json.dumps(parameters)
            self.session.add(model_state)
        
        self.session.commit()
        self.session.refresh(model_state)
        return model_state
    
    def get_model_state(self, name: str) -> Optional[ModelState]:
        """Get ML model state by name."""
        statement = select(ModelState).where(ModelState.name == name)
        return self.session.exec(statement).first()
    
    def cleanup_old_data(self, days: int = 30):
        """Clean up old data from database."""
        cutoff = datetime.utcnow() - timedelta(days=days)
        
        # Delete old flows
        flow_stmt = select(Flow).where(Flow.timestamp < cutoff)
        old_flows = self.session.exec(flow_stmt).all()
        for flow in old_flows:
            self.session.delete(flow)
        
        # Delete old resolved alerts
        alert_stmt = select(Alert).where(
            and_(Alert.timestamp < cutoff, Alert.status == "resolved")
        )
        old_alerts = self.session.exec(alert_stmt).all()
        for alert in old_alerts:
            self.session.delete(alert)
        
        self.session.commit()
        
        return {
            "flows_deleted": len(old_flows),
            "alerts_deleted": len(old_alerts)
        }

    def wipe_all_data(self):
        """Delete all devices, flows, and alerts for hard mode separation."""
        # Delete Flows first (to avoid FK issues)
        flows = self.session.exec(select(Flow)).all()
        for flow in flows:
            self.session.delete(flow)
        alerts = self.session.exec(select(Alert)).all()
        for alert in alerts:
            self.session.delete(alert)
        devices = self.session.exec(select(Device)).all()
        for device in devices:
            self.session.delete(device)
        self.session.commit()