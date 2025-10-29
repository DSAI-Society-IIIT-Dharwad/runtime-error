"""Machine learning model for anomaly detection."""

import joblib
import numpy as np
import logging
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import asyncio
import json

from core.config import settings
from detection.features import FeatureExtractor
from detection.heuristics import HeuristicDetector

logger = logging.getLogger(__name__)


class AnomalyDetector:
    """ML-based anomaly detection system."""
    
    def __init__(self, model_path: Optional[str] = None):
        """Initialize anomaly detector.
        
        Args:
            model_path: Path to saved model file
        """
        self.model = None
        self.scaler = StandardScaler()
        self.feature_extractor = FeatureExtractor()
        self.heuristic_detector = HeuristicDetector()
        
        # Model parameters
        self.contamination = settings.anomaly_contamination
        self.model_version = "1.0.0"
        self.model_path = Path(model_path) if model_path else Path("models/anomaly_detector.joblib")
        self.scaler_path = Path("models/scaler.joblib")
        
        # Training data buffer
        self.training_buffer = []
        self.max_buffer_size = 10000
        
        # Model performance metrics
        self.metrics = {
            'last_trained': None,
            'training_samples': 0,
            'anomaly_rate': 0.0,
            'false_positive_rate': 0.0,
            'detection_rate': 0.0
        }
        
        # Load existing model if available
        self._load_model()
        
        # Schedule periodic retraining
        self.retrain_task = None
        self.start_retrain_scheduler()
    
    def _load_model(self) -> bool:
        """Load saved model and scaler.
        
        Returns:
            True if model loaded successfully
        """
        try:
            if self.model_path.exists() and self.scaler_path.exists():
                self.model = joblib.load(self.model_path)
                self.scaler = joblib.load(self.scaler_path)
                
                # Load metrics if available
                metrics_path = self.model_path.parent / "metrics.json"
                if metrics_path.exists():
                    with open(metrics_path, 'r') as f:
                        self.metrics = json.load(f)
                
                logger.info(f"Loaded model from {self.model_path}")
                return True
            else:
                logger.info("No saved model found, will train new model")
                return False
        except Exception as e:
            logger.error(f"Error loading model: {e}")
            return False
    
    def _save_model(self):
        """Save model and scaler to disk."""
        try:
            # Create models directory if not exists
            self.model_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Save model and scaler
            joblib.dump(self.model, self.model_path)
            joblib.dump(self.scaler, self.scaler_path)
            
            # Save metrics
            metrics_path = self.model_path.parent / "metrics.json"
            with open(metrics_path, 'w') as f:
                json.dump(self.metrics, f, indent=2, default=str)
            
            logger.info(f"Saved model to {self.model_path}")
        except Exception as e:
            logger.error(f"Error saving model: {e}")
    
    def train(self, flows: List[Dict], device_macs: List[str]) -> Dict[str, any]:
        """Train anomaly detection model.
        
        Args:
            flows: List of network flows
            device_macs: List of device MAC addresses to include
            
        Returns:
            Training metrics
        """
        logger.info(f"Training model with {len(flows)} flows from {len(device_macs)} devices")
        
        # Extract features for each device
        feature_vectors = []
        feature_labels = []  # For tracking which device
        
        for mac in device_macs:
            features = self.feature_extractor.extract_features(mac, flows)
            feature_vector = self.feature_extractor.get_feature_vector(features)
            
            if np.any(feature_vector):  # Skip zero vectors
                feature_vectors.append(feature_vector)
                feature_labels.append(mac)
        
        if len(feature_vectors) < 10:
            logger.warning(f"Insufficient training data: {len(feature_vectors)} samples")
            return {
                'status': 'failed',
                'reason': 'insufficient_data',
                'samples': len(feature_vectors)
            }
        
        # Convert to numpy array
        X = np.array(feature_vectors)
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Train Isolation Forest
        self.model = IsolationForest(
            contamination=self.contamination,
            n_estimators=100,
            max_samples='auto',
            max_features=1.0,
            bootstrap=False,
            n_jobs=-1,
            random_state=42,
            warm_start=False
        )
        
        self.model.fit(X_scaled)
        
        # Evaluate model
        predictions = self.model.predict(X_scaled)
        anomaly_scores = self.model.score_samples(X_scaled)
        
        # Calculate metrics
        n_anomalies = np.sum(predictions == -1)
        anomaly_rate = n_anomalies / len(predictions)
        
        # Update metrics
        self.metrics.update({
            'last_trained': datetime.utcnow().isoformat(),
            'training_samples': len(X),
            'anomaly_rate': float(anomaly_rate),
            'feature_count': X.shape[1],
            'model_version': self.model_version
        })
        
        # Save model
        self._save_model()
        
        logger.info(f"Model trained: {len(X)} samples, {anomaly_rate:.2%} anomalies detected")
        
        return {
            'status': 'success',
            'samples': len(X),
            'features': X.shape[1],
            'anomaly_rate': anomaly_rate,
            'anomaly_count': n_anomalies
        }
    
    def predict(self, device_mac: str, flows: List[Dict]) -> Tuple[float, str, Dict]:
        """Predict anomaly score for device.
        
        Args:
            device_mac: Device MAC address
            flows: Recent flows for device
            
        Returns:
            Tuple of (score, severity, details)
        """
        # Extract features
        features = self.feature_extractor.extract_features(device_mac, flows)
        feature_vector = self.feature_extractor.get_feature_vector(features)
        
        # Initialize default response
        score = 0.0
        severity = "LOW"
        details = {
            'features': features,
            'model_based': False,
            'heuristic_based': False
        }
        
        # Run heuristic detection
        heuristic_results = self.heuristic_detector.detect(device_mac, flows, features)
        if heuristic_results:
            details['heuristic_results'] = heuristic_results
            details['heuristic_based'] = True
            
            # Determine severity from heuristics
            severities = [r['severity'] for r in heuristic_results]
            if 'CRITICAL' in severities:
                severity = 'CRITICAL'
                score = 0.9
            elif 'HIGH' in severities:
                severity = 'HIGH'
                score = 0.7
            elif 'MEDIUM' in severities:
                severity = 'MEDIUM'
                score = 0.5
            else:
                severity = 'LOW'
                score = 0.3
        
        # Run ML detection if model is available
        if self.model is not None and np.any(feature_vector):
            try:
                # Scale features
                X = feature_vector.reshape(1, -1)
                X_scaled = self.scaler.transform(X)
                
                # Predict
                prediction = self.model.predict(X_scaled)[0]
                anomaly_score = self.model.score_samples(X_scaled)[0]
                
                # Normalize score to 0-1 range
                # Isolation Forest scores are typically between -0.5 and 0.5
                # More negative = more anomalous
                ml_score = max(0.0, min(1.0, -anomaly_score + 0.5))
                
                details['model_based'] = True
                details['ml_prediction'] = 'anomaly' if prediction == -1 else 'normal'
                details['ml_score'] = float(ml_score)
                
                # Combine ML and heuristic scores
                if heuristic_results:
                    # Weight: 60% heuristic, 40% ML
                    combined_score = 0.6 * score + 0.4 * ml_score
                else:
                    combined_score = ml_score
                    
                    # Determine severity based on ML score alone
                    if ml_score > 0.8:
                        severity = 'CRITICAL'
                    elif ml_score > 0.6:
                        severity = 'HIGH'
                    elif ml_score > 0.4:
                        severity = 'MEDIUM'
                    else:
                        severity = 'LOW'
                
                score = combined_score
                
            except Exception as e:
                logger.error(f"Error in ML prediction: {e}")
                details['ml_error'] = str(e)
        
        # Add feature importance if available
        if self.model is not None and hasattr(self.model, 'feature_importances_'):
            importances = self.model.feature_importances_
            feature_names = self.feature_extractor.feature_names
            
            # Get top important features
            top_features_idx = np.argsort(importances)[-5:][::-1]
            top_features = [
                {
                    'name': feature_names[i],
                    'value': features.get(feature_names[i], 0),
                    'importance': float(importances[i])
                }
                for i in top_features_idx
            ]
            details['top_features'] = top_features
        
        # Ensure score is in valid range
        score = max(0.0, min(1.0, score))
        
        return score, severity, details
    
    def classify_severity(self, score: float, heuristic_results: List[Dict]) -> str:
        """Classify severity based on score and heuristic results.
        
        Args:
            score: Anomaly score (0-1)
            heuristic_results: Results from heuristic detection
            
        Returns:
            Severity level (LOW, MEDIUM, HIGH, CRITICAL)
        """
        # Check heuristic results first
        if heuristic_results:
            severities = [r['severity'] for r in heuristic_results]
            if 'CRITICAL' in severities:
                return 'CRITICAL'
            elif 'HIGH' in severities:
                return 'HIGH'
            elif 'MEDIUM' in severities:
                return 'MEDIUM'
        
        # Fall back to score-based classification
        if score > 0.8:
            return 'CRITICAL'
        elif score > 0.6:
            return 'HIGH'
        elif score > 0.4:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def add_training_data(self, device_mac: str, flows: List[Dict], label: Optional[str] = None):
        """Add data to training buffer for future retraining.
        
        Args:
            device_mac: Device MAC address
            flows: Flows for the device
            label: Optional label (normal/anomaly)
        """
        # Extract features
        features = self.feature_extractor.extract_features(device_mac, flows)
        
        # Add to buffer
        self.training_buffer.append({
            'device_mac': device_mac,
            'features': features,
            'label': label,
            'timestamp': datetime.utcnow().isoformat()
        })
        
        # Limit buffer size
        if len(self.training_buffer) > self.max_buffer_size:
            self.training_buffer = self.training_buffer[-self.max_buffer_size:]
    
    async def retrain_model(self):
        """Retrain model with accumulated data."""
        logger.info("Starting model retraining")
        
        try:
            # Get recent flows from database
            # This would typically query the database for recent flows
            # For now, we'll use the training buffer
            
            if len(self.training_buffer) < 100:
                logger.info("Insufficient data for retraining")
                return
            
            # Extract features from buffer
            feature_vectors = []
            for entry in self.training_buffer:
                features = entry['features']
                vector = self.feature_extractor.get_feature_vector(features)
                if np.any(vector):
                    feature_vectors.append(vector)
            
            if len(feature_vectors) < 50:
                logger.info("Insufficient valid features for retraining")
                return
            
            # Train new model
            X = np.array(feature_vectors)
            X_scaled = self.scaler.fit_transform(X)
            
            # Create new model
            new_model = IsolationForest(
                contamination=self.contamination,
                n_estimators=100,
                max_samples='auto',
                max_features=1.0,
                bootstrap=False,
                n_jobs=-1,
                random_state=42
            )
            
            new_model.fit(X_scaled)
            
            # Update model
            self.model = new_model
            
            # Update metrics
            self.metrics['last_trained'] = datetime.utcnow().isoformat()
            self.metrics['training_samples'] = len(X)
            
            # Save model
            self._save_model()
            
            logger.info(f"Model retrained with {len(X)} samples")
            
            # Clear buffer after successful training
            self.training_buffer = self.training_buffer[-1000:]  # Keep last 1000 for continuity
            
        except Exception as e:
            logger.error(f"Error during retraining: {e}")
    
    def start_retrain_scheduler(self):
        """Start periodic model retraining."""
        async def retrain_loop():
            while True:
                try:
                    await asyncio.sleep(settings.model_retrain_interval)
                    await self.retrain_model()
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.error(f"Error in retrain loop: {e}")
        
        # Start retrain task
        loop = asyncio.get_event_loop()
        self.retrain_task = loop.create_task(retrain_loop())
        logger.info(f"Started model retrain scheduler (interval: {settings.model_retrain_interval}s)")
    
    def stop_retrain_scheduler(self):
        """Stop periodic retraining."""
        if self.retrain_task:
            self.retrain_task.cancel()
            self.retrain_task = None
            logger.info("Stopped model retrain scheduler")
    
    def get_model_info(self) -> Dict:
        """Get model information and metrics.
        
        Returns:
            Model info dictionary
        """
        info = {
            'version': self.model_version,
            'trained': self.model is not None,
            'metrics': self.metrics,
            'feature_count': len(self.feature_extractor.feature_names),
            'contamination': self.contamination,
            'buffer_size': len(self.training_buffer)
        }
        
        if self.model:
            info['model_type'] = type(self.model).__name__
            if hasattr(self.model, 'n_estimators'):
                info['n_estimators'] = self.model.n_estimators
        
        return info
    
    def generate_baseline(self, flows: List[Dict], device_macs: List[str],
                         duration_hours: int = 24) -> Dict:
        """Generate baseline from normal traffic.
        
        Args:
            flows: Historical flows
            device_macs: Devices to include
            duration_hours: Hours of data to use
            
        Returns:
            Baseline statistics
        """
        # Filter flows by time
        cutoff = datetime.utcnow() - timedelta(hours=duration_hours)
        recent_flows = [
            f for f in flows
            if self._parse_timestamp(f.get('timestamp')) >= cutoff
        ]
        
        # Calculate baseline statistics
        baseline = {
            'devices': {},
            'global_stats': {},
            'generated_at': datetime.utcnow().isoformat(),
            'duration_hours': duration_hours
        }
        
        # Per-device baselines
        for mac in device_macs:
            features = self.feature_extractor.extract_features(mac, recent_flows)
            
            # Calculate statistics for each feature
            device_baseline = {}
            for feature_name, value in features.items():
                device_baseline[feature_name] = {
                    'mean': float(value),
                    'current': float(value)
                }
            
            baseline['devices'][mac] = device_baseline
        
        # Global statistics
        total_flows = len(recent_flows)
        unique_ips = len(set(f.get('dst_ip') for f in recent_flows))
        total_bytes = sum(f.get('bytes_total', 0) for f in recent_flows)
        
        baseline['global_stats'] = {
            'total_flows': total_flows,
            'flows_per_hour': total_flows / duration_hours,
            'unique_destinations': unique_ips,
            'total_bytes': total_bytes,
            'mb_per_hour': (total_bytes / 1048576) / duration_hours
        }
        
        return baseline
    
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
