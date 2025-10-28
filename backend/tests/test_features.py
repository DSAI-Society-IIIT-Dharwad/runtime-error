"""Tests for feature extraction."""

import pytest
import numpy as np
from datetime import datetime, timedelta
from detection.features import FeatureExtractor


@pytest.fixture
def feature_extractor():
    """Create feature extractor instance."""
    return FeatureExtractor()


@pytest.fixture
def sample_flows():
    """Generate sample flow data."""
    base_time = datetime.utcnow()
    flows = []
    
    for i in range(10):
        flows.append({
            'timestamp': (base_time - timedelta(minutes=i)).isoformat(),
            'src_ip': '192.168.1.100',
            'dst_ip': '8.8.8.8',
            'src_port': 50000 + i,
            'dst_port': 443,
            'protocol': 'TCP',
            'bytes_total': 1000 * (i + 1),
            'packets_total': 10 * (i + 1),
            'src_mac': '00:11:22:33:44:55',
            'dst_mac': 'ff:ff:ff:ff:ff:ff',
            'dns_queries': ['google.com', 'facebook.com'] if i % 2 == 0 else [],
            'sni': 'www.google.com' if i % 3 == 0 else None,
            'is_external': True
        })
    
    return flows


def test_feature_extraction_basic(feature_extractor, sample_flows):
    """Test basic feature extraction."""
    device_mac = '00:11:22:33:44:55'
    features = feature_extractor.extract_features(device_mac, sample_flows)
    
    # Check all features are present
    assert len(features) == len(feature_extractor.feature_names)
    
    # Check feature values are numeric
    for name, value in features.items():
        assert isinstance(value, (int, float))
        assert not np.isnan(value)


def test_feature_extraction_empty_flows(feature_extractor):
    """Test feature extraction with no flows."""
    device_mac = '00:11:22:33:44:55'
    features = feature_extractor.extract_features(device_mac, [])
    
    # Should return zero features
    assert all(value == 0.0 for value in features.values())


def test_outbound_ratio_calculation(feature_extractor):
    """Test outbound ratio calculation."""
    device_mac = '00:11:22:33:44:55'
    flows = [
        {
            'timestamp': datetime.utcnow().isoformat(),
            'src_mac': device_mac,
            'dst_mac': 'ff:ff:ff:ff:ff:ff',
            'bytes_total': 1000,
            'src_ip': '192.168.1.100',
            'dst_ip': '8.8.8.8',
            'src_port': 50000,
            'dst_port': 443,
            'protocol': 'TCP',
            'packets_total': 10
        },
        {
            'timestamp': datetime.utcnow().isoformat(),
            'src_mac': 'ff:ff:ff:ff:ff:ff',
            'dst_mac': device_mac,
            'bytes_total': 500,
            'src_ip': '8.8.8.8',
            'dst_ip': '192.168.1.100',
            'src_port': 443,
            'dst_port': 50000,
            'protocol': 'TCP',
            'packets_total': 5
        }
    ]
    
    features = feature_extractor.extract_features(device_mac, flows)
    
    # Outbound ratio should be 1000 / (1000 + 500) = 0.667
    assert abs(features['outbound_ratio'] - 0.667) < 0.01


def test_unique_destinations_count(feature_extractor, sample_flows):
    """Test unique destination counting."""
    device_mac = '00:11:22:33:44:55'
    
    # Add flows with different destinations
    flows = sample_flows[:3]
    flows[1]['dst_ip'] = '1.1.1.1'
    flows[2]['dst_ip'] = '8.8.4.4'
    
    features = feature_extractor.extract_features(device_mac, flows)
    
    # Should have 3 unique destinations
    assert features['unique_dst_count'] == 3.0


def test_dns_features(feature_extractor):
    """Test DNS feature extraction."""
    device_mac = '00:11:22:33:44:55'
    base_time = datetime.utcnow()
    
    flows = []
    for i in range(10):
        flows.append({
            'timestamp': (base_time - timedelta(seconds=i*6)).isoformat(),  # 10 queries in 1 minute
            'src_mac': device_mac,
            'dst_ip': '8.8.8.8',
            'dst_port': 53,
            'dns_queries': [f'domain{i}.com'],
            'src_ip': '192.168.1.100',
            'src_port': 50000 + i,
            'protocol': 'UDP',
            'bytes_total': 100,
            'packets_total': 1
        })
    
    features = feature_extractor.extract_features(device_mac, flows, window_minutes=1)
    
    # DNS query rate should be around 10 queries per minute = 0.167 qps
    assert features['dns_query_rate'] > 0
    assert features['dns_unique_domains'] == 10


def test_port_entropy(feature_extractor):
    """Test port entropy calculation."""
    device_mac = '00:11:22:33:44:55'
    
    # Flows with uniform port distribution (high entropy)
    flows_uniform = []
    for port in [80, 443, 22, 3389, 8080]:
        flows_uniform.append({
            'timestamp': datetime.utcnow().isoformat(),
            'src_mac': device_mac,
            'dst_port': port,
            'src_ip': '192.168.1.100',
            'dst_ip': '8.8.8.8',
            'src_port': 50000,
            'protocol': 'TCP',
            'bytes_total': 1000,
            'packets_total': 10
        })
    
    features_uniform = feature_extractor.extract_features(device_mac, flows_uniform)
    
    # Flows with single port (low entropy)
    flows_single = []
    for i in range(5):
        flows_single.append({
            'timestamp': datetime.utcnow().isoformat(),
            'src_mac': device_mac,
            'dst_port': 443,  # Same port
            'src_ip': '192.168.1.100',
            'dst_ip': '8.8.8.8',
            'src_port': 50000 + i,
            'protocol': 'TCP',
            'bytes_total': 1000,
            'packets_total': 10
        })
    
    features_single = feature_extractor.extract_features(device_mac, flows_single)
    
    # Uniform distribution should have higher entropy
    assert features_uniform['port_entropy'] > features_single['port_entropy']


def test_feature_vector_conversion(feature_extractor, sample_flows):
    """Test conversion to numpy array."""
    device_mac = '00:11:22:33:44:55'
    features = feature_extractor.extract_features(device_mac, sample_flows)
    
    vector = feature_extractor.get_feature_vector(features)
    
    # Check vector properties
    assert isinstance(vector, np.ndarray)
    assert vector.dtype == np.float32
    assert len(vector) == len(feature_extractor.feature_names)
    assert not np.any(np.isnan(vector))
