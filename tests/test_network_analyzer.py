import pytest
import sys
import os
from unittest.mock import patch, MagicMock
import torch
from scapy.all import IP

# Add the parent directory to the Python path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from security_modules.network_analyzer import (
    Autoencoder, train_model, detect_anomaly, scan_network,
    extract_packet_features, analyze_traffic
)

from models import Issue, db


def test_autoencoder():
    model = Autoencoder()
    test_data = torch.randn(1, 5)
    output = model(test_data)
    assert output.shape == test_data.shape

def test_train_model():
    model = Autoencoder()
    test_data = torch.randn(10, 5)
    train_model(test_data)
    # Test completes without errors

@patch('models.db.session.bulk_save_objects')  # Updated path
@patch('models.db.session.commit')  # Updated path
def test_detect_anomaly(mock_commit, mock_bulk_save, app_ctx):
    # Train on normal data
    normal_train_data = torch.tensor([[0.1] * 5] * 10, dtype=torch.float32)
    train_model(normal_train_data)

    # Test normal data
    normal_data = torch.tensor([[0.1] * 5], dtype=torch.float32)
    result = detect_anomaly(normal_data)
    assert not any(result)
    mock_bulk_save.assert_not_called()
    mock_commit.assert_not_called()

    # Reset mocks
    mock_bulk_save.reset_mock()
    mock_commit.reset_mock()

    # Test anomalous data
    anomaly_data = torch.tensor([[10.0] * 5], dtype=torch.float32)
    result = detect_anomaly(anomaly_data)
    assert any(result)
    mock_bulk_save.assert_called_once()
    mock_commit.assert_called_once()

@patch('nmap.PortScanner')
def test_scan_network_error(mock_scanner):
    mock_scanner_instance = MagicMock()
    mock_scanner.return_value = mock_scanner_instance
    mock_scanner_instance.scan.side_effect = Exception("Scan error")

    result = scan_network('192.168.1.1')
    assert isinstance(result, dict)
    assert 'error' in result
    assert 'host' in result
    assert result['error'] == "Scan error"
    assert result['host'] == "192.168.1.1"

def test_extract_packet_features():
    packet = MagicMock()
    ip_layer = MagicMock()
    ip_layer.src = '192.168.1.2'
    ip_layer.dst = '192.168.1.2'
    ip_layer.proto = 6
    ip_layer.ttl = 64
    ip_layer.flags = 2
    ip_layer.tos = 0

    packet.haslayer = lambda x: True if x == IP else False
    packet.__getitem__.return_value = ip_layer
    packet.__len__.return_value = 100

    features = extract_packet_features(packet)
    assert isinstance(features, dict)
    assert features['length'] == 100
    assert features['src'] == '192.168.1.2'
    assert features['dst'] == '192.168.1.2'
    assert features['proto'] == 6
    assert features['ttl'] == 64
    assert features['flags'] == 2
    assert features['tos'] == 0
    assert 'timestamp' in features

def test_extract_packet_features_error():
    packet = MagicMock()
    packet.haslayer = lambda x: False
    result = extract_packet_features(packet)
    assert result is None



@patch('security_modules.network_analyzer.sniff')
def test_analyze_traffic(mock_sniff, app_ctx):
    mock_sniff.return_value = []

    result = analyze_traffic(count=5)
    assert isinstance(result, list)
    assert len(result) == 0

@patch('security_modules.network_analyzer.sniff')
def test_analyze_traffic_error(mock_sniff, app_ctx):
    mock_sniff.side_effect = Exception("Network capture failed")

    result = analyze_traffic()
    assert isinstance(result, list)
    assert len(result) == 0