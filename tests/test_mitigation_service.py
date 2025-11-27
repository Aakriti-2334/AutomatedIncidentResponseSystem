import pytest
from unittest.mock import patch, MagicMock
import time
from services.mitigation_service import process_packet, unblock_ip, get_blocked_ips, get_alerts
from config import (
    INITIAL_REPUTATION_SCORE, REPUTATION_MANUAL_UNBLOCK_RESET_SCORE,
    REPUTATION_THRESHOLD_BLOCK, REPUTATION_THRESHOLD_ALERT
)

# Mock the database_service for these tests
@pytest.fixture(autouse=True)
def mock_database_service():
    with patch('services.mitigation_service.database_service') as mock_db:
        # Mock internal state for reputation, blocked, and alerted IPs
        mock_db.reputation_store = {}
        mock_db.blocked_ips_set = set()
        mock_db.alerted_ips_dict = {}

        # Reputation mocks
        def get_ip_reputation(ip):
            if ip in mock_db.reputation_store:
                return {'reputation_score': mock_db.reputation_store[ip], 'last_seen': time.time()}
            return None
        def update_ip_reputation(ip, score):
            mock_db.reputation_store[ip] = score
        
        mock_db.get_ip_reputation.side_effect = get_ip_reputation
        mock_db.update_ip_reputation.side_effect = update_ip_reputation

        # Blocked/Alerted IPs mocks
        mock_db.add_blocked_ip.side_effect = lambda ip: mock_db.blocked_ips_set.add(ip)
        mock_db.remove_blocked_ip.side_effect = lambda ip: mock_db.blocked_ips_set.discard(ip) or True if ip in mock_db.blocked_ips_set else False
        mock_db.is_ip_blocked.side_effect = lambda ip: ip in mock_db.blocked_ips_set
        
        mock_db.add_alerted_ip.side_effect = lambda ip, unblock_time: mock_db.alerted_ips_dict.update({ip: unblock_time})
        mock_db.remove_alerted_ip.side_effect = lambda ip: mock_db.alerted_ips_dict.pop(ip, None) is not None
        mock_db.is_ip_alerted.side_effect = lambda ip: ip in mock_db.alerted_ips_dict and mock_db.alerted_ips_dict[ip] > time.time()

        mock_db.get_blocked_ips.side_effect = lambda: list(mock_db.blocked_ips_set)
        mock_db.get_alerted_ips.side_effect = lambda: [{"ip": ip, "unblock_time": t} for ip, t in mock_db.alerted_ips_dict.items()]
        
        yield mock_db

# Mock packet_data for testing
@pytest.fixture
def mock_packet_data():
    mock_values = {
        'src_ip': '192.168.1.1',
        'dst_ip': '10.0.0.1',
        'attack_type': 'Normal',
        'confidence_score': 90.0
    }
    mock = MagicMock()
    mock.__getitem__.side_effect = lambda key: mock_values[key]
    mock.to_dict.return_value = mock_values
    # Attach the values to the mock so tests can modify them
    mock.mock_values = mock_values
    return mock

@pytest.fixture
def mock_prediction_data():
    mock = MagicMock()
    return mock

def test_process_packet_allow_new_ip(mock_packet_data, mock_prediction_data, mock_database_service):
    """Test that a normal packet from a new IP is allowed and reputation is stable."""
    mock_packet_data.mock_values['attack_type'] = 'Normal'
    mock_packet_data.mock_values['confidence_score'] = 100.0 # Trust score = 90 (Trusted)
    
    result = process_packet(mock_packet_data, mock_prediction_data)
    
    assert result['action'] == 'Allow'
    assert float(result['ip_reputation']) == INITIAL_REPUTATION_SCORE
    mock_database_service.update_ip_reputation.assert_called_with('192.168.1.1', INITIAL_REPUTATION_SCORE)

def test_process_packet_medium_risk_triggers_alert(mock_packet_data, mock_prediction_data, mock_database_service):
    """Test that a medium risk packet lowers reputation and triggers an alert."""
    mock_packet_data.mock_values['attack_type'] = 'Port Scanning' # Risk 80
    mock_packet_data.mock_values['confidence_score'] = 51.0 # Trust score = 59.2 (Medium Risk) -> Rep penalty 10
    
    # First packet, reputation drops from 100 to 90
    result1 = process_packet(mock_packet_data, mock_prediction_data)
    assert result1['action'] == 'Allow'
    assert float(result1['ip_reputation']) == 90

    # Second packet, reputation drops from 90 to 80
    result2 = process_packet(mock_packet_data, mock_prediction_data)
    assert result2['action'] == 'Allow'
    assert float(result2['ip_reputation']) == 80

    # Third packet, reputation drops from 80 to 70
    result3 = process_packet(mock_packet_data, mock_prediction_data)
    assert result3['action'] == 'Allow'
    assert float(result3['ip_reputation']) == 70

    # Fourth packet, reputation drops from 70 to 60. This should trigger an Alert.
    result4 = process_packet(mock_packet_data, mock_prediction_data)
    assert result4['action'] == 'Alert'
    assert float(result4['ip_reputation']) == 60
    mock_database_service.add_alerted_ip.assert_called()

def test_process_packet_critical_risk_triggers_block(mock_packet_data, mock_prediction_data, mock_database_service):
    """Test that a critical risk packet lowers reputation and triggers a block."""
    mock_packet_data.mock_values['attack_type'] = 'DDoS' # Risk 95
    mock_packet_data.mock_values['confidence_score'] = 90.0 # Trust score = 14.5 (Critical Risk) -> Rep penalty 50
    
    # First packet, reputation drops from 100 to 50
    result1 = process_packet(mock_packet_data, mock_prediction_data)
    assert result1['action'] == 'Alert'
    assert float(result1['ip_reputation']) == 50
    mock_database_service.add_alerted_ip.assert_called_once()

    # Second packet, reputation drops from 50 to 0. This should trigger a Block.
    result2 = process_packet(mock_packet_data, mock_prediction_data)
    assert result2['action'] == 'Block'
    assert float(result2['ip_reputation']) == 0
    mock_database_service.add_blocked_ip.assert_called_once()

def test_unblock_ip_resets_reputation(mock_database_service):
    """Test that unblocking an IP resets its reputation score."""
    ip = '192.168.1.100'
    mock_database_service.reputation_store[ip] = 10
    mock_database_service.blocked_ips_set.add(ip)
    
    result = unblock_ip(ip)
    
    assert result['message'] == "IP 192.168.1.100 unblocked and reputation reset."
    assert ip not in mock_database_service.blocked_ips_set
    assert mock_database_service.reputation_store[ip] == REPUTATION_MANUAL_UNBLOCK_RESET_SCORE

