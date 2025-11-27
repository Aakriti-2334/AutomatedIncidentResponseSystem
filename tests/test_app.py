import pytest
from unittest.mock import patch, MagicMock
import pandas as pd
from app import app, socketio # Import app and socketio from your main Flask app

# Fixture for Flask test client
@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

# Fixture for Socket.IO test client
@pytest.fixture
def socketio_client(client):
    return socketio.test_client(app, flask_test_client=client)

# Mock dataframes for data_service
@pytest.fixture
def mock_data_frames():
    mock_honeypot_df = pd.DataFrame({
        'src_ip': ['192.168.1.1', '192.168.1.2', '192.168.1.3', '192.168.1.1'],
        'dst_ip': ['10.0.0.1', '10.0.0.2', '10.0.0.1', '10.0.0.3'],
        'attack_type': ['Normal', 'DDoS', 'Port Scanning', 'Normal'],
        'confidence_score': [90, 95, 80, 90]
    })
    mock_prediction_df = pd.DataFrame({
        'prediction': ['Allow', 'Block', 'Alert', 'Allow'],
        'score': [0.9, 0.99, 0.8, 0.9]
    })
    return mock_honeypot_df, mock_prediction_df

# Mock data_service functions
@pytest.fixture(autouse=True)
def mock_data_service(mock_data_frames):
    honeypot_df, prediction_df = mock_data_frames
    with patch('app.data_service') as mock_ds:
        mock_ds.load_honeypot_dataset.return_value = honeypot_df
        mock_ds.load_prediction_dataset.return_value = prediction_df
        mock_ds.get_next_packet_by_ip.side_effect = [
            (honeypot_df.iloc[0], 0), # First call returns the first packet
            (None, 1) # Subsequent calls return None
        ]
        mock_ds.get_prediction_by_index.side_effect = lambda df, idx: df.iloc[idx]
        yield mock_ds

# Patch global dataframes in app.py
@pytest.fixture(autouse=True)
def mock_app_dataframes(mock_data_frames):
    honeypot_df, prediction_df = mock_data_frames
    with patch('app.honeypot_df', honeypot_df), \
         patch('app.prediction_df', prediction_df):
        yield

# Mock mitigation_service functions
@pytest.fixture(autouse=True)
def mock_mitigation_service():
    with patch('app.mitigation_service') as mock_ms:
        mock_ms.process_packet.return_value = {
            "attack_prediction": "Normal",
            "confidence": "90.00%",
            "trust_score": "90.00",
            "trust_level": "Trusted",
            "ip_reputation": "100.00",
            "action": "Allow",
            "details": {'src_ip': '192.168.1.1'}
        }
        mock_ms.unblock_ip.return_value = {"message": "IP unblocked successfully."}
        mock_ms.get_blocked_ips.return_value = {"blocked_ips": []}
        mock_ms.get_alerts.return_value = {"alerts": []}
        yield mock_ms

# Mock database_service functions
@pytest.fixture(autouse=True)
def mock_database_service():
    with patch('app.database_service') as mock_db_service:
        mock_db_service.init_db.return_value = None
        mock_db_service.get_blocked_ips.return_value = []
        mock_db_service.get_alerted_ips.return_value = []
        mock_db_service.remove_blocked_ip.return_value = True
        mock_db_service.remove_alerted_ip.return_value = True
        yield mock_db_service

def test_index_route(client):
    """Test the main index page loads correctly."""
    response = client.get('/')
    assert response.status_code == 200
    assert b"Automated Incident Response System" in response.data

def test_get_blocked_ips_api(client, mock_mitigation_service):
    """Test the /api/blocked_ips endpoint."""
    mock_mitigation_service.get_blocked_ips.return_value = {"blocked_ips": ["1.1.1.1", "2.2.2.2"]}
    response = client.get('/api/blocked_ips')
    assert response.status_code == 200
    assert response.json == {"blocked_ips": ["1.1.1.1", "2.2.2.2"]}

def test_get_alerts_api(client, mock_mitigation_service):
    """Test the /api/alerts endpoint."""
    mock_mitigation_service.get_alerts.return_value = {"alerts": [{"ip": "3.3.3.3", "remaining_time": 60}]}
    response = client.get('/api/alerts')
    assert response.status_code == 200
    assert response.json == {"alerts": [{"ip": "3.3.3.3", "remaining_time": 60}]}

def test_unblock_ip_api(client, mock_mitigation_service):
    """Test the /api/unblock_ip endpoint."""
    response = client.post('/api/unblock_ip', json={'ip': '1.1.1.1'})
    assert response.status_code == 200
    assert response.json == {"message": "IP unblocked successfully."}
    mock_mitigation_service.unblock_ip.assert_called_with('1.1.1.1')

def test_socketio_connect(socketio_client):
    """Test Socket.IO connection."""
    assert socketio_client.is_connected()

def test_socketio_request_next_packet(socketio_client, mock_mitigation_service, mock_data_frames):
    """Test the 'request_next_packet' Socket.IO event."""
    honeypot_df, prediction_df = mock_data_frames
    
    # Ensure packet_index starts at 0 for this test
    with patch('app.packet_index', 0):
        # First packet request
        socketio_client.emit('request_next_packet', {'target_ip': '10.0.0.1'})
        received = socketio_client.get_received()
        
        assert len(received) == 1
        assert received[0]['name'] == 'packet_data_response'
        data = received[0]['args'][0]
        
        assert data['action'] == 'Allow' # Based on mock_mitigation_service default
        assert data['packet_index'] == 0 # First packet
        mock_mitigation_service.process_packet.assert_called_once()

        # Clear received messages for the next part of the test
        socketio_client.get_received() 

        # Simulate remaining packets until the end of traffic
        # The mock honeypot_df has 4 packets. packet_index starts at 0.
        # After the first emit, packet_index is 1.
        # We need 3 more emits to reach packet_index = 4 (len(honeypot_df))
        for i in range(len(honeypot_df) - 1): # -1 because one packet was already processed
            socketio_client.emit('request_next_packet', {})
            socketio_client.get_received() # Clear received messages

        # Now, emit one more time to trigger the "End of traffic data." message
        socketio_client.emit('request_next_packet', {})
        received_end = socketio_client.get_received()
        assert len(received_end) == 1
        assert received_end[0]['name'] == 'packet_data_response'
        assert received_end[0]['args'][0]['message'] == 'End of traffic data.'
def test_socketio_request_next_packet_error(socketio_client):
    """Test error handling for 'request_next_packet' when data loading fails."""
    with patch('app.honeypot_df', None), patch('app.prediction_df', None):
        socketio_client.emit('request_next_packet', {})
        received = socketio_client.get_received()
        assert len(received) == 1
        assert received[0]['name'] == 'packet_data_response'
        assert received[0]['args'][0]['error'] == 'System not initialized. Check model/data files.'
