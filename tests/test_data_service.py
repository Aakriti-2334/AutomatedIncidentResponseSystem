import pytest
from unittest.mock import patch, MagicMock
import pandas as pd
from services.data_service import load_honeypot_dataset, load_prediction_dataset, get_packet_by_index, get_prediction_by_index, get_next_packet_by_ip
from config import HONEYPOT_DATASET_PATH, PREDICTION_DATASET_PATH

# Fixture to mock pd.read_csv
@pytest.fixture
def mock_read_csv():
    with patch('pandas.read_csv') as mock_method:
        # Mock dataframes
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

        def side_effect(path):
            if path == HONEYPOT_DATASET_PATH:
                return mock_honeypot_df
            elif path == PREDICTION_DATASET_PATH:
                return mock_prediction_df
            else:
                raise FileNotFoundError

        mock_method.side_effect = side_effect
        yield mock_method

def test_load_honeypot_dataset_success(mock_read_csv):
    """Test successful loading of honeypot dataset."""
    df = load_honeypot_dataset()
    assert df is not None
    assert not df.empty
    mock_read_csv.assert_any_call(HONEYPOT_DATASET_PATH)

def test_load_prediction_dataset_success(mock_read_csv):
    """Test successful loading of prediction dataset."""
    df = load_prediction_dataset()
    assert df is not None
    assert not df.empty
    mock_read_csv.assert_any_call(PREDICTION_DATASET_PATH)

def test_load_dataset_file_not_found():
    """Test handling of FileNotFoundError for datasets."""
    with patch('pandas.read_csv', side_effect=FileNotFoundError):
        df = load_honeypot_dataset()
        assert df is None
        df = load_prediction_dataset()
        assert df is None

def test_get_packet_by_index(mock_read_csv):
    """Test retrieving a packet by index."""
    df = load_honeypot_dataset()
    packet = get_packet_by_index(df, 0)
    assert packet is not None
    assert packet['src_ip'] == '192.168.1.1'
    assert get_packet_by_index(df, 999) is None # Out of bounds

def test_get_prediction_by_index(mock_read_csv):
    """Test retrieving a prediction by index."""
    df = load_prediction_dataset()
    prediction = get_prediction_by_index(df, 0)
    assert prediction is not None
    assert prediction['prediction'] == 'Allow'
    assert get_prediction_by_index(df, 999) is None # Out of bounds
    assert get_prediction_by_index(None, 0) is None # None dataframe

def test_get_next_packet_by_ip(mock_read_csv):
    """Test finding the next packet by target IP."""
    df = load_honeypot_dataset()

    # Find first occurrence of '10.0.0.1'
    packet, index = get_next_packet_by_ip(df, 0, '10.0.0.1')
    assert packet is not None
    assert packet['dst_ip'] == '10.0.0.1'
    assert index == 0

    # Find next occurrence of '10.0.0.1'
    packet, index = get_next_packet_by_ip(df, index + 1, '10.0.0.1')
    assert packet is not None
    assert packet['dst_ip'] == '10.0.0.1'
    assert index == 2

    # No more occurrences
    packet, index = get_next_packet_by_ip(df, index + 1, '10.0.0.1')
    assert packet is None

    # IP not in dataset
    packet, index = get_next_packet_by_ip(df, 0, '99.99.99.99')
    assert packet is None

    # Empty dataframe
    empty_df = pd.DataFrame()
    packet, index = get_next_packet_by_ip(empty_df, 0, '10.0.0.1')
    assert packet is None
    assert index == 0

    # Start index out of bounds
    packet, index = get_next_packet_by_ip(df, len(df), '10.0.0.1')
    assert packet is None
    assert index == len(df)
