import pandas as pd
from config import PREDICTION_DATASET_PATH, HONEYPOT_DATASET_PATH

def load_honeypot_dataset():
    """Load the honeypot dataset."""
    try:
        dataset_df = pd.read_csv(HONEYPOT_DATASET_PATH)
        print(f"✅ Honeypot data loaded successfully: {len(dataset_df)} records.")
        return dataset_df
    except FileNotFoundError as e:
        print(f"❌ Error: File not found. {e}")
        return None

def load_prediction_dataset():
    """Load the prediction dataset."""
    try:
        dataset_df = pd.read_csv(PREDICTION_DATASET_PATH)
        print(f"✅ Prediction data loaded successfully: {len(dataset_df)} records.")
        return dataset_df
    except FileNotFoundError as e:
        print(f"❌ Error: File not found. {e}")
        return None

def get_packet_by_index(df, index):
    """Get a packet from the dataframe by index."""
    if index < len(df):
        return df.iloc[index]
    return None

def get_prediction_by_index(df, index):
    """Get a prediction from the dataframe by index."""
    if df is not None and index < len(df):
        return df.iloc[index]
    return None

def get_next_packet_by_ip(df, start_index, target_ip):
    """Find the next packet with a matching destination IP."""
    if start_index >= len(df):
        return None, start_index
    
    # Search from the current index to the end of the dataframe
    for index in range(start_index, len(df)):
        if df.iloc[index]['dst_ip'] == target_ip:
            return df.iloc[index], index
            
    # If not found, return None
    return None, start_index
