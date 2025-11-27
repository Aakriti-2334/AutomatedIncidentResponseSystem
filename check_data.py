import pandas as pd
import os

TRAFFIC_DATA_PATH = os.path.join('Models', 'cicids2018', 'CICIDS2018_test_balanced_alligned.csv')
DETAILS_DATA_PATH = os.path.join('Models', 'ztadatasetfile.csv')

print("--- Data Integrity Check ---")

try:
    traffic_df = pd.read_csv(TRAFFIC_DATA_PATH)
    details_df = pd.read_csv(DETAILS_DATA_PATH)

    traffic_len = len(traffic_df)
    details_len = len(details_df)

    print(f"Rows in AI data file ('CICIDS2018_..."): {traffic_len}")
    print(f"Rows in Details data file ('ztadatasetfile.csv'): {details_len}")

    if traffic_len != details_len:
        print("\nWARNING: The two data files have a different number of rows.")
        print("The simulation will stop when it reaches the end of the shorter file.")

    packet_index_to_check = 13
    if packet_index_to_check < details_len:
        print(f"\n--- Checking content of row #{packet_index_to_check} in 'ztadatasetfile.csv' ---")
        packet_details = details_df.iloc[[packet_index_to_check]]
        
        # Check for missing values
        if packet_details.isnull().values.any():
            print("WARNING: The row contains missing or empty values.")
        else:
            print("SUCCESS: The row appears to be complete.")
            
        print("\nRow content:")
        print(packet_details.to_string())
    else:
        print(f"\nERROR: Cannot check row #{packet_index_to_check} as it is beyond the file length of {details_len}.")

except FileNotFoundError as e:
    print(f"ERROR: Could not find a data file. {e}")
except Exception as e:
    print(f"An unexpected error occurred: {e}")
