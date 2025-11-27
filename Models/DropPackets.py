import pandas as pd
import os

def drop_critical_packets(input_path):
    """
    Drop packets with trust score less than 20 (Critical Risk)
    
    Args:
        input_path: Path to the CSV file containing packet data with trust scores
        
    Returns:
        DataFrame containing only safe packets (trust score >= 20)
    """
    # Read the input CSV
    df = pd.read_csv(input_path)
    
    # Keep track of original count
    original_count = len(df)
    
    # Filter out critical packets (trust_score < 20)
    safe_packets = df[df['trust_score'] >= 20].copy()
    
    # Count of dropped packets
    dropped_count = original_count - len(safe_packets)
    
    print(f"\nDropPackets: Processing complete")
    print(f"Total packets: {original_count}")
    print(f"Dropped packets: {dropped_count} ({(dropped_count/original_count)*100:.1f}% of traffic)")
    print(f"Remaining packets: {len(safe_packets)}")
    
    return safe_packets

def save_filtered_packets(filtered_df, output_path):
    """Save filtered packets to a CSV file"""
    filtered_df.to_csv(output_path, index=False)
    print(f"Filtered packets saved to: {output_path}")
    return output_path

def main():
    """Main function for standalone execution"""
    input_path = r'c:\Users\amanr\Desktop\Capstone\zero_trust_scores.csv'
    output_path = r'c:\Users\amanr\Desktop\Capstone\filtered_packets.csv'
    
    if not os.path.exists(input_path):
        print(f"Error: Input file not found: {input_path}")
        return
    
    # Drop critical packets
    filtered_df = drop_critical_packets(input_path)
    
    # Save filtered packets
    save_filtered_packets(filtered_df, output_path)

if __name__ == "__main__":
    main()