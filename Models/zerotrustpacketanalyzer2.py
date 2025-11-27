import pandas as pd
import csv
import os
from . import DropPackets  # Import the DropPackets module

def calculate_trust_score(attack_type, confidence_score):
    """
    Calculate trust score based on attack type and confidence score.
    Trust score is inversely proportional to confidence score for malicious traffic.
    Different attack types have different base risk levels.
    
    Returns a score between 0-100, where:
    - 0-20: Critical risk (block immediately)
    - 21-40: High risk (strict verification required)
    - 41-60: Medium risk (additional verification required)
    - 61-80: Low risk (standard verification)
    - 81-100: Trusted (minimal verification)
    """
    
    # Base risk levels for different attack types (higher number = higher risk)
    attack_risk_levels = {
        "DDoS": 95,
        "SQL Injection": 90,
        "Malware": 95,
        "XSS": 85,
        "Command Injection": 90,
        "Brute Force": 85,
        "Port Scanning": 80,
        "Path Traversal": 75,
        "CSRF": 70,
        "Reconnaissance": 65,
        "Normal": 10  # Very low base risk
    }
    
    # Get base risk level for this attack type
    base_risk = attack_risk_levels.get(attack_type, 80)  # Default to 80 if attack type not found
    
    if attack_type == "Normal":
        # For normal traffic, higher confidence that it's normal means higher trust
        # Since confidence_score is confidence it's an attack, we invert for normal traffic
        trust_score = 100 - ((confidence_score / 100) * base_risk)
    else:
        # For malicious traffic, higher confidence means lower trust
        # Scale the impact based on the attack's base risk level
        trust_score = 100 - ((confidence_score / 100) * base_risk)
    
    # Ensure score is within 0-100 range
    return max(0, min(100, trust_score))

def process_dataset(file_path):
    """Process the dataset and calculate trust scores for each packet."""
    
    results = []
    
    # Read CSV file
    with open(file_path, 'r') as csvfile:
        reader = csv.DictReader(csvfile)
        
        for row in reader:
            packet_id = row['packet_id']
            attack_type = row['attack_type']
            confidence_score = float(row['confidence_score'])
            is_malicious = int(row['is_malicious'])
            
            # Calculate trust score
            trust_score = calculate_trust_score(attack_type, confidence_score)
            
            # Determine trust level category
            if trust_score < 20:
                trust_level = "Critical Risk - Block"
            elif trust_score < 40:
                trust_level = "High Risk - Strict Verification"
            elif trust_score < 60:
                trust_level = "Medium Risk - Additional Verification"
            elif trust_score < 80:
                trust_level = "Low Risk - Standard Verification"
            else:
                trust_level = "Trusted - Minimal Verification"
            
            # Add to results
            results.append({
                'packet_id': packet_id,
                'attack_type': attack_type,
                'confidence_score': confidence_score,
                'trust_score': round(trust_score, 2),
                'trust_level': trust_level
            })
    
    return results

def main():
    # Path to your dataset
    file_path = r'c:\Users\amanr\Desktop\Capstone\ztadatasetfile.csv'
    
    # Process the dataset
    results = process_dataset(file_path)
    
    # Print results
    print(f"{'Packet ID':<38} | {'Attack Type':<17} | {'Confidence':<10} | {'Trust Score':<11} | {'Trust Level'}")
    print("-" * 120)
    
    for result in results:
        print(f"{result['packet_id']:<38} | {result['attack_type']:<17} | {result['confidence_score']:<10.2f} | {result['trust_score']:<11.2f} | {result['trust_level']}")
    
    # Save results to CSV
    df = pd.DataFrame(results)
    output_path = r'c:\Users\amanr\Desktop\Capstone\zero_trust_scores.csv'
    df.to_csv(output_path, index=False)
    print(f"\nResults saved to: {output_path}")
    
    # Print summary statistics
    print("\nSummary Statistics:")
    print(f"Total packets analyzed: {len(results)}")
    
    # Count packets by trust level
    trust_levels = {}
    for result in results:
        level = result['trust_level']
        trust_levels[level] = trust_levels.get(level, 0) + 1
    
    for level, count in trust_levels.items():
        percentage = (count / len(results)) * 100
        print(f"{level}: {count} packets ({percentage:.1f}%)")
    
    # Call DropPackets to filter out critical packets
    print("\n--- Starting packet filtering ---")
    filtered_df = DropPackets.drop_critical_packets(output_path)
    
    # Save the filtered packets
    filtered_path = r'c:\Users\amanr\Desktop\Capstone\filtered_packets.csv'
    DropPackets.save_filtered_packets(filtered_df, filtered_path)
    
    # Display some information about what was filtered
    critical_packets = [r for r in results if r['trust_score'] < 20]
    print("\nDetails on filtered (dropped) packets:")
    if critical_packets:
        print(f"{'Attack Type':<17} | {'Count':<6} | {'Avg Confidence':<15}")
        print("-" * 45)
        
        # Group by attack type
        attack_types = {}
        for packet in critical_packets:
            attack = packet['attack_type']
            confidence = packet['confidence_score']
            if attack not in attack_types:
                attack_types[attack] = {'count': 0, 'total_confidence': 0}
            attack_types[attack]['count'] += 1
            attack_types[attack]['total_confidence'] += confidence
        
        # Print summary for each attack type
        for attack, data in attack_types.items():
            avg_confidence = data['total_confidence'] / data['count']
            print(f"{attack:<17} | {data['count']:<6} | {avg_confidence:<15.2f}")
    else:
        print("No packets were filtered out.")

if __name__ == "__main__":
    main()