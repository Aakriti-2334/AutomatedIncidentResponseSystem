import csv
import random
import uuid
from datetime import datetime, timedelta

# Configuration
NUM_ROWS = 2000
OUTPUT_FILE = 'honeypot_dataset.csv'

# Attack types from app.py's ATTACK_CATEGORY_MAP
ATTACK_TYPES = [
    "Normal", "Brute Force", "Port Scanning", "DDoS", "DoS attacks-Hulk",
    "Botnet", "Infiltration", "Web attacks", "DoS attacks-GoldenEye",
    "DoS attacks-Slowloris", "SSH-Bruteforce", "FTP-BruteForce",
    "Heartbleed", "SQL Injection", "XSS"
]

# Headers for the CSV file
HEADERS = [
    'timestamp', 'src_ip', 'dst_ip', 'protocol', 'port',
    'attack_type', 'confidence_score', 'is_malicious'
]

def generate_random_ip():
    """Generates a random IPv4 address."""
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def generate_honeypot_data():
    """Generates the honeypot dataset."""
    # Create a pool of 20 source IPs to ensure repetition for filtering
    src_ip_pool = [generate_random_ip() for _ in range(20)]
    
    data = []
    current_time = datetime.now()

    for _ in range(NUM_ROWS):
        # Determine if the packet is normal or an attack
        is_attack = random.random() > 0.5
        
        if is_attack:
            attack_type = random.choice([at for at in ATTACK_TYPES if at != "Normal"])
            # Confidence for attacks should be high to be realistic
            confidence = round(random.uniform(80, 99), 2)
            is_malicious = 1
        else:
            attack_type = "Normal"
            # Confidence for normal traffic should be low (as it's confidence of being an attack)
            # to ensure trust score is > 60
            confidence = round(random.uniform(1, 20), 2)
            is_malicious = 0

        row = {
            'timestamp': current_time.strftime('%Y-%m-%d %H:%M:%S'),
            'src_ip': random.choice(src_ip_pool),  # Pick a random IP from the pool
            'dst_ip': generate_random_ip(),
            'protocol': random.choice(['TCP', 'UDP', 'ICMP']),
            'port': random.randint(1, 65535),
            'attack_type': attack_type,
            'confidence_score': confidence,
            'is_malicious': is_malicious
        }
        data.append(row)
        
        # Increment time for the next packet
        current_time += timedelta(milliseconds=random.randint(50, 500))

    return data

def save_to_csv(data, filename):
    """Saves the generated data to a CSV file."""
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=HEADERS)
        writer.writeheader()
        writer.writerows(data)
    print(f"✅ Successfully generated {len(data)} rows of honeypot data in '{filename}'.")

if __name__ == "__main__":
    honeypot_data = generate_honeypot_data()
    save_to_csv(honeypot_data, OUTPUT_FILE)
