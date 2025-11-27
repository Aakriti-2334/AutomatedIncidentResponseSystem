# config.py

# Data Paths
PREDICTION_DATASET_PATH = 'Models/cicids_live_predictions.csv'
HONEYPOT_DATASET_PATH = 'honeypot_dataset.csv'

# Mitigation Service Configuration
ALERT_DURATION_SECONDS = 15 * 60  # 15 minutes

# Zero Trust Service Configuration
ATTACK_RISK_LEVELS = {
    "Normal": 10, "Brute Force": 85, "Port Scanning": 80, "DDoS": 95,
    "DoS attacks-Hulk": 90, "Botnet": 90, "Infiltration": 85, "Web attacks": 85,
    "DoS attacks-GoldenEye": 90, "DoS attacks-Slowloris": 90, "SSH-Bruteforce": 85,
    "FTP-BruteForce": 85, "Heartbleed": 95, "SQL Injection": 90, "XSS": 85, "Unknown": 70
}

# IP Reputation System Configuration (Simplified for Trust Score Model)
INITIAL_REPUTATION_SCORE = 100 
REPUTATION_MANUAL_UNBLOCK_RESET_SCORE = 75 # Score to reset to on manual unblock, less critical now

# New thresholds based on the packet's individual trust score (0-100, lower is worse)
TRUST_SCORE_THRESHOLD_BLOCK = 19  # Trust score at or below which an IP is permanently blocked
TRUST_SCORE_THRESHOLD_ALERT = 60  # Trust score at or below which an IP is temporarily blocked

