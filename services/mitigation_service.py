import time
from services.zerotrust_service import calculate_trust_score, get_trust_level
from services import database_service
from config import (
    ALERT_DURATION_SECONDS, INITIAL_REPUTATION_SCORE,
    REPUTATION_MANUAL_UNBLOCK_RESET_SCORE,
    TRUST_SCORE_THRESHOLD_BLOCK, TRUST_SCORE_THRESHOLD_ALERT
)

def decay_reputation_scores():
    """
    Gradually increase the reputation of IPs over time if they haven't been seen.
    This is a simple decay model. A real system might use a background job.
    """
    # This function is a placeholder for a real decay mechanism.
    # In a real application, this would be triggered by a scheduler (e.g., cron, APScheduler)
    # and not called on every packet processing.
    # For this simulation, we will not call it automatically to keep things simple.
    pass

def process_packet(packet_data, prediction_data):
    """Process a single packet, and determine an action based purely on its trust score."""
    src_ip = packet_data['src_ip']

    attack_type = packet_data.get('attack_type', 'Normal')
    confidence = packet_data.get('confidence_score', 0.0)
    packet_trust_score = calculate_trust_score(attack_type, confidence)
    trust_level = get_trust_level(packet_trust_score)

    # --- Determine action based purely on the packet's trust score ---
    if packet_trust_score <= TRUST_SCORE_THRESHOLD_BLOCK:
        action = "Block"
        database_service.add_blocked_ip(src_ip)
        database_service.remove_alerted_ip(src_ip) # Ensure consistency
        print(f"IP {src_ip} trust score was {packet_trust_score:.2f}. Permanently blocked.")
    
    elif packet_trust_score <= TRUST_SCORE_THRESHOLD_ALERT:
        action = "Temporary Block"
        unblock_time = time.time() + ALERT_DURATION_SECONDS
        database_service.add_alerted_ip(src_ip, unblock_time) # This will insert or update
        print(f"IP {src_ip} trust score was {packet_trust_score:.2f}. Temporarily blocked.")
    
    else:
        action = "Allow"

    return {
        "attack_prediction": attack_type,
        "confidence": f"{confidence:.2f}%",
        "trust_score": f"{packet_trust_score:.2f}",
        "trust_level": trust_level,
        "ip_reputation": "N/A", # Reputation is no longer a factor
        "action": action,
        "details": packet_data
    }

def unblock_ip(ip_to_unblock):
    """Unblock a previously blocked or alerted IP address and reset its reputation."""
    if ip_to_unblock:
        # Remove from block/alert lists
        was_blocked = database_service.remove_blocked_ip(ip_to_unblock)
        was_alerted = database_service.remove_alerted_ip(ip_to_unblock)

        if was_blocked or was_alerted:
            # Reset reputation to a healthy score
            database_service.update_ip_reputation(ip_to_unblock, REPUTATION_MANUAL_UNBLOCK_RESET_SCORE)
            print(f"✅ IP {ip_to_unblock} manually unblocked and reputation reset to {REPUTATION_MANUAL_UNBLOCK_RESET_SCORE}.")
            return {"message": f"IP {ip_to_unblock} unblocked and reputation reset."}
        else:
            return {"message": f"IP {ip_to_unblock} was not found in any block/alert list."}
    else:
        return {"error": "No IP address provided for unblocking."}

def get_blocked_ips():
    """Return the list of currently permanently blocked IP addresses."""
    return {"blocked_ips": database_service.get_blocked_ips()}

def get_alerts():
    """Return the list of IPs in the alert state with remaining time."""
    # This function can remain as is, as it's a good way to manage temporary blocks
    # First, remove any expired alerts from the database
    current_time = time.time()
    alerts = database_service.get_alerted_ips()
    for alert in alerts:
        if current_time > alert['unblock_time']:
            database_service.remove_alerted_ip(alert['ip'])
            print(f"✅ IP {alert['ip']} automatically unblocked from alerts.")

    # Then, fetch the remaining alerts
    remaining_alerts = database_service.get_alerted_ips()
    formatted_alerts = [
        {"ip": alert['ip'], "remaining_time": alert['unblock_time'] - current_time}
        for alert in remaining_alerts
    ]
    return {"alerts": formatted_alerts}

def clear_all_blocks():
    """Clear all permanently blocked IPs and all temporarily alerted IPs."""
    database_service.clear_blocked_ips()
    database_service.clear_alerted_ips()
    return {"message": "All permanent and temporary blocks have been cleared."}