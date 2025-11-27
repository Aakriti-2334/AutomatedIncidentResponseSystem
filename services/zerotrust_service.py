from config import ATTACK_RISK_LEVELS

def calculate_trust_score(attack_type, confidence_score):
    """Calculate trust score based on attack type and confidence score."""
    base_risk = ATTACK_RISK_LEVELS.get(attack_type, 70)
    trust_score = 100 - ((confidence_score / 100) * base_risk)
    return max(0, min(100, trust_score))

def get_trust_level(trust_score):
    """Determine the trust level category from the trust score."""
    if trust_score < 20: return "Critical Risk"
    elif trust_score < 40: return "High Risk"
    elif trust_score < 60: return "Medium Risk"
    else: return "Trusted"
