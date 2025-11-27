import pytest
from services.zerotrust_service import calculate_trust_score, get_trust_level

def test_calculate_trust_score():
    """Test the calculate_trust_score function."""
    # Test cases based on ATTACK_RISK_LEVELS and logic
    assert calculate_trust_score("Normal", 100) == 90 # 100 - (1 * 10)
    assert calculate_trust_score("DDoS", 100) == 5   # 100 - (1 * 95)
    assert calculate_trust_score("Brute Force", 50) == 57.5 # 100 - (0.5 * 85)
    assert calculate_trust_score("Unknown", 100) == 30 # 100 - (1 * 70)
    assert calculate_trust_score("Normal", 0) == 100 # 100 - (0 * 10)
    assert calculate_trust_score("DDoS", 0) == 100 # 100 - (0 * 95)
    assert calculate_trust_score("DDoS", 10) == 90.5 # 100 - (0.1 * 95)

    # Edge cases for confidence score
    assert calculate_trust_score("DDoS", 100) == 5
    assert calculate_trust_score("DDoS", 0) == 100

    # Ensure score is capped between 0 and 100
    assert calculate_trust_score("DDoS", 120) == 0 # Should not go below 0
    assert calculate_trust_score("Normal", -10) == 100 # Should not go above 100

def test_get_trust_level():
    """Test the get_trust_level function."""
    assert get_trust_level(10) == "Critical Risk"
    assert get_trust_level(19) == "Critical Risk"
    assert get_trust_level(20) == "High Risk" # Boundary
    assert get_trust_level(21) == "High Risk"
    assert get_trust_level(39) == "High Risk"
    assert get_trust_level(40) == "Medium Risk" # Boundary
    assert get_trust_level(41) == "Medium Risk"
    assert get_trust_level(59) == "Medium Risk"
    assert get_trust_level(60) == "Trusted" # Boundary
    assert get_trust_level(61) == "Trusted"
    assert get_trust_level(100) == "Trusted"
