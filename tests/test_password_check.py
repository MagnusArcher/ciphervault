import pytest
from modules.password_check import check_password_strength

def test_weak_password():
    result = check_password_strength("password")
    assert result['level'] == "Weak"

def test_strong_password():
    result = check_password_strength("aK9$mP2@xL5#qR8!")
    assert result['level'] == "Very Strong"

def test_password_entropy():
    result = check_password_strength("a")
    assert result['entropy'] > 0
