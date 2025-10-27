import pytest
from modules.password_gen import generate_password

def test_password_length():
    pwd = generate_password(12)
    assert len(pwd) == 12

def test_password_min_length():
    with pytest.raises(ValueError):
        generate_password(7)

def test_password_max_length():
    with pytest.raises(ValueError):
        generate_password(65)

def test_password_character_types():
    pwd = generate_password(16, use_lower=True, use_upper=True, use_digits=True, use_symbols=True)
    assert any(c.islower() for c in pwd)
    assert any(c.isupper() for c in pwd)
    assert any(c.isdigit() for c in pwd)
    assert any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in pwd)

def test_password_no_types():
    with pytest.raises(ValueError):
        generate_password(16, use_lower=False, use_upper=False, use_digits=False, use_symbols=False)
