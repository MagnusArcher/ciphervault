import secrets
import string


def generate_password(length=16, use_lower=True, use_upper=True, use_digits=True, use_symbols=True):
    """
    Generate a cryptographically secure random password.
    
    Args:
        length (int): Password length (8-64)
        use_lower (bool): Include lowercase letters
        use_upper (bool): Include uppercase letters
        use_digits (bool): Include digits
        use_symbols (bool): Include special symbols
    
    Returns:
        str: Generated password
    
    Raises:
        ValueError: If invalid parameters
    """
    
    if length < 8 or length > 64:
        raise ValueError("Password length must be between 8 and 64")
    
    char_pool = ""
    
    if use_lower:
        char_pool += string.ascii_lowercase
    if use_upper:
        char_pool += string.ascii_uppercase
    if use_digits:
        char_pool += string.digits
    if use_symbols:
        char_pool += "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    if not char_pool:
        raise ValueError("At least one character type must be selected")
    
    password = ''.join(secrets.choice(char_pool) for _ in range(length))
    
    password = _ensure_character_diversity(
        password, char_pool, use_lower, use_upper, use_digits, use_symbols
    )
    
    return password


def _ensure_character_diversity(password, char_pool, use_lower, use_upper, use_digits, use_symbols):
    """
    Ensure password contains at least one character from each selected type.
    
    Args:
        password (str): Generated password
        char_pool (str): Character pool used
        use_lower (bool): Lowercase selected
        use_upper (bool): Uppercase selected
        use_digits (bool): Digits selected
        use_symbols (bool): Symbols selected
    
    Returns:
        str: Password with guaranteed diversity
    """
    password_list = list(password)
    
    if use_lower and not any(c.islower() for c in password):
        pos = secrets.randbelow(len(password_list))
        password_list[pos] = secrets.choice(string.ascii_lowercase)
    
    if use_upper and not any(c.isupper() for c in password):
        pos = secrets.randbelow(len(password_list))
        password_list[pos] = secrets.choice(string.ascii_uppercase)
    
    if use_digits and not any(c.isdigit() for c in password):
        pos = secrets.randbelow(len(password_list))
        password_list[pos] = secrets.choice(string.digits)
    
    if use_symbols and not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
        pos = secrets.randbelow(len(password_list))
        password_list[pos] = secrets.choice("!@#$%^&*()_+-=[]{}|;:,.<>?")
    
    return ''.join(password_list)
