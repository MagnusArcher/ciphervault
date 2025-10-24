import secrets
import string

def generate_password(length=16, use_lower=True, use_upper=True, use_digits=True, use_symbols=True):
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
        password, use_lower, use_upper, use_digits, use_symbols
    )
    return password


def _ensure_character_diversity(password, use_lower, use_upper, use_digits, use_symbols):
    password_list = list(password)
    required_types = []
    
    if use_lower:
        required_types.append(('lower', string.ascii_lowercase))
    if use_upper:
        required_types.append(('upper', string.ascii_uppercase))
    if use_digits:
        required_types.append(('digit', string.digits))
    if use_symbols:
        required_types.append(('symbol', "!@#$%^&*()_+-=[]{}|;:,.<>?"))
    
    available_positions = list(range(len(password_list)))
    
    for i, char in enumerate(password_list):
        if use_lower and char.islower() and ('lower', string.ascii_lowercase) in required_types:
            if i in available_positions:
                available_positions.remove(i)
        elif use_upper and char.isupper() and ('upper', string.ascii_uppercase) in required_types:
            if i in available_positions:
                available_positions.remove(i)
        elif use_digits and char.isdigit() and ('digit', string.digits) in required_types:
            if i in available_positions:
                available_positions.remove(i)
        elif use_symbols and char in "!@#$%^&*()_+-=[]{}|;:,.<>?" and ('symbol', "!@#$%^&*()_+-=[]{}|;:,.<>?") in required_types:
            if i in available_positions:
                available_positions.remove(i)

    for req_type, charset in required_types:
        has_char = False
        if req_type == 'lower':
            has_char = any(c.islower() for c in password_list)
        elif req_type == 'upper':
            has_char = any(c.isupper() for c in password_list)
        elif req_type == 'digit':
            has_char = any(c.isdigit() for c in password_list)
        elif req_type == 'symbol':
            has_char = any(c in charset for c in password_list)
        
        if not has_char:
            if available_positions:
                pos = secrets.choice(available_positions)
                available_positions.remove(pos)
                password_list[pos] = secrets.choice(charset)
            else:
                pos = secrets.randbelow(len(password_list))
                password_list[pos] = secrets.choice(charset)
    
    return ''.join(password_list)
