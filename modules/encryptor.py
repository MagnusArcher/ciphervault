import secrets
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2


def encrypt_text(plaintext, key=None):
    """
    Encrypt text using AES-256-GCM.
    
    Args:
        plaintext (str): Text to encrypt
        key (str, optional): Encryption key (min 8 chars). If None, generates random key.
    
    Returns:
        dict: Contains 'key' and 'encrypted' (base64 encoded)
    
    Raises:
        ValueError: If key is too short
    """
    
    if key is None:
        key = _generate_random_key()
    else:
        if len(key) < 8:
            raise ValueError("Key must be at least 8 characters")
    
    salt = secrets.token_bytes(16)
    
    derived_key = _derive_key(key, salt)
    
    nonce = secrets.token_bytes(12)
    
    aesgcm = AESGCM(derived_key)
    
    plaintext_bytes = plaintext.encode('utf-8')
    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, None)
    
    encrypted_data = salt + nonce + ciphertext
    encrypted_base64 = base64.b64encode(encrypted_data).decode('utf-8')
    
    return {
        'key': key,
        'encrypted': encrypted_base64
    }


def _generate_random_key(length=16):
    """
    Generate a random encryption key.
    
    Args:
        length (int): Key length
    
    Returns:
        str: Random key
    """
    import string
    chars = string.ascii_letters + string.digits
    return ''.join(secrets.choice(chars) for _ in range(length))


def _derive_key(password, salt):
    """
    Derive encryption key from password using PBKDF2.
    
    Args:
        password (str): User password
        salt (bytes): Salt (16 bytes)
    
    Returns:
        bytes: 32-byte derived key
    """
    kdf = PBKDF2(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    return kdf.derive(password.encode('utf-8'))
