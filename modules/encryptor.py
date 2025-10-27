import secrets
import base64
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from argon2 import PasswordHasher

def encrypt_text(plaintext, key=None, cipher='AES-GCM', kdf='PBKDF2', hash_alg='SHA256'):
    if key is None:
        key = _generate_random_key()
    else:
        if len(key) < 8:
            raise ValueError("Key must be at least 8 characters")
    
    salt = secrets.token_bytes(16)
    
    if kdf == 'Argon2':
        derived_key = _derive_key_argon2(key, salt, cipher)
    else:
        hash_func = hashes.SHA512() if hash_alg == 'SHA512' else hashes.SHA256()
        derived_key = _derive_key_pbkdf2(key, salt, hash_func, cipher)
    
    if cipher == 'ChaCha20':
        if len(derived_key) != 32:
            derived_key = derived_key[:32]
        nonce = secrets.token_bytes(16)
        chacha = ChaCha20Poly1305(derived_key)
        ciphertext = chacha.encrypt(nonce, plaintext.encode('utf-8'), None)
        encrypted_data = salt + nonce + ciphertext
    else:
        if len(derived_key) != 32:
            derived_key = derived_key[:32]
        nonce = secrets.token_bytes(16)
        aesgcm = AESGCM(derived_key)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
        encrypted_data = salt + nonce + ciphertext
    
    encrypted_base64 = base64.b64encode(encrypted_data).decode('utf-8')
    
    return {
        'key': key,
        'encrypted': encrypted_base64,
        'cipher': cipher,
        'kdf': kdf,
        'hash': hash_alg
    }

def encrypt_file(input_path, output_path, key=None, cipher='AES-GCM', kdf='PBKDF2', hash_alg='SHA256'):
    if not os.path.exists(input_path):
        raise FileNotFoundError(f"Input file not found: {input_path}")
    
    with open(input_path, 'rb') as f:
        data = f.read()
    
    salt = secrets.token_bytes(16)
    
    if key is None:
        key = _generate_random_key()
    
    if kdf == 'Argon2':
        derived_key = _derive_key_argon2(key, salt, cipher)
    else:
        hash_func = hashes.SHA512() if hash_alg == 'SHA512' else hashes.SHA256()
        derived_key = _derive_key_pbkdf2(key, salt, hash_func, cipher)
    
    if cipher == 'ChaCha20':
        if len(derived_key) != 32:
            derived_key = derived_key[:32]
        nonce = secrets.token_bytes(16)
        chacha = ChaCha20Poly1305(derived_key)
        ciphertext = chacha.encrypt(nonce, data, None)
        encrypted_data = salt + nonce + ciphertext
    else:
        if len(derived_key) != 32:
            derived_key = derived_key[:32]
        nonce = secrets.token_bytes(16)
        aesgcm = AESGCM(derived_key)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        encrypted_data = salt + nonce + ciphertext
    
    with open(output_path, 'wb') as f:
        f.write(encrypted_data)
    
    return {
        'key': key,
        'cipher': cipher,
        'kdf': kdf,
        'hash': hash_alg
    }

def _generate_random_key(length=16):
    import string
    chars = string.ascii_letters + string.digits
    return ''.join(secrets.choice(chars) for _ in range(length))

def _derive_key_pbkdf2(password, salt, hash_func, cipher):
    length = 32
    kdf = PBKDF2HMAC(
        algorithm=hash_func,
        length=length,
        salt=salt,
        iterations=480000,
    )
    return kdf.derive(password.encode('utf-8'))

def _derive_key_argon2(password, salt, cipher):
    ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=1, hash_len=32, salt_len=16)
    return ph.hash(password, salt=salt).encode('utf-8')[:32]
