import base64
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from argon2 import PasswordHasher

def decrypt_text(encrypted_base64, key, cipher='AES-GCM', kdf='PBKDF2', hash_alg='SHA256'):
    try:
        encrypted_data = base64.b64decode(encrypted_base64)
        salt = encrypted_data[:16]
        nonce = encrypted_data[16:32]
        ciphertext = encrypted_data[32:]
        
        if kdf == 'Argon2':
            derived_key = _derive_key_argon2(key, salt, cipher)
        else:
            hash_func = hashes.SHA512() if hash_alg == 'SHA512' else hashes.SHA256()
            derived_key = _derive_key_pbkdf2(key, salt, hash_func, cipher)
        
        if cipher == 'ChaCha20':
            if len(derived_key) != 32:
                derived_key = derived_key[:32]
            chacha = ChaCha20Poly1305(derived_key)
            plaintext_bytes = chacha.decrypt(nonce, ciphertext, None)
        else:
            if len(derived_key) != 32:
                derived_key = derived_key[:32]
            aesgcm = AESGCM(derived_key)
            plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        
        plaintext = plaintext_bytes.decode('utf-8')
        return {
            'success': True,
            'decrypted': plaintext
        }
    
    except Exception as e:
        return {
            'success': False,
            'error': 'Invalid key or corrupted data'
        }

def decrypt_file(input_path, output_path, key, cipher='AES-GCM', kdf='PBKDF2', hash_alg='SHA256'):
    if not os.path.exists(input_path):
        raise FileNotFoundError(f"Input file not found: {input_path}")
    
    with open(input_path, 'rb') as f:
        encrypted_data = f.read()
    
    salt = encrypted_data[:16]
    nonce = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]
    
    try:
        if kdf == 'Argon2':
            derived_key = _derive_key_argon2(key, salt, cipher)
        else:
            hash_func = hashes.SHA512() if hash_alg == 'SHA512' else hashes.SHA256()
            derived_key = _derive_key_pbkdf2(key, salt, hash_func, cipher)
        
        if cipher == 'ChaCha20':
            if len(derived_key) != 32:
                derived_key = derived_key[:32]
            chacha = ChaCha20Poly1305(derived_key)
            plaintext_bytes = chacha.decrypt(nonce, ciphertext, None)
        else:
            if len(derived_key) != 32:
                derived_key = derived_key[:32]
            aesgcm = AESGCM(derived_key)
            plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        
        with open(output_path, 'wb') as f:
            f.write(plaintext_bytes)
        
        return {
            'success': True
        }
    
    except Exception as e:
        return {
            'success': False,
            'error': 'Invalid key or corrupted data'
        }

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
