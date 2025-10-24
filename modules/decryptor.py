import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def decrypt_text(encrypted_base64, key):
    try:
        encrypted_data = base64.b64decode(encrypted_base64)
        
        salt = encrypted_data[:16]
        nonce = encrypted_data[16:28]
        ciphertext = encrypted_data[28:]
        
        derived_key = _derive_key(key, salt)
        
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


def _derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    return kdf.derive(password.encode('utf-8'))
