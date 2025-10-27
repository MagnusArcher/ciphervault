import os
import json
import secrets
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes, hmac
from argon2 import PasswordHasher
import logging

VAULT_FILE = "vault.json"
logger = logging.getLogger("cipher")

def _derive_vault_keys(master_password, salt1, salt2, salt3):
    ph = PasswordHasher(
        time_cost=4,
        memory_cost=131072,
        parallelism=2,
        hash_len=64,
        salt_len=32
    )
    key1 = ph.hash(master_password, salt=salt1).encode('utf-8')[:32]
    key2 = ph.hash(master_password, salt=salt2).encode('utf-8')[:32]
    key3 = ph.hash(master_password, salt=salt3).encode('utf-8')[:64]
    return key1, key2, key3

def save_password_to_vault(master_password, name, password):
    try:
        salt1 = secrets.token_bytes(32)
        salt2 = secrets.token_bytes(32)
        salt3 = secrets.token_bytes(32)
        nonce1 = secrets.token_bytes(16)
        nonce2 = secrets.token_bytes(12)
        
        key1, key2, key3 = _derive_vault_keys(master_password, salt1, salt2, salt3)
        
        entry = {
            "id": secrets.token_hex(8),
            "name": name,
            "password": password,
            "created_at": __import__('datetime').datetime.utcnow().isoformat() + "Z"
        }
        
        if vault_exists():
            vault_data = load_vault_raw(master_password)
            vault_data["entries"].append(entry)
        else:
            vault_data = {"entries": [entry]}
        
        plaintext = json.dumps(vault_data).encode('utf-8')
        aesgcm = AESGCM(key1)
        ciphertext1 = aesgcm.encrypt(nonce1, plaintext, None)
        
        chacha = ChaCha20Poly1305(key2)
        wrapped_key1 = chacha.encrypt(nonce2, key1, None)
        
        h = hmac.HMAC(key3, hashes.SHA512())
        h.update(ciphertext1)
        hmac_digest = h.finalize()
        
        vault_file = {
            "vault_version": "2.0",
            "salt1": base64.b64encode(salt1).decode('utf-8'),
            "salt2": base64.b64encode(salt2).decode('utf-8'),
            "salt3": base64.b64encode(salt3).decode('utf-8'),
            "nonce1": base64.b64encode(nonce1).decode('utf-8'),
            "nonce2": base64.b64encode(nonce2).decode('utf-8'),
            "wrapped_key": base64.b64encode(wrapped_key1).decode('utf-8'),
            "ciphertext": base64.b64encode(ciphertext1).decode('utf-8'),
            "hmac": base64.b64encode(hmac_digest).decode('utf-8')
        }
        
        with open(VAULT_FILE, 'w') as f:
            json.dump(vault_file, f, indent=2)
        
        logger.info(f"Password saved to vault: {name}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to save password to vault: {str(e)}")
        return False

def load_vault(master_password):
    try:
        if not vault_exists():
            return []
        
        with open(VAULT_FILE, 'r') as f:
            vault_file = json.load(f)
        
        salt1 = base64.b64decode(vault_file["salt1"])
        salt2 = base64.b64decode(vault_file["salt2"])
        salt3 = base64.b64decode(vault_file["salt3"])
        nonce1 = base64.b64decode(vault_file["nonce1"])
        nonce2 = base64.b64decode(vault_file["nonce2"])
        wrapped_key1 = base64.b64decode(vault_file["wrapped_key"])
        ciphertext1 = base64.b64decode(vault_file["ciphertext"])
        stored_hmac = base64.b64decode(vault_file["hmac"])
        
        _, key2, key3 = _derive_vault_keys(master_password, salt1, salt2, salt3)
        
        chacha = ChaCha20Poly1305(key2)
        key1 = chacha.decrypt(nonce2, wrapped_key1, None)
        
        h = hmac.HMAC(key3, hashes.SHA512())
        h.update(ciphertext1)
        computed_hmac = h.finalize()
        
        if not secrets.compare_digest(computed_hmac, stored_hmac):
            raise ValueError("Vault integrity check failed")
        
        aesgcm = AESGCM(key1)
        plaintext = aesgcm.decrypt(nonce1, ciphertext1, None)
        vault_data = json.loads(plaintext.decode('utf-8'))
        
        logger.info("Vault loaded successfully")
        return vault_data["entries"]
        
    except Exception as e:
        logger.error(f"Failed to load vault: {str(e)}")
        return []

def load_vault_raw(master_password):
    with open(VAULT_FILE, 'r') as f:
        vault_file = json.load(f)
    
    salt1 = base64.b64decode(vault_file["salt1"])
    salt2 = base64.b64decode(vault_file["salt2"])
    salt3 = base64.b64decode(vault_file["salt3"])
    nonce1 = base64.b64decode(vault_file["nonce1"])
    nonce2 = base64.b64decode(vault_file["nonce2"])
    wrapped_key1 = base64.b64decode(vault_file["wrapped_key"])
    ciphertext1 = base64.b64decode(vault_file["ciphertext"])
    stored_hmac = base64.b64decode(vault_file["hmac"])
    
    _, key2, key3 = _derive_vault_keys(master_password, salt1, salt2, salt3)
    
    chacha = ChaCha20Poly1305(key2)
    key1 = chacha.decrypt(nonce2, wrapped_key1, None)
    
    h = hmac.HMAC(key3, hashes.SHA512())
    h.update(ciphertext1)
    computed_hmac = h.finalize()
    
    if not secrets.compare_digest(computed_hmac, stored_hmac):
        raise ValueError("Vault integrity check failed")
    
    aesgcm = AESGCM(key1)
    plaintext = aesgcm.decrypt(nonce1, ciphertext1, None)
    return json.loads(plaintext.decode('utf-8'))

def vault_exists():
    return os.path.exists(VAULT_FILE)
