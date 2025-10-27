import pytest
from modules.encryptor import encrypt_text
from modules.decryptor import decrypt_text

def test_encrypt_decrypt():
    plaintext = "Hello, World!"
    result = encrypt_text(plaintext)
    decrypted = decrypt_text(result['encrypted'], result['key'])
    assert decrypted['success']
    assert decrypted['decrypted'] == plaintext

def test_encrypt_with_custom_key():
    plaintext = "Secret message"
    key = "MySecretKey123"
    result = encrypt_text(plaintext, key=key)
    assert result['key'] == key
