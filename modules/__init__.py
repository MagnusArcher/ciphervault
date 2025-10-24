from .password_gen import generate_password
from .password_check import check_password_strength
from .encryptor import encrypt_text
from .decryptor import decrypt_text
from .clipboard_utils import copy_to_clipboard

__all__ = [
    'generate_password',
    'check_password_strength',
    'encrypt_text',
    'decrypt_text',
    'copy_to_clipboard'
]

__version__ = '1.0.0'
__author__ = 'Magnus Archer'
