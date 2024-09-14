import os
import base64
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils import generate_key, encrypt_password, decrypt_password, is_strong_password

# Test for utility functions
def test_generate_key():
    master = "test_master_password"
    salt = os.urandom(16)
    key = generate_key(master, salt)
    assert isinstance(key, bytes)
    assert len(base64.urlsafe_b64decode(key)) == 32

def test_encrypt_decrypt_password():
    master = "test_master_password"
    salt = os.urandom(16)
    password = "test_password"
    encrypted = encrypt_password(password, master, salt)
    decrypted = decrypt_password(encrypted, master, salt)
    assert decrypted == password

def test_is_strong_password():
    assert is_strong_password("StrongPass1!") == True
    assert is_strong_password("weak") == False
