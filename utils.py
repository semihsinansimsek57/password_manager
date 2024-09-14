import hashlib
import base64
import logging
import re
from cryptography.fernet import Fernet
import os
import ctypes

def set_permissions(path, mode):
    try:
        os.chmod(path, mode)
    except Exception as e:
        logging.error(f"Error setting permissions for {path}.")
        raise e

def generate_key(master, salt, iterations=200000):
    key = hashlib.pbkdf2_hmac("sha256", master.encode(), salt, iterations, dklen=32)
    return base64.urlsafe_b64encode(key)

def encrypt_password(password, master, salt, iterations=200000):
    key = generate_key(master, salt, iterations)
    f = Fernet(key)
    encrypted = f.encrypt(password.encode())
    return encrypted

def decrypt_password(password, master, salt, iterations=200000):
    key = generate_key(master, salt, iterations)
    f = Fernet(key)
    decrypted = f.decrypt(password).decode()
    try:
        return decrypted
    finally:
        secure_erase(decrypted)  # Securely erase the decrypted password

def is_strong_password(password):
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    return True

def secure_erase(data):
    if isinstance(data, str):
        data = data.encode()
    length = len(data)
    buf = ctypes.create_string_buffer(length)
    ctypes.memset(buf, 0, length)
    ctypes.memmove(ctypes.addressof(buf), data, length)
    ctypes.memset(ctypes.addressof(buf), 0, length)