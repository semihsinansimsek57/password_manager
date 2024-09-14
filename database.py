import pysqlcipher3.dbapi2 as sqlite
import os
import logging
import hashlib
import base64
import secrets
from cryptography.fernet import Fernet
from utils import set_permissions

class Database:
    def __init__(self, master_password, db_path=".password_manager/passwords.db", iterations=200000):
        self.db_path = db_path
        self.iterations = iterations
        self.salt_encryption_key = self._generate_salt_encryption_key(master_password)  # Initialize salt_encryption_key first
        self.encryption_key = self._derive_key(master_password)
        self._ensure_db_exists()
        self._ensure_table_exists()  # Ensure the passwords table exists

    def _ensure_table_exists(self):
        try:
            with sqlite.connect(self.db_path) as conn:
                conn.execute(f"PRAGMA key = '{self.encryption_key.decode()}'")
                c = conn.cursor()
                c.execute('''CREATE TABLE IF NOT EXISTS passwords
                             (service text, username text, password text, salt blob)''')
                conn.commit()
        except Exception as e:
            logging.error("Error ensuring passwords table exists.")
            raise e

    def _derive_key(self, master_password):
        salt = self._get_salt()
        key = hashlib.pbkdf2_hmac("sha256", master_password.encode(), salt, self.iterations, dklen=32)
        return base64.urlsafe_b64encode(key)

    def _generate_salt_encryption_key(self, master_password):
        # Derive a key from the master password to ensure consistency
        key = hashlib.pbkdf2_hmac("sha256", master_password.encode(), b"salt_encryption", self.iterations, dklen=32)
        return base64.urlsafe_b64encode(key)

    def _encrypt_salt(self, salt):
        f = Fernet(self.salt_encryption_key)
        return f.encrypt(salt)

    def _decrypt_salt(self, encrypted_salt):
        f = Fernet(self.salt_encryption_key)
        return f.decrypt(encrypted_salt)

    def _get_salt(self):
        salt_path = ".password_manager/salt"
        if not os.path.exists(salt_path):
            salt = secrets.token_bytes(16)
            encrypted_salt = self._encrypt_salt(salt)
            with open(salt_path, "wb") as f:
                f.write(encrypted_salt)
            set_permissions(salt_path, 0o600)
        else:
            with open(salt_path, "rb") as f:
                encrypted_salt = f.read()
            salt = self._decrypt_salt(encrypted_salt)
        return salt

    def _ensure_db_exists(self):
        if not os.path.exists(".password_manager"):
            os.makedirs(".password_manager", mode=0o700)
        set_permissions(".password_manager", 0o700)
        if not os.path.exists(self.db_path):
            self.create_db()

    def create_db(self):
        try:
            with sqlite.connect(self.db_path) as conn:
                conn.execute(f"PRAGMA key = '{self.encryption_key.decode()}'")
                c = conn.cursor()
                c.execute('''CREATE TABLE passwords
                             (service text, username text, password text, salt blob)''')
                conn.commit()
            set_permissions(self.db_path, 0o600)
        except Exception as e:
            logging.error("Error creating database.")
            raise e

    def execute_query(self, query, params=()):
        try:
            with sqlite.connect(self.db_path) as conn:
                conn.execute(f"PRAGMA key = '{self.encryption_key.decode()}'")
                c = conn.cursor()
                c.execute(query, params)
                conn.commit()
                return c.fetchall()
        except Exception as e:
            logging.error("Error executing query.")
            raise e