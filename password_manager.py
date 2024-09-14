import getpass
import os
import platform
import random
import secrets
import subprocess
import bcrypt
import logging
import time
import pyotp
from database import Database
from utils import generate_key, encrypt_password, decrypt_password, is_strong_password, secure_erase, set_permissions
import authenticator
import qrcode
from PIL import Image
import io
import re
from colorama import Fore, Style

class PasswordManager:
    def __init__(self, iterations=200000):
        self.master_password = None
        self.db = None
        self.iterations = iterations
        self.mfa_secret = None
        self._ensure_directory_exists()

    @staticmethod
    def _ensure_directory_exists():
        if not os.path.exists(".password_manager"):
            os.makedirs(".password_manager", mode=0o700)
        set_permissions(".password_manager", 0o700)

    @staticmethod
    def _set_permissions(path, mode):
        set_permissions(path, mode)

    def set_master_password(self, master_password):
        self.master_password = master_password  # Store the master password directly
        self.db = Database(master_password=self.master_password, iterations=self.iterations)
        # Prompt for MFA code after setting up MFA
        if not os.path.exists(".password_manager/mfa_secret.key"):
            self.mfa_secret = self.create_mfa_secret(".password_manager/mfa_secret.key")
            self.display_qr_code(self.mfa_secret)
            input(Fore.YELLOW + "Scan the QR code with your authenticator app and press Enter to continue...")
            mfa_code = input(Fore.YELLOW + "Enter the MFA code: ")
            if not self.verify_mfa_code(mfa_code):
                logging.error(Fore.RED + "Incorrect MFA code.")
                print(Fore.RED + "Incorrect MFA code.")
                exit()
        else:
            self.mfa_secret = self.get_mfa_secret()

    def get_master_password(self):
        master_password_file = ".password_manager/master_password.hash"
        if not os.path.exists(master_password_file):
            return self.create_master_password(master_password_file)
        master_password = self.verify_master_password(master_password_file)
        if not self.mfa_secret:
            self.mfa_secret = self.get_mfa_secret()
        if not self.verify_mfa_code_static():
            logging.error(Fore.RED + "Incorrect MFA code.")
            print(Fore.RED + "Incorrect MFA code.")
            exit()
        return master_password

    @staticmethod
    def get_mfa_secret():
        mfa_secret_file = ".password_manager/mfa_secret.key"
        with open(mfa_secret_file, "r") as f:
            return f.read().strip()

    @staticmethod
    def create_mfa_secret(mfa_secret_file):
        secret = pyotp.random_base32()  # Use pyotp to generate a random base32 secret
        with open(mfa_secret_file, "w") as f:
            f.write(secret)
        PasswordManager._set_permissions(mfa_secret_file, 0o600)
        return secret

    @staticmethod
    def display_qr_code(secret):
        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(name="user@example.com", issuer_name="PasswordManager")
        qr = qrcode.make(uri)
        # Convert the QR code to an image and display it
        with io.BytesIO() as output:
            qr.save(output, format="PNG")
            output.seek(0)  # Reset the stream position to the beginning
            image = Image.open(output)
            image_path = "/tmp/qr_code.png"
            image.save(image_path)

            # Determine the platform and use appropriate command
            if platform.system() == "Linux":
                try:
                    subprocess.run(["eog", image_path], stderr=subprocess.DEVNULL)
                except FileNotFoundError:
                    # Save the image to current directory if eog is not available
                    image.save("qr_code.png")
            elif platform.system() == "Darwin":  # macOS
                subprocess.run(["open", image_path], stderr=subprocess.DEVNULL)
            elif platform.system() == "Windows":
                subprocess.run(["start", image_path], shell=True, stderr=subprocess.DEVNULL)

    @staticmethod
    def create_master_password(master_password_file):
        try:
            while True:
                master = getpass.getpass(Fore.YELLOW + "Create a master password: ")
                if is_strong_password(master):
                    break
                else:
                    print(Fore.RED + "Password must be at least 8 characters long, include an uppercase letter, a lowercase letter, a number, and a special character.")
            hashed = bcrypt.hashpw(master.encode(), bcrypt.gensalt())
            with open(master_password_file, "wb") as f:
                f.write(hashed)
            PasswordManager._set_permissions(master_password_file, 0o600)
            return master
        except Exception as e:
            logging.error(Fore.RED + "Error creating master password.")
            raise e

    @staticmethod
    def verify_master_password(master_password_file):
        retry_limit = 3
        attempts = 0
        with open(master_password_file, "rb") as f:
            stored_master = f.read()
        while attempts < retry_limit:
            try:
                master = getpass.getpass(Fore.YELLOW + "Enter the master password to continue: ")
                if bcrypt.checkpw(master.encode(), stored_master):
                    return master
                else:
                    logging.warning(Fore.RED + "Incorrect master password.")
                    print(Fore.RED + "Incorrect master password.")
                attempts += 1
                backoff_time = (2 ** attempts) + random.uniform(0, 1)  # Exponential backoff with jitter
                time.sleep(backoff_time)
            except Exception as e:
                logging.error(Fore.RED + "Error verifying master password.")
                exit()
        logging.error(Fore.RED + "Exceeded maximum retry limit for master password.")
        print(Fore.RED + "Exceeded maximum retry limit. Exiting...")
        exit()

    def verify_mfa_code(self, code):
        totp = pyotp.TOTP(self.mfa_secret)
        return totp.verify(code)

    @staticmethod
    def verify_mfa_code_static():
        mfa_secret_file = ".password_manager/mfa_secret.key"
        with open(mfa_secret_file, "r") as f:
            mfa_secret = f.read().strip()
        totp = pyotp.TOTP(mfa_secret)
        mfa_code = input(Fore.YELLOW + "Enter the MFA code: ")
        return totp.verify(mfa_code)

    @staticmethod
    def validate_input(input_value, input_type):
        if input_type == "service":
            if not re.match(r"^[a-zA-Z0-9_-]+$", input_value):
                raise ValueError(Fore.RED + "Invalid service name.")
        elif input_type == "username":
            # Username can contain letters, numbers, periods, underscores, and hyphens, also it could be an email address
            if not re.match(r"^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", input_value):
                raise ValueError(Fore.RED + "Invalid username.")
        elif input_type == "password":
            if not is_strong_password(input_value):
                raise ValueError(Fore.RED + "Password must be at least 8 characters long, include an uppercase letter, a lowercase letter, a number, and a special character.")
        else:
            raise ValueError(Fore.RED + "Invalid input type.")

    def add_password(self, service, username, password):
        try:
            self.validate_input(service, "service")
            self.validate_input(username, "username")
            self.validate_input(password, "password")
            salt = secrets.token_bytes(16)
            encrypted_password = encrypt_password(password, self.master_password, salt)
            self.db.execute_query("INSERT INTO passwords (service, username, password, salt) VALUES (?, ?, ?, ?)", (service, username, encrypted_password, salt))
            logging.info(Fore.GREEN + f"Password added for service: {service}")
        except Exception as e:
            logging.error(Fore.RED + "Error adding password.")
            raise e

    def get_password(self, service):
        try:
            self.validate_input(service, "service")
            result = self.db.execute_query("SELECT username, password, salt FROM passwords WHERE service = ?", (service,))
            if result:
                username, encrypted_password, salt = result[0]
                password = decrypt_password(encrypted_password, self.master_password, salt)
                return username, password
            else:
                raise ValueError(Fore.RED + "No password found for the given service.")
        except Exception as e:
            logging.error(Fore.RED + "Error retrieving password.")
            raise e

    def delete_password(self, service):
        try:
            self.validate_input(service, "service")
            self.db.execute_query("DELETE FROM passwords WHERE service = ?", (service,))
            logging.info(Fore.GREEN + f"Password deleted for service: {service}")
        except Exception as e:
            logging.error(Fore.RED + "Error deleting password.")
            raise e

    def list_passwords(self):
        try:
            result = self.db.execute_query("SELECT service, username, password, salt FROM passwords")
            if result:
                passwords = []
                for row in result:
                    service, username, encrypted_password, salt = row
                    password = decrypt_password(encrypted_password, self.master_password, salt)
                    passwords.append({"service": service, "username": username, "password": password})
                return passwords
            else:
                return []
        except Exception as e:
            logging.error(Fore.RED + "Error listing passwords.")
            raise e

    def change_password(self, service, new_password):
        try:
            self.validate_input(service, "service")
            self.validate_input(new_password, "password")
            result = self.db.execute_query("SELECT username, salt FROM passwords WHERE service = ?", (service,))
            if result:
                username, salt = result[0]
                encrypted_password = encrypt_password(new_password, self.master_password, salt)
                self.db.execute_query("UPDATE passwords SET password = ? WHERE service = ?", (encrypted_password, service))
                logging.info(Fore.GREEN + f"Password changed for service: {service}")
            else:
                raise ValueError(Fore.RED + "No password found for the given service.")
        except Exception as e:
            logging.error(Fore.RED + "Error changing password.")
            raise e
