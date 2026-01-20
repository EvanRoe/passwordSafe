from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64
import json
import os

class PasswordManager:
    def __init__(self, vault_file="vault.json"):
        self.vault_file = vault_file
        self.vault = {}

    def derive_key(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    def encrypt_data(self, data: str, key: bytes) -> bytes:
        f = Fernet(key)
        return f.encrypt(data.encode())
    
    def decrypt_data(self, encrypted_data: bytes, key: bytes) -> str:
        f = Fernet(key)
        return f.decrypt(encrypted_data).decode()
    
if __name__ == "__main__":
    pm = PasswordManager()

    salt = os.urandom(16)
    test_password = input("Enter test master password: ")

    key = pm.derive_key(test_password, salt)
    print(f"Key derived: {key[:10]}...")

    test_secret = "MyPassword123"
    encrypted = pm.encrypt_data(test_secret, key)
    print(f"Encrypted: {encrypted[:20]}...")

    decrypted = pm.decrypt_data(encrypted, key)
    print(f"Decrypted: {decrypted}")
    print(f"Match: {test_secret == decrypted}")