from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from getpass import getpass
import datetime
import base64
import json
import os

# class that manages the whole thing
class PasswordManager:
    # initialising values
    def __init__(self, vault_file="vault.json"):
        self.vault_file = vault_file
        self.vault = {}
        self.salt = None
        self.key = None

    # using PBKDF2HMAC to "blend" the password iterations times with salt key
    def derive_key(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        # turn it into a bytes key
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    def encrypt_data(self, data: str, key: bytes) -> bytes:
        f = Fernet(key)
        return f.encrypt(data.encode())
    
    def decrypt_data(self, encrypted_data: bytes, key: bytes) -> str:
        f = Fernet(key)
        return f.decrypt(encrypted_data).decode()
    
    def _create_entry(self, service: str, username: str, password: str, notes="") -> dict:
        current_time = datetime.now()
        entry = {"service": service,
                 "user": username,
                 "pass": password,
                 "notes": notes,
                 "timestamp": current_time}
        return entry
    
    def _encrypt_entry(self, entry_dict: dict, key: bytes) -> dict:
        enc_entry = {}
        for type, entry in entry_dict.items():
            if(type == "service"):
                enc_entry[type] = entry
            else:
                enc_entry[type] = self.encrypt_data(entry, key)
        return enc_entry
    
    def _decrypt_entry(self, enc_entry: dict, key: bytes) -> dict:
        dec_entry = {}
        for type, entry in enc_entry.items():
            if(type == "service"):
                dec_entry[type] = entry
            else:
                dec_entry[type] = self.decrypt_data(entry, key)
        return dec_entry
    
    def save_vault(self):
        json_vault = {}
        for service, entry_dict in self.vault.items():
            json_vault[service] = {}

            for name, value in entry_dict.items():
                if isinstance(value, bytes):
                    json_vault[service][name] = \
                        base64.b64encode(value).decode('utf-8')
                else:
                    json_vault[service][name] = value
        
        # create complete data package
        complete_data = {
            "metadata": {
                "salt": base64.b64encode(self.salt).decode('utf-8'),
                "iterations": 480000,
                "version": "1.0",
                "created": datetime.now().isoformat()
                },
                "vault": json_vault # actual encrypted passwords
            }
        # convert complete package to JSON string
        json_string = json.dumps(complete_data, indent=2)
        # encrypt entire JSON string
        enc_bytes = self.encrypt_data(json_string, self.key)
        # write encrypted bytes to file
        with open(self.vault_file, 'wb') as f: # 'wb' = write binary
            f.write(enc_bytes)






    
if __name__ == "__main__":
    test_dict = {"gmail": {"user": "test@test.com", "pass": "mypass123"}}
    json_str = json.dumps(test_dict, indent=1)
    print(json_str)