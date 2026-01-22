from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from getpass import getpass
from datetime import datetime
import base64
import json
import os
import sys

# class that manages the whole thing
class PasswordManager:
    # initialising values
    def __init__(self, vault_file="vault.json"):
        self.vault_file = vault_file
        self.vault = {}
        self.salt = None
        self.key = None

    # set up 
    def initialise(self):
        if not os.path.exists(self.vault_file):
            self.salt = os.urandom(16)

            while True:
                pw1 = getpass("Create a master password: ")
                pw2 = getpass("Once more cause you're stupid: ")

                if pw1 != pw2:
                    print("They don't match, try again.")
                    continue
                if len(pw1) < 6:
                    print("It has got to be longer bruh.")
                    continue
                break
            
            self.key = self.derive_key(pw1, self.salt)
            self.vault = {}
            self.save_vault()
            print(f"New vault created at {self.vault_file}")
            # clear password from memory
            pw1 = pw2 = "x" * len(pw1)
            return True
        return False

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
    
    # each password entry is a dict with other parts, kinda fun having all that data
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

    def load_vault(self):
        if not os.path.exists(self.vault_file):
            return False
      
        with open(self.vault_file, 'rb') as f:                
            enc_bytes = f.read()

        json_string = self.decrypt_data(enc_bytes, self.key)
        data = json.loads(json_string)
        # extract metadata
        self.salt = base64.b64decode(data["metadata"]["salt"])

        # convert vault data into bytes
        self.vault = {}
        for service, entry_dict in data["vault"].items():
            self.vault[service] = {}
            for name, value in entry_dict.items():
                if name == "service":
                    self.vault[service][name] = value
                else:
                    self.vault[service][name] = \
                    base64.b64decode(value)

    def load_metadata(self):
        if not os.path.exists(self.vault_file):
            return None
        with open(self.vault_file, 'rb') as f:                
            enc_bytes = f.read()

        json_string = self.decrypt_data(enc_bytes, self.key)
        data = json.loads(json_string)
        # return salt
        return data["metadata"]
    
    def run_menu(self):
        print("Password manager menu:\n1. Add 2. Get 3. List 4. Change/Delete 5. Exit\n")
        while True:
            service = input("Which service is needed: ")
            if service == 1:
                self._add_entry()
            elif service == 2:
                self._get_entry()
            elif service == 3:
                self._list_services()
            elif service == 4:
                self._change_del_entry()
            elif service == 5:
                print("Goodbye!\n")
                self._clear_sensitive_data()
                break
            else:
                print("Invalid input.\n")
    
    def _add_entry(self):
        service = input("Type the service name: ")
        username = input("Type the username of the account: ")
        password = getpass("Type in the password slowly: ")
        notes = input("Any notes for this entry?: ")
        new_entry = self._create_entry(service, username, password, notes)
        enc_entry = self._encrypt_entry(new_entry)
        self.vault[service] = enc_entry
        self.save_vault()

    def _get_entry(self):
        service = input("Which service do you need: ")
        enc_entry = self.vault[service]
        dec_entry = self._decrypt_entry(enc_entry, self.key)
        print(f"For {service}\nthe username is {dec_entry["username"]}\n \
              the password is {dec_entry["password"]} ")
        
    def _list_services(self):
        print("These are the passwords saved:\n")
        index = 1
        for service in self.vault:
            print(f"{index}. {service}\n")
            index += 1
    
    def _change_del_entry(self):
        option = input("Change(type 1) or delete(type 2) an entry (or 3 for the menu): ")
        if option == 1:
            pass
        elif option == 2:
            pass
        elif option == 3:
            self.run_menu()
        else:
            print("Type either 1 or 2 for change or delete respectively.")
            self._change_del_entry()
            

    

    
def main():
    pm = PasswordManager()

    if pm.initialise():
        print("Setup complete.")
    else:
        password = getpass("Bruh type in the master: ")
        # load salt from metadata
        metadata = pm.load_metadata()
        pm.salt = base64.b64decode(metadata["salt"])
        pm.key = pm.derive_key(password, pm.salt)

        # load the vault
        if pm.load_vault():
            pass
        else:
            print("Failed to unlock the vault?! wHO aRE yOU?")
            return
    pm.run_menu()
        