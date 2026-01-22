# =============== IMPORTS ===============
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import InvalidToken
from cryptography.fernet import Fernet
from datetime import datetime
from getpass import getpass
import threading
import pyperclip
import platform
import base64
import time
import json
import sys
import os
import gc

# =============== UTILITY FUNCTIONS ===============
def clear_terminal():
    os.system('cls' if platform.system() == "Windows" else 'clear')

# =============== PASSWORD MANAGER CLASS ===============
class PasswordManager:

# =============== INITIALISATION ===============
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
    
# =============== CORE ENCRYPTION ===============

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
    
# =============== ENTRY MANAGEMENT ===============
    
    # each password entry is a dict with other parts, kinda fun having all that data
    def _create_entry(self, service: str, username: str, password: str, notes="") -> dict:
        current_time = datetime.now().isoformat()
        entry = {"service": service,
                 "username": username,
                 "password": password,
                 "notes": notes,
                 "timestamp": current_time}
        return entry
    
    def _encrypt_entry(self, entry_dict: dict, key: bytes) -> dict:
        enc_entry = {}
        for name, value in entry_dict.items():
            if(name == "service"):
                enc_entry[name] = value
            else:
                enc_entry[name] = self.encrypt_data(value, key)
        return enc_entry
    
    def _decrypt_entry(self, enc_entry: dict, key: bytes) -> dict:
        dec_entry = {}
        for name, value in enc_entry.items():
            if(name == "service"):
                dec_entry[name] = value
            else:
                dec_entry[name] = self.decrypt_data(value, key)
        return dec_entry
    
# =============== FILE OPERATIONS ===============
    
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
            # write salt length and salt
            f.write(len(self.salt).to_bytes(4, 'big'))
            f.write(self.salt)
            f.write(enc_bytes)

    def load_vault(self):
        if not os.path.exists(self.vault_file):
            return False

        try:
            with open(self.vault_file, 'rb') as f: 
                # read salt and salt length
                salt_len = int.from_bytes(f.read(4), 'big')
                self.salt = f.read(salt_len)               
                enc_bytes = f.read()

            json_string = self.decrypt_data(enc_bytes, self.key)
            data = json.loads(json_string)

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
            return True
        
        except Exception as e:
            self.key = None
            self.salt = None
            self.vault = {}

            if isinstance(e, InvalidToken):
                print("Wrong master password!\n")
            else:
                print(f"Failed to load vault: {e}")
            return False
        
# =============== USER INTERFACE ===============
    
    def run_menu(self):
        while True:
            print("Password manager menu:\n1. Add 2. Get 3. List 4. Change/Delete 5. Exit\n")
            service = input("Which menu option is needed(integers): ")
            if service == "1":
                clear_terminal()
                self._add_entry()
            elif service == "2":
                clear_terminal()
                self._get_entry()
            elif service == "3":
                clear_terminal()
                self._list_services()
            elif service == "4":
                clear_terminal()
                self._change_del_entry()
            elif service == "5":
                clear_terminal()
                print("Goodbye!\n")
                self._clear_sensitive_data()
                break
            else:
                print("Invalid input.\n")
    
    def _add_entry(self):
        service = input("Type the service name: ")
        if not service:
            print("Service name required.\n")
            return
        
        if service in self.vault:
            print("Going to change menu.\n")
            self._change_del_entry()
            return

        username = input("Type the username of the account: ")
        if not username:
            print("Username required.\n")
            return
        
        password = getpass("Type in the password slowly: ")
        if not password:
            print("Password required.\n")
            return
         
        notes = input("Any notes for this entry?: ").strip()
        new_entry = self._create_entry(service, username, password, notes)
        enc_entry = self._encrypt_entry(new_entry, self.key)
        self.vault[service] = enc_entry
        self.save_vault()
        print(f"{service} saved successfully!")

    def _get_entry(self):
        if not self.vault:
            print("Vault is empty.\n")
            return
        
        services = list(self.vault.keys())
        print("These are the passwords saved:\n")
        
        for i, service in enumerate(services, 1):
            print(f"{i}. {service}\n")
        
        # get selection by number
        while True:
            try:
                selection = input("Enter the number of the service: ").strip()
                index = int(selection) - 1
                
                if 0 <= index < len(services):
                    service = services[index]
                    break
                else:
                    print("Enter one of the numbers listed.\n")
            except ValueError:
                print("Please enter a valid number.\n")
        
        enc_entry = self.vault[service]
        dec_entry = self._decrypt_entry(enc_entry, self.key)
        print(f"For {service}\nthe username is {dec_entry['username']}\n \
              the password is {dec_entry['password']}\n")
        print(f"Added: {datetime.fromisoformat(dec_entry['timestamp'])}")

        if dec_entry['notes']:
            print(f"the notes are {dec_entry['notes']}\n")

        while True:
            answer = input("Copy password to clipboard (y/n): ")

            if answer == "y":
                pyperclip.copy(dec_entry["password"])
                break
            elif answer == "n":
                break
            else:
                print("Invalid input, try again.\n")

        self._setup_clipboard_timeout(dec_entry["password"])
        
    def _list_services(self):
        if not self.vault:
            print("Vault is empty.\n")
            return
        
        print("These are the passwords saved:\n")
        index = 1
        for service in self.vault:
            print(f"{index}. {service}\n")
            index += 1
    
    def _change_del_entry(self):
        if not self.vault:
            print("Vault is empty.\n")
            return
        
        while True:
            option = input("Change(type 1) or delete(type 2) an entry (or 3 for the menu): ")

            if option == "1":
                self._list_services()
                service = input("What service do you want to change: ")

                if not service or service not in self.vault:
                    print("Correct service name is needed.\n")
                    return
                
                enc_entry = self.vault[service]
                dec_entry = self._decrypt_entry(enc_entry, self.key)
                new_password = getpass("What is the new password: ")

                if not new_password:
                    print("Password is required.\n")
                    return

                dec_entry["password"] = new_password
                enc_entry = self._encrypt_entry(dec_entry, self.key)
                self.vault[service] = enc_entry
                self.save_vault()
                print(f"{service} changed successfully.\n")
                return

            elif option == "2":
                self._list_services()
                service = input("What service do you want to delete: ")

                if not service or service not in self.vault:
                    print("Correct service name is needed.\n")
                    return
                
                del self.vault[service]
                self.save_vault()
                print(f"{service} deleted successfully.\n")
                return

            elif option == "3":
                return

            else:
                print("Type either 1 or 2 for change or delete respectively, or 3 to exit.")

    def _setup_clipboard_timeout(self, text_to_clear, timeout_seconds=30):
        # store password in mutable list
        password_ref = [text_to_clear]

        def clear_after_delay(pw_list, seconds):
            time.sleep(seconds)
            # check if clipboard still has the password
            try:
                if pyperclip.paste() == pw_list[0]:
                    pyperclip.copy("")
            except:
                pass
            finally:
                # clear the text from thread memory
                if pw_list and pw_list[0]:
                    pw_list[0] = "x" * len(pw_list[0])
                    pw_list.clear()

        timer = threading.Thread(target=clear_after_delay,
                                 args=(password_ref, timeout_seconds))
        timer.daemon = True # thread dies when main program exits
        timer.start()
        return
    
    def _clear_sensitive_data(self):
        self.key = None
        self.vault = {}
        gc.collect()
        print("Sensitive data cleared from memory.\n")
            
# =============== MAIN FUNCTIONS ===============
    
def main():
    pm = PasswordManager()

    if pm.initialise():
        print("Setup complete.")
    else:
        for attempt in range(3):
            password = getpass("Bruh type in the master: ")
            # load salt from metadata
            if os.path.exists(pm.vault_file):
                with open(pm.vault_file, 'rb') as f:
                    salt_len = int.from_bytes(f.read(4), 'big')
                    pm.salt = f.read(salt_len)
            pm.key = pm.derive_key(password, pm.salt)

            # load the vault
            if pm.load_vault():
                break
            else:
                if attempt == 2:
                    print("Too many failed attempts! wHO aRE yOU?")
                    return
        password = "x" * len(password)
    pm.run_menu()

if __name__ == "__main__":
    main()
        