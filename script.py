import os
import secrets
import getpass
import base64
from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class Vault:
    def __init__(self):
        # Passwords are handled per-operation.
        self.iterations = 600_000  

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.iterations,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))

    def lock(self, file_path: Path, password: str):
        if not file_path.exists() or not file_path.is_file():
            print(f"Error: Target '{file_path}' does not exist or is not a file.")
            return

        # Replace the entire extension with .vault (e.g., secret.txt -> secret.vault)
        vault_path = file_path.with_name(file_path.stem + ".vault")
        
        if vault_path.exists():
            print(f"\Error: '{vault_path.name}' already exists. Please rename or move it.")
            return

        try:
            salt = secrets.token_bytes(16)
            key = self._derive_key(password, salt)
            fernet = Fernet(key)

            # --- PAYLOAD PACKING ---
            # 1. Get the original filename as bytes
            filename_bytes = file_path.name.encode('utf-8')
            # 2. Store the length of the filename in exactly 2 bytes
            filename_length_bytes = len(filename_bytes).to_bytes(2, byteorder='big')
            # 3. Read the actual file data
            file_data = file_path.read_bytes()
            
            # Combine them: [2 Bytes for Name Length] + [Filename Bytes] + [File Data]
            raw_payload = filename_length_bytes + filename_bytes + file_data
            
            # Encrypt the entire payload (hiding the original filename inside the encryption)
            encrypted_data = fernet.encrypt(raw_payload)
            
            # Write the salt + encrypted data
            with open(vault_path, 'wb') as v_file:
                v_file.write(salt)
                v_file.write(encrypted_data)
            
            # Secure shredding of original file
            file_path.write_bytes(os.urandom(len(file_data)))
            file_path.unlink()
            
            print(f"✅ 🔒 Locked & Shredded: {file_path.name} -> {vault_path.name}")

        except Exception as e:
            print(f"\Encryption failed: {e}")

    def unlock(self, vault_path: Path, password: str):
        if not vault_path.name.endswith(".vault"):
            print("\Error: Target must be a '.vault' file.")
            return
        if not vault_path.exists() or not vault_path.is_file():
            print(f"Error: Target '{vault_path}' does not exist.")
            return

        try:
            file_data = vault_path.read_bytes()
            if len(file_data) < 16:
                raise ValueError("File is corrupted or too small.")

            salt = file_data[:16]
            encrypted_data = file_data[16:]

            key = self._derive_key(password, salt)
            fernet = Fernet(key)

            # Decrypt the payload
            decrypted_payload = fernet.decrypt(encrypted_data)
            
            # --- PAYLOAD UNPACKING ---
            # 1. Read the first 2 bytes to find out how long the filename is
            filename_length = int.from_bytes(decrypted_payload[:2], byteorder='big')
            # 2. Extract the filename based on that length
            original_filename = decrypted_payload[2:2+filename_length].decode('utf-8')
            # 3. The rest is the actual file data
            original_file_data = decrypted_payload[2+filename_length:]
            
            # Reconstruct the original file path
            original_path = vault_path.parent / original_filename
            
            if original_path.exists():
                 print(f"Error: '{original_path.name}' already exists in this directory. Aborting to prevent overwrite.")
                 return

            original_path.write_bytes(original_file_data)
            vault_path.unlink()
            
            print(f"✅ 🔓 Unlocked: {original_path.name}")

        except InvalidToken:
            print("Error: Incorrect password or corrupted file.")
        except Exception as e:
            print(f"Decryption failed: {e}")

def main():
    print("=" * 50)
    print("  LOCAL CRYPTOGRAPHIC VAULT  ".center(50, "="))
    print("=" * 50)
    
    vault = Vault()
    
    while True:
        print("\n" + "-" * 30)
        print(" VAULT MENU ")
        print("-" * 30)
        print("[1] Lock a file (Encrypt & Shred)")
        print("[2] Unlock a file (Decrypt)")
        print("[3] Exit")
        
        choice = input("\nSelect an option (1-3): ").strip()
        
        if choice == '3':
            print("\nExiting Vault. Stay safe! 🛡️\n")
            break
            
        elif choice in ('1', '2'):
            file_input = input("Enter the file path: ").strip()
            
            # Remove surrounding quotes for drag-and-drop support
            if file_input.startswith('"') and file_input.endswith('"'):
                file_input = file_input[1:-1]
            elif file_input.startswith("'") and file_input.endswith("'"):
                file_input = file_input[1:-1]
                
            target_path = Path(file_input)
    
            file_password = getpass.getpass(f"Enter password for {target_path.name}: ")
            
            if choice == '1':
                vault.lock(target_path, file_password)
            elif choice == '2':
                vault.unlock(target_path, file_password)
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nForce quit detected. Exiting Vault. 🛡️")
