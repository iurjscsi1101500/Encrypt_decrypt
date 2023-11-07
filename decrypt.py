import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from concurrent.futures import ProcessPoolExecutor

def decrypt_file_in_place(filename, key):
    with open(filename, 'rb') as file:
        salt = file.read(16)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            iterations=100000,
            salt=salt,
            length=32 + 16
        )

        key = kdf.derive(key)
        iv = key[-16:]

        cipher = Cipher(algorithms.AES(key[:-16]), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        encrypted_content = file.read()
        decrypted_content = decryptor.update(encrypted_content)

        with open(filename, 'wb') as decrypted_file:
            decrypted_file.write(decrypted_content)

def decrypt_folder(foldername, key):
    with ProcessPoolExecutor(max_workers=os.cpu_count() // 2) as executor:
        for item in os.scandir(foldername):
            if item.is_file():
                if item.name not in ["encrypt.py", "decrypt.py"]:
                    executor.submit(decrypt_file_in_place, item.path, key)
            elif item.is_dir():
                decrypt_folder(item.path, key)

def main():
    input_directory = "."
    key_bytes = str(input("Enter the key decrypt files and folders: ")).encode('utf-16')

    try:
        decrypt_folder(input_directory, key_bytes)
    except Exception as e:
        print(f'Decryption failed: {e}')

if __name__ == "__main__":
    main()
