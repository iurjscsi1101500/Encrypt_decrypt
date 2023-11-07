import os
from concurrent.futures import ProcessPoolExecutor
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def encrypt_file(filename, key):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32 + 16
    )
    key = kdf.derive(key)
    iv = key[-16:]
    cipher = Cipher(algorithms.AES(key[:-16]), modes.CFB(iv), backend=default_backend())

    with open(filename, 'rb') as file:
        plaintext_content = file.read()

    encryptor = cipher.encryptor()
    encrypted_content = encryptor.update(plaintext_content) + encryptor.finalize()

    with open(filename, 'wb') as encrypted_file:
        encrypted_file.write(salt + encrypted_content)

def encrypt_folder(foldername, key):
    with ProcessPoolExecutor(max_workers=os.cpu_count() // 2) as executor:
        file_list = []
        for item in os.scandir(foldername):
            if item.is_file() and item.name not in ["encrypt.py", "decrypt.py"]:
                file_list.append(item.path)
            elif item.is_dir():
                encrypt_folder(item.path, key)

        for file_path in file_list:
            executor.submit(encrypt_file, file_path, key)

def main():
    input_directory = "."
    key_bytes = str(input("Enter a Key to encrypt files and folders: ")).encode('utf-16')

    try:
        encrypt_folder(input_directory, key_bytes)
    except Exception as e:
        print(f'Encryption failed: {e}')

if __name__ == "__main__":
    main()
