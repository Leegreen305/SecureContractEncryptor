
import os
import argparse
import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# === Logging Function ===
def log_event(message):
    os.makedirs("logs", exist_ok=True)
    with open("logs/activity.log", "a") as log:
        log.write(f"[{datetime.datetime.now()}] {message}\n")

# === Key/IV Handling ===
def save_key_iv(key, iv):
    with open("encryption_key.bin", "wb") as kf:
        kf.write(key)
    with open("encryption_iv.bin", "wb") as vf:
        vf.write(iv)
    log_event("Key and IV saved.")

def load_key_iv():
    with open("encryption_key.bin", "rb") as kf:
        key = kf.read()
    with open("encryption_iv.bin", "rb") as vf:
        iv = vf.read()
    return key, iv

# === Encryption ===
def encrypt_file(file_path):
    with open(file_path, 'rb') as f:
        data = f.read()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    key = os.urandom(32)  # AES-256 key
    iv = os.urandom(16)   # 128-bit IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    encrypted_path = file_path + ".enc"
    with open(encrypted_path, 'wb') as ef:
        ef.write(encrypted_data)

    save_key_iv(key, iv)
    log_event(f"Encrypted {file_path} -> {encrypted_path}")
    print(f"✅ Encrypted file saved as: {encrypted_path}")

# === Decryption ===
def decrypt_file(encrypted_path):
    with open(encrypted_path, 'rb') as ef:
        encrypted_data = ef.read()

    key, iv = load_key_iv()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()

    output_path = encrypted_path.replace('.enc', '_decrypted')
    with open(output_path, 'wb') as df:
        df.write(data)

    log_event(f"Decrypted {encrypted_path} -> {output_path}")
    print(f"✅ Decrypted file saved as: {output_path}")

# === Main CLI ===
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Secure Contract Encryptor Tool")
    parser.add_argument("action", choices=["encrypt", "decrypt"], help="Choose to encrypt or decrypt a file.")
    parser.add_argument("file", help="Path to the file.")

    args = parser.parse_args()

    if args.action == "encrypt":
        encrypt_file(args.file)
    elif args.action == "decrypt":
        decrypt_file(args.file)



