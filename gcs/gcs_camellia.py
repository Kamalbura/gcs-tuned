# ==============================================================================
# gcs_camellia.py
#
# GCS-Side Proxy for Camellia Cryptography (CBC Mode)
#
# PURPOSE:
#   Implements the GCS-side logic for Camellia encryption. It uses the
#   CustomCamelliaCipher class from your previous work, which is an excellent
#   way to leverage the `cryptography` library's backend.
#
# SECURITY WARNING:
#   This implementation uses CBC mode, which provides confidentiality but NOT
#   authenticity. An attacker could potentially modify ciphertext without
#   being detected. For a production system, you MUST add a Message
#   Authentication Code (e.g., HMAC-SHA256) to each message.
#
# DEPENDENCIES:
#   - cryptography (pip install cryptography)
#   - ip_config.py
#   - camellia.py (Your custom implementation)
# ==============================================================================

import socket
import threading
import os
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from ip_config import *

## 1. YOUR CUSTOM CAMELLIA IMPLEMENTATION ##
# This is based on the high-quality class you provided.
class CustomCamelliaCipher:
    def __init__(self, key):
        if len(key) not in (16, 24, 32):
            raise ValueError("Key must be 16, 24, or 32 bytes.")
        self.key = key
        self.block_size = 128  # Camellia block size is 128 bits (16 bytes)

    def encrypt(self, plaintext, iv):
        padder = PKCS7(self.block_size).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        cipher = Cipher(algorithms.Camellia(self.key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        return encryptor.update(padded_data) + encryptor.finalize()

    def decrypt(self, ciphertext, iv):
        cipher = Cipher(algorithms.Camellia(self.key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = PKCS7(self.block_size).unpadder()
        return unpadder.update(padded_plaintext) + unpadder.finalize()

## 2. CONFIGURATION ##

# Pre-Shared Key. Must be 16, 24, or 32 bytes.
PSK_CAMELLIA = b'MySecureCamelliaKey_16Bytes12345'
camellia_cipher = CustomCamelliaCipher(PSK_CAMELLIA)

## 3. CRYPTOGRAPHY FUNCTIONS ##

def encrypt_message(plaintext):
    """Encrypts using Camellia-CBC, prepending a random 16-byte IV."""
    iv = os.urandom(16)  # CBC requires a 16-byte IV
    ciphertext = camellia_cipher.encrypt(plaintext, iv)
    return iv + ciphertext

def decrypt_message(encrypted_message):
    """Decrypts using Camellia-CBC after splitting the IV."""
    try:
        iv = encrypted_message[:16]
        ciphertext = encrypted_message[16:]
        return camellia_cipher.decrypt(ciphertext, iv)
    except Exception as e:
        print(f"[Camellia GCS] Decryption failed: {e}")
        return None

## 4. NETWORKING THREADS ##

def drone_to_gcs_thread():
    """Listens for encrypted telemetry and forwards decrypted data."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((GCS_HOST, PORT_GCS_LISTEN_ENCRYPTED_TLM))
    print(f"[Camellia GCS] Listening for drone telemetry on {GCS_HOST}:{PORT_GCS_LISTEN_ENCRYPTED_TLM}")
    while True:
        encrypted_data, addr = sock.recvfrom(4096)
        plaintext = decrypt_message(encrypted_data)
        if plaintext:
            sock.sendto(plaintext, (GCS_HOST, PORT_GCS_FORWARD_DECRYPTED_TLM))

def gcs_to_drone_thread():
    """Listens for plaintext commands and sends encrypted data."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((GCS_HOST, PORT_GCS_LISTEN_PLAINTEXT_CMD))
    print(f"[Camellia GCS] Listening for GCS commands on {GCS_HOST}:{PORT_GCS_LISTEN_PLAINTEXT_CMD}")
    while True:
        plaintext_data, addr = sock.recvfrom(4096)
        encrypted_command = encrypt_message(plaintext_data)
        sock.sendto(encrypted_command, (DRONE_HOST, PORT_DRONE_LISTEN_ENCRYPTED_CMD))

## 5. MAIN LOGIC ##
if __name__ == "__main__":
    print("--- GCS CAMELLIA PROXY ---")
    t1 = threading.Thread(target=drone_to_gcs_thread, daemon=True)
    t2 = threading.Thread(target=gcs_to_drone_thread, daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
