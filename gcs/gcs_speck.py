# ==============================================================================
# gcs_speck.py
#
# GCS-Side Proxy for SPECK Lightweight Cryptography (CBC Mode)
#
# PURPOSE:
#   Implements the GCS-side logic for SPECK encryption. It relies on your
#   custom `speck.py` module.
#
# SECURITY WARNING:
#   Like the Camellia example, this uses CBC mode which lacks authenticity.
#   A MAC (like HMAC) is required for a secure system.
#
# DEPENDENCIES:
#   - pycryptodome (for padding)
#   - ip_config.py
#   - speck.py (Your custom implementation must be in the same folder)
# ==============================================================================

import socket
import threading
import os
from Crypto.Util.Padding import pad, unpad
from speck import Python_SPECK # Assuming your class is named Python_SPECK
from ip_config import *

## 1. CONFIGURATION ##
PSK_SPECK = b'MySecureSpeckKey'  # Must match the drone's key
# The IV for CBC mode will be generated randomly for each message.
# The IV in the Python_SPECK class constructor is just an initial placeholder.
IV_PLACEHOLDER = b'\x00' * 16

## 2. CRYPTOGRAPHY FUNCTIONS ##

def encrypt_message(plaintext):
    """Encrypts using SPECK-CBC, prepending a random 16-byte IV."""
    iv = os.urandom(16)
    # The class seems to manage its IV state internally after initialization.
    # To encrypt each message with a new IV, we create a new cipher object.
    cipher = Python_SPECK(key=PSK_SPECK, IV=iv)
    # Pad the plaintext to be a multiple of the block size (16 bytes for Speck-128)
    padded_plaintext = pad(plaintext, cipher.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    return iv + ciphertext

def decrypt_message(encrypted_message):
    """Decrypts using SPECK-CBC after splitting the IV."""
    try:
        iv = encrypted_message[:16]
        ciphertext = encrypted_message[16:]
        cipher = Python_SPECK(key=PSK_SPECK, IV=iv)
        decrypted_padded = cipher.decrypt(ciphertext)
        return unpad(decrypted_padded, cipher.block_size)
    except Exception as e:
        print(f"[SPECK GCS] Decryption failed: {e}")
        return None

## 3. NETWORKING THREADS ##

def drone_to_gcs_thread():
    """Listens for encrypted telemetry and forwards decrypted data."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((GCS_HOST, PORT_GCS_LISTEN_ENCRYPTED_TLM))
    print(f"[SPECK GCS] Listening for drone telemetry on {GCS_HOST}:{PORT_GCS_LISTEN_ENCRYPTED_TLM}")
    while True:
        encrypted_data, addr = sock.recvfrom(4096)
        plaintext = decrypt_message(encrypted_data)
        if plaintext:
            sock.sendto(plaintext, (GCS_HOST, PORT_GCS_FORWARD_DECRYPTED_TLM))

def gcs_to_drone_thread():
    """Listens for plaintext commands and sends encrypted data."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((GCS_HOST, PORT_GCS_LISTEN_PLAINTEXT_CMD))
    print(f"[SPECK GCS] Listening for GCS commands on {GCS_HOST}:{PORT_GCS_LISTEN_PLAINTEXT_CMD}")
    while True:
        plaintext_data, addr = sock.recvfrom(4096)
        encrypted_command = encrypt_message(plaintext_data)
        sock.sendto(encrypted_command, (DRONE_HOST, PORT_DRONE_LISTEN_ENCRYPTED_CMD))

## 4. MAIN LOGIC ##
if __name__ == "__main__":
    print("--- GCS SPECK PROXY ---")
    t1 = threading.Thread(target=drone_to_gcs_thread, daemon=True)
    t2 = threading.Thread(target=gcs_to_drone_thread, daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
