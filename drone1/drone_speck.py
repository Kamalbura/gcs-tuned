# ==============================================================================
# drone_speck.py
#
# Drone-Side Proxy for SPECK Lightweight Cryptography (CBC Mode)
#
# PURPOSE:
#   Mirrors the GCS-side SPECK proxy.
#
# SECURITY WARNING:
#   CBC mode requires a separate Message Authentication Code (MAC) for security.
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
try:
    from .drneha.new_git_repos.Speck.speck import Python_SPECK
except Exception:
    from drneha.new_git_repos.Speck.speck import Python_SPECK
from ip_config import *

## 1. CONFIGURATION ##
PSK_SPECK = b'MySecureSpeckKey'
IV_PLACEHOLDER = b'\x00' * 16

## 2. CRYPTOGRAPHY FUNCTIONS ##

def encrypt_message(plaintext):
    """Encrypts using SPECK-CBC, prepending a random 16-byte IV."""
    iv = os.urandom(16)
    cipher = Python_SPECK(key=PSK_SPECK, IV=iv)
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
        print(f"[SPECK Drone] Decryption failed: {e}")
        return None

## 3. NETWORKING THREADS ##

def telemetry_to_gcs_thread():
    """Listens for plaintext telemetry, encrypts, and sends to GCS."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((DRONE_HOST, PORT_DRONE_LISTEN_PLAINTEXT_TLM))
    print(f"[SPECK Drone] Listening for telemetry on {DRONE_HOST}:{PORT_DRONE_LISTEN_PLAINTEXT_TLM}")
    while True:
        plaintext_data, addr = sock.recvfrom(4096)
        encrypted_telemetry = encrypt_message(plaintext_data)
        sock.sendto(encrypted_telemetry, (GCS_HOST, PORT_GCS_LISTEN_ENCRYPTED_TLM))

def commands_from_gcs_thread():
    """Listens for encrypted commands, decrypts, and forwards to flight controller."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((DRONE_HOST, PORT_DRONE_LISTEN_ENCRYPTED_CMD))
    print(f"[SPECK Drone] Listening for GCS commands on {DRONE_HOST}:{PORT_DRONE_LISTEN_ENCRYPTED_CMD}")
    while True:
        encrypted_data, addr = sock.recvfrom(4096)
        plaintext_command = decrypt_message(encrypted_data)
        if plaintext_command:
            sock.sendto(plaintext_command, (DRONE_HOST, PORT_DRONE_FORWARD_DECRYPTED_CMD))

## 4. MAIN LOGIC ##
if __name__ == "__main__":
    print("--- DRONE SPECK PROXY ---")
    t1 = threading.Thread(target=telemetry_to_gcs_thread, daemon=True)
    t2 = threading.Thread(target=commands_from_gcs_thread, daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
