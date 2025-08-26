# ==============================================================================
# drone_aes.py
#
# Drone-Side Proxy for AES-256-GCM Cryptography
#
# PURPOSE:
#   - Listens for plaintext MAVLink telemetry from the flight controller.
#   - Encrypts it using AES-256-GCM.
#   - Sends the encrypted telemetry to the GCS.
#   - Listens for encrypted commands from the GCS.
#   - Decrypts them using AES-256-GCM.
#   - Forwards the plaintext commands to the flight controller.
#
# DEPENDENCIES:
#   - cryptography (pip install cryptography)
#   - ip_config.py
# ==============================================================================

import socket
import threading
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from ip_config import *

## 1. CONFIGURATION ##

# SECURITY WARNING: This key MUST be identical to the one in gcs_aes.py.
PSK_AES = b'ThisIs_A_VerySecure_32ByteKey!!'

## 2. CRYPTOGRAPHY FUNCTIONS ##

def encrypt_message(plaintext):
    """Encrypts using AES-256-GCM, prepending a random 12-byte nonce."""
    nonce = os.urandom(NONCE_IV_SIZE)
    aesgcm = AESGCM(PSK_AES)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext

def decrypt_message(encrypted_message):
    """Decrypts using AES-256-GCM after splitting the nonce."""
    try:
        nonce = encrypted_message[:NONCE_IV_SIZE]
        ciphertext = encrypted_message[NONCE_IV_SIZE:]
        aesgcm = AESGCM(PSK_AES)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext
    except Exception as e:
        print(f"[AES Drone] Decryption failed: {e}")
        return None

## 3. NETWORKING THREADS ##

def telemetry_to_gcs_thread():
    """Listens for plaintext telemetry, encrypts, and sends to GCS."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((DRONE_HOST, PORT_DRONE_LISTEN_PLAINTEXT_TLM))
    print(f"[AES Drone] Listening for plaintext telemetry on {DRONE_HOST}:{PORT_DRONE_LISTEN_PLAINTEXT_TLM}")

    while True:
        plaintext_data, addr = sock.recvfrom(4096)
        encrypted_telemetry = encrypt_message(plaintext_data)
        sock.sendto(encrypted_telemetry, (GCS_HOST, PORT_GCS_LISTEN_ENCRYPTED_TLM))

def commands_from_gcs_thread():
    """Listens for encrypted commands, decrypts, and forwards to flight controller."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((DRONE_HOST, PORT_DRONE_LISTEN_ENCRYPTED_CMD))
    print(f"[AES Drone] Listening for encrypted GCS commands on {DRONE_HOST}:{PORT_DRONE_LISTEN_ENCRYPTED_CMD}")

    while True:
        encrypted_data, addr = sock.recvfrom(4096)
        plaintext_command = decrypt_message(encrypted_data)
        if plaintext_command:
            sock.sendto(plaintext_command, (DRONE_HOST, PORT_DRONE_FORWARD_DECRYPTED_CMD))

## 4. MAIN LOGIC ##

if __name__ == "__main__":
    print("--- DRONE AES-256-GCM PROXY ---")
    thread1 = threading.Thread(target=telemetry_to_gcs_thread, daemon=True)
    thread2 = threading.Thread(target=commands_from_gcs_thread, daemon=True)
    thread1.start()
    thread2.start()
    thread1.join()
    thread2.join()
