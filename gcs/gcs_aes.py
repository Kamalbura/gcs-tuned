# ==============================================================================
# gcs_aes.py
#
# GCS-Side Proxy for AES-256-GCM Cryptography
#
# PURPOSE:
#   - Listens for encrypted telemetry from the Drone.
#   - Decrypts it using AES-256-GCM.
#   - Forwards the plaintext MAVLink telemetry to the local GCS application.
#   - Listens for plaintext MAVLink commands from the local GCS application.
#   - Encrypts them using AES-256-GCM.
#   - Sends the encrypted commands to the Drone.
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

# SECURITY WARNING: This is a pre-shared key (PSK). In a real-world system,
# this should be derived from a PQC key exchange (like Kyber).
# Key must be 32 bytes for AES-256.
# Must be exactly 32 bytes for AES-256
PSK_AES = b'ThisIs_A_VerySecure_32ByteKey!!!'

## 2. CRYPTOGRAPHY FUNCTIONS ##

def encrypt_message(plaintext):
    """
    Encrypts a plaintext message using AES-256-GCM.
    A new random 12-byte nonce is generated for each message.
    The nonce is prepended to the ciphertext+tag returned by AESGCM.
    [nonce (12 bytes)] + [ciphertext || tag (16 bytes)]
    """
    nonce = os.urandom(NONCE_IV_SIZE)
    aesgcm = AESGCM(PSK_AES)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext

def decrypt_message(encrypted_message):
    """
    Decrypts an incoming message using AES-256-GCM.
    Splits the nonce, then decrypts and verifies.
    Returns plaintext or None if verification fails.
    """
    try:
        nonce = encrypted_message[:NONCE_IV_SIZE]
        ciphertext = encrypted_message[NONCE_IV_SIZE:]
        aesgcm = AESGCM(PSK_AES)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext
    except Exception as e:
        print(f"[AES GCS] Decryption failed: {e}")
        return None

## 3. NETWORKING THREADS ##

def drone_to_gcs_thread():
    """Listens for encrypted telemetry and forwards decrypted data to GCS app."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((GCS_HOST, PORT_GCS_LISTEN_ENCRYPTED_TLM))
    print(f"[AES GCS] Listening for encrypted drone telemetry on {GCS_HOST}:{PORT_GCS_LISTEN_ENCRYPTED_TLM}")

    while True:
        encrypted_data, addr = sock.recvfrom(4096)
        plaintext = decrypt_message(encrypted_data)
        if plaintext:
            sock.sendto(plaintext, (GCS_HOST, PORT_GCS_FORWARD_DECRYPTED_TLM))

def gcs_to_drone_thread():
    """Listens for plaintext commands and sends encrypted data to the drone."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((GCS_HOST, PORT_GCS_LISTEN_PLAINTEXT_CMD))
    print(f"[AES GCS] Listening for plaintext GCS commands on {GCS_HOST}:{PORT_GCS_LISTEN_PLAINTEXT_CMD}")

    while True:
        plaintext_data, addr = sock.recvfrom(4096)
        encrypted_command = encrypt_message(plaintext_data)
        sock.sendto(encrypted_command, (DRONE_HOST, PORT_DRONE_LISTEN_ENCRYPTED_CMD))

## 4. MAIN LOGIC ##

if __name__ == "__main__":
    print("--- GCS AES-256-GCM PROXY ---")
    thread1 = threading.Thread(target=drone_to_gcs_thread, daemon=True)
    thread2 = threading.Thread(target=gcs_to_drone_thread, daemon=True)
    thread1.start()
    thread2.start()
    thread1.join()
    thread2.join()
