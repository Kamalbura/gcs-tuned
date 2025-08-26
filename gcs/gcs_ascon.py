# ==============================================================================
# gcs_ascon.py
# GCS-Side Proxy for ASCON-128 Cryptography
# PURPOSE:
# - Listens for encrypted telemetry from the Drone.
# - Decrypts it using ASCON-128.
# - Forwards the plaintext MAVLink telemetry to the local GCS application.
# - Listens for plaintext MAVLink commands from the local GCS application.
# - Encrypts them using ASCON-128.
# - Sends the encrypted commands to the Drone.
# DEPENDENCIES:
# - pycryptodome (pip install pycryptodome)
# - ip_config.py (must be in the same directory or Python path)
# HOW TO RUN:
# This script is intended to be started by a manager process.
# To run standalone for testing: python gcs_ascon.py
# ==============================================================================

import socket
import threading
import os
from Crypto.Cipher import ASCON
from ip_config import *

# 1. CONFIGURATION
# SECURITY WARNING: This is a pre-shared key (PSK). In a real-world system,
# this key should be generated dynamically and exchanged securely, for example,
# using a Post-Quantum Key Encapsulation Mechanism (KEM) like Kyber.
# For this example, we use a static key for simplicity.
# Key must be 16 bytes for ASCON-128.

PSK_ASCON = b'ThisIsA_16ByteKey'

# 2. CRYPTOGRAPHY FUNCTIONS

def encrypt_message(plaintext):
    """
    Encrypts a plaintext message using ASCON-128.
    A new random nonce is generated for each message for security.
    The nonce is prepended to the ciphertext.
    [nonce (16 bytes)] + [ciphertext + tag]
    """
    nonce = os.urandom(16) # ASCON uses a 16-byte nonce
    cipher = ASCON.new(key=PSK_ASCON, mode=ASCON.MODE_EAX, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return nonce + ciphertext + tag

def decrypt_message(encrypted_message):
    """
    Decrypts an incoming message using ASCON-128.
    Splits the nonce from the message, then decrypts and verifies.
    Returns the plaintext or None if verification fails.
    """
    try:
        nonce = encrypted_message[:16]
        ciphertext_with_tag = encrypted_message[16:]
        cipher = ASCON.new(key=PSK_ASCON, mode=ASCON.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext_with_tag[:-16], ciphertext_with_tag[-16:])
        return plaintext
    except (ValueError, KeyError) as e:
        print(f"[ASCON GCS] Decryption failed: {e}")
        return None

# 3. NETWORKING THREADS

def drone_to_gcs_thread():
    """
    - Listens for encrypted telemetry from the Drone.
    - Decrypts the message.
    - Forwards plaintext to the local GCS application.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((GCS_HOST, PORT_GCS_LISTEN_ENCRYPTED_TLM))
    print(f"[ASCON GCS] Listening for encrypted drone telemetry on {GCS_HOST}:{PORT_GCS_LISTEN_ENCRYPTED_TLM}")
    
    while True:
        encrypted_data, addr = sock.recvfrom(4096)
        plaintext = decrypt_message(encrypted_data)
        if plaintext:
            sock.sendto(plaintext, (GCS_HOST, PORT_GCS_FORWARD_DECRYPTED_TLM))

def gcs_to_drone_thread():
    """
    - Listens for plaintext commands from the local GCS application.
    - Encrypts the command.
    - Sends the encrypted command to the Drone.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((GCS_HOST, PORT_GCS_LISTEN_PLAINTEXT_CMD))
    print(f"[ASCON GCS] Listening for plaintext GCS commands on {GCS_HOST}:{PORT_GCS_LISTEN_PLAINTEXT_CMD}")
    
    while True:
        plaintext_data, addr = sock.recvfrom(4096)
        encrypted_command = encrypt_message(plaintext_data)
        sock.sendto(encrypted_command, (DRONE_HOST, PORT_DRONE_LISTEN_ENCRYPTED_CMD))

# 4. MAIN LOGIC

if __name__ == "__main__":
    print("--- GCS ASCON PROXY ---")
    
    thread1 = threading.Thread(target=drone_to_gcs_thread, daemon=True)
    thread2 = threading.Thread(target=gcs_to_drone_thread, daemon=True)

    thread1.start()
    thread2.start()

    thread1.join()
    thread2.join()
