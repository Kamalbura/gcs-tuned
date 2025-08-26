# ==============================================================================
# gcs_ascon.py
#
# GCS-Side Proxy for ASCON-128 Cryptography
#
# PURPOSE:
#   - Listens for encrypted telemetry from the Drone.
#   - Decrypts it using ASCON-128.
#   - Forwards the plaintext MAVLink telemetry to the local GCS application.
#   - Listens for plaintext MAVLink commands from the local GCS application.
#   - Encrypts them using ASCON-128.
#   - Sends the encrypted commands to the Drone.
#
# DEPENDENCIES:
#   - pycryptodome (pip install pycryptodome)
#   - ip_config.py (must be in the same directory or Python path)
#
# HOW TO RUN:
#   This script is intended to be started by a manager process.
#   To run standalone for testing: python gcs_ascon.py
# ==============================================================================

import socket
import threading
import os
from drneha.ascon.ascon import ascon_encrypt, ascon_decrypt
from ip_config import *

## 1. CONFIGURATION ##

# SECURITY WARNING: This is a pre-shared key (PSK). In a real-world system,
# this key should be generated dynamically and exchanged securely, for example,
# using a Post-Quantum Key Encapsulation Mechanism (KEM) like Kyber.
# For this example, we use a static key for simplicity.
# ASCON-128 uses a 16-byte key and a 16-byte nonce
# Exactly 16 bytes
PSK_ASCON = b'ThisIsA16ByteKey'
ASCON_NONCE_SIZE = 16

## 2. CRYPTOGRAPHY FUNCTIONS ##

def encrypt_message(plaintext):
    """
    Encrypts a plaintext message using ASCON-128 (AEAD).
    Frames as [nonce (16)] + [ciphertext || tag (16)].
    """
    nonce = os.urandom(ASCON_NONCE_SIZE)
    ct_tag = ascon_encrypt(PSK_ASCON, nonce, b"", plaintext, variant="Ascon-128")
    return nonce + ct_tag

def decrypt_message(encrypted_message):
    """
    Decrypts an incoming message using ASCON-128.
    Splits the 16-byte nonce and verifies the tag.
    Returns plaintext or None on failure.
    """
    try:
        nonce = encrypted_message[:ASCON_NONCE_SIZE]
        ct_tag = encrypted_message[ASCON_NONCE_SIZE:]
        plaintext = ascon_decrypt(PSK_ASCON, nonce, b"", ct_tag, variant="Ascon-128")
        return plaintext
    except Exception as e:
        print(f"[ASCON GCS] Decryption failed: {e}")
        return None

## 3. NETWORKING THREADS ##

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

## 4. MAIN LOGIC ##

if __name__ == "__main__":
    print("--- GCS ASCON PROXY ---")
    print("[ASCON] Using Ascon-128 (AEAD)")
    
    # Start the two networking threads
    thread1 = threading.Thread(target=drone_to_gcs_thread, daemon=True)
    thread2 = threading.Thread(target=gcs_to_drone_thread, daemon=True)

    thread1.start()
    thread2.start()

    # Keep the main thread alive
    thread1.join()
    thread2.join()
