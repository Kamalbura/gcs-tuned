# ==============================================================================
# drone_ascon.py
#
# Drone-Side Proxy for ASCON-128 Cryptography
#
# PURPOSE:
#   - Listens for plaintext MAVLink telemetry from the flight controller.
#   - Encrypts it using ASCON-128.
#   - Sends the encrypted telemetry to the GCS.
#   - Listens for encrypted commands from the GCS.
#   - Decrypts them using ASCON-128.
#   - Forwards the plaintext commands to the flight controller.
#
# DEPENDENCIES:
#   - pycryptodome (pip install pycryptodome)
#   - ip_config.py (must be in the same directory or Python path)
#
# HOW TO RUN:
#   This script should be run on the drone's companion computer.
#   python drone_ascon.py
# ==============================================================================

import socket
import threading
import os
from drneha.ascon.ascon import ascon_encrypt, ascon_decrypt
from ip_config import *

## 1. CONFIGURATION ##

# SECURITY WARNING: Must match GCS. ASCON-128: 16-byte key
# Exactly 16 bytes
PSK_ASCON = b'ThisIsA16ByteKey'
ASCON_NONCE_SIZE = 16

## 2. CRYPTOGRAPHY FUNCTIONS ##

def encrypt_message(plaintext):
    """Encrypts using ASCON-128, framing [nonce16 || ct||tag]."""
    nonce = os.urandom(ASCON_NONCE_SIZE)
    ct_tag = ascon_encrypt(PSK_ASCON, nonce, b"", plaintext, variant="Ascon-128")
    return nonce + ct_tag

def decrypt_message(encrypted_message):
    """Decrypts using ASCON-128, splitting 16-byte nonce and verifying tag."""
    try:
        nonce = encrypted_message[:ASCON_NONCE_SIZE]
        ct_tag = encrypted_message[ASCON_NONCE_SIZE:]
        plaintext = ascon_decrypt(PSK_ASCON, nonce, b"", ct_tag, variant="Ascon-128")
        return plaintext
    except Exception as e:
        print(f"[ASCON Drone] Decryption failed: {e}")
        return None

## 3. NETWORKING THREADS ##

def telemetry_to_gcs_thread():
    """
    - Listens for plaintext telemetry from the flight controller.
    - Encrypts the telemetry.
    - Sends encrypted telemetry to the GCS.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((DRONE_HOST, PORT_DRONE_LISTEN_PLAINTEXT_TLM))
    print(f"[ASCON Drone] Listening for plaintext telemetry on {DRONE_HOST}:{PORT_DRONE_LISTEN_PLAINTEXT_TLM}")

    while True:
        plaintext_data, addr = sock.recvfrom(4096)
        encrypted_telemetry = encrypt_message(plaintext_data)
        sock.sendto(encrypted_telemetry, (GCS_HOST, PORT_GCS_LISTEN_ENCRYPTED_TLM))

def commands_from_gcs_thread():
    """
    - Listens for encrypted commands from the GCS.
    - Decrypts the command.
    - Forwards plaintext command to the flight controller.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((DRONE_HOST, PORT_DRONE_LISTEN_ENCRYPTED_CMD))
    print(f"[ASCON Drone] Listening for encrypted GCS commands on {DRONE_HOST}:{PORT_DRONE_LISTEN_ENCRYPTED_CMD}")

    while True:
        encrypted_data, addr = sock.recvfrom(4096)
        plaintext_command = decrypt_message(encrypted_data)
        if plaintext_command:
            sock.sendto(plaintext_command, (DRONE_HOST, PORT_DRONE_FORWARD_DECRYPTED_CMD))

## 4. MAIN LOGIC ##

if __name__ == "__main__":
    print("--- DRONE ASCON PROXY ---")
    
    thread1 = threading.Thread(target=telemetry_to_gcs_thread, daemon=True)
    thread2 = threading.Thread(target=commands_from_gcs_thread, daemon=True)
    
    thread1.start()
    thread2.start()
    
    thread1.join()
    thread2.join()
