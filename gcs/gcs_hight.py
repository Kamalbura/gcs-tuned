# ==============================================================================
# gcs_hight.py
#
# GCS-Side Proxy for HIGHT Lightweight Cryptography (CBC Mode)
#
# SECURITY WARNING:
#   CBC mode lacks authenticity. A MAC (like HMAC) is required.
#
# DEPENDENCIES:
#   - pycryptodome (for padding)
#   - ip_config.py
#   - hight.py, hight_CBC.py (Your implementations)
# ==============================================================================

import socket
import threading
import os
from Crypto.Util.Padding import pad, unpad
from hight_CBC import cbc_hight_encryption, cbc_hight_decryption
from ip_config import *

## 1. CONFIGURATION ##
PSK_HIGHT_MK = [0x88, 0xE3, 0x4F, 0x8F, 0x08, 0x17, 0x79, 0xF1, 0xE9, 0xF3, 0x94, 0x37, 0x0A, 0xD4, 0x05, 0x89]
BLOCK_SIZE = 8 # HIGHT has a 64-bit (8-byte) block size

## 2. CRYPTOGRAPHY FUNCTIONS ##
def encrypt_message(plaintext):
    """Encrypts using HIGHT-CBC, prepending a random 8-byte IV."""
    iv = list(os.urandom(BLOCK_SIZE))
    padded_plaintext = list(pad(plaintext, BLOCK_SIZE))
    ciphertext = cbc_hight_encryption(padded_plaintext, iv, PSK_HIGHT_MK)
    return bytes(iv) + bytes(ciphertext)

def decrypt_message(encrypted_message):
    """Decrypts using HIGHT-CBC after splitting the IV."""
    try:
        iv = list(encrypted_message[:BLOCK_SIZE])
        ciphertext = list(encrypted_message[BLOCK_SIZE:])
        decrypted_padded = cbc_hight_decryption(ciphertext, iv, PSK_HIGHT_MK)
        return unpad(bytes(decrypted_padded), BLOCK_SIZE)
    except Exception as e:
        print(f"[HIGHT GCS] Decryption failed: {e}")
        return None

## 3. NETWORKING THREADS ##
def drone_to_gcs_thread():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((GCS_HOST, PORT_GCS_LISTEN_ENCRYPTED_TLM))
    print(f"[HIGHT GCS] Listening on {GCS_HOST}:{PORT_GCS_LISTEN_ENCRYPTED_TLM}")
    while True:
        data, addr = sock.recvfrom(4096)
        plaintext = decrypt_message(data)
        if plaintext:
            sock.sendto(plaintext, (GCS_HOST, PORT_GCS_FORWARD_DECRYPTED_TLM))

def gcs_to_drone_thread():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((GCS_HOST, PORT_GCS_LISTEN_PLAINTEXT_CMD))
    print(f"[HIGHT GCS] Listening on {GCS_HOST}:{PORT_GCS_LISTEN_PLAINTEXT_CMD}")
    while True:
        data, addr = sock.recvfrom(4096)
        encrypted = encrypt_message(data)
        sock.sendto(encrypted, (DRONE_HOST, PORT_DRONE_LISTEN_ENCRYPTED_CMD))

## 4. MAIN LOGIC ##
if __name__ == "__main__":
    print("--- GCS HIGHT PROXY ---")
    t1 = threading.Thread(target=drone_to_gcs_thread, daemon=True)
    t2 = threading.Thread(target=gcs_to_drone_thread, daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
