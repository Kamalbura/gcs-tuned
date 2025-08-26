# ==============================================================================
# gcs_kyber_hybrid.py
#
# GCS-Side Proxy for Hybrid Post-Quantum Cryptography
#
# METHOD:
#   1. KEY EXCHANGE (PQC): Use Kyber1024 to securely establish a shared secret.
#      - GCS generates a Kyber keypair.
#      - GCS sends its public key to the Drone.
#      - Drone encapsulates a secret and sends the ciphertext back.
#      - GCS decapsulates to get the same shared secret.
#   2. DATA EXCHANGE (Symmetric): Use the shared secret as a key for AES-256-GCM
#      to encrypt and authenticate all subsequent MAVLink messages.
#
# This hybrid approach provides post-quantum security for the key exchange
# and the high performance of AES for the bulk data transfer.
#
# DEPENDENCIES:
#   - oqs (pip install oqs)
#   - cryptography (pip install cryptography)
#   - ip_config.py
# ==============================================================================

import socket
import threading
import os
import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from ip_config import *

## 1. POST-QUANTUM KEY EXCHANGE ##

print("[KYBER GCS] Starting Post-Quantum Key Exchange...")

# GCS generates a Kyber keypair.
kem = oqs.KeyEncapsulation("Kyber1024")
gcs_public_key = kem.generate_keypair()

# Use a simple TCP socket for the one-time key exchange for reliability.
# The server (GCS) waits for the client (Drone) to connect.
exchange_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
exchange_sock.bind((GCS_HOST, PORT_KEY_EXCHANGE))
exchange_sock.listen(1)
print(f"[KYBER GCS] Waiting for Drone to connect for key exchange on {GCS_HOST}:{PORT_KEY_EXCHANGE}...")
conn, addr = exchange_sock.accept()
print(f"[KYBER GCS] Drone connected from {addr}")

# Send the public key to the Drone.
conn.sendall(gcs_public_key)
print("[KYBER GCS] Public key sent.")

# Receive the ciphertext from the Drone.
ciphertext = conn.recv(4096)
print("[KYBER GCS] Ciphertext received.")

# Decapsulate the ciphertext to get the shared secret.
shared_secret = kem.decap_secret(ciphertext)

# The first 32 bytes of the shared secret will be our AES key.
AES_KEY = shared_secret[:32]
aesgcm = AESGCM(AES_KEY)
print("✅ [KYBER GCS] Secure shared key established successfully!")
conn.close()
exchange_sock.close()


## 2. SYMMETRIC CRYPTOGRAPHY FUNCTIONS (using the established key) ##

def encrypt_message(plaintext):
    nonce = os.urandom(NONCE_IV_SIZE)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext

def decrypt_message(encrypted_message):
    try:
        nonce = encrypted_message[:NONCE_IV_SIZE]
        ciphertext = encrypted_message[NONCE_IV_SIZE:]
        return aesgcm.decrypt(nonce, ciphertext, None)
    except Exception as e:
        print(f"[AES GCS] Decryption failed: {e}")
        return None

## 3. NETWORKING THREADS ##

def drone_to_gcs_thread():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((GCS_HOST, PORT_GCS_LISTEN_ENCRYPTED_TLM))
    print(f"[KYBER GCS] Now listening for encrypted drone telemetry on {GCS_HOST}:{PORT_GCS_LISTEN_ENCRYPTED_TLM}")
    while True:
        data, addr = sock.recvfrom(4096)
        plaintext = decrypt_message(data)
        if plaintext:
            sock.sendto(plaintext, (GCS_HOST, PORT_GCS_FORWARD_DECRYPTED_TLM))

def gcs_to_drone_thread():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((GCS_HOST, PORT_GCS_LISTEN_PLAINTEXT_CMD))
    print(f"[KYBER GCS] Now listening for plaintext GCS commands on {GCS_HOST}:{PORT_GCS_LISTEN_PLAINTEXT_CMD}")
    while True:
        data, addr = sock.recvfrom(4096)
        encrypted = encrypt_message(data)
        sock.sendto(encrypted, (DRONE_HOST, PORT_DRONE_LISTEN_ENCRYPTED_CMD))

## 4. MAIN LOGIC ##
if __name__ == "__main__":
    print("--- GCS KYBER HYBRID PROXY ---")
    t1 = threading.Thread(target=drone_to_gcs_thread, daemon=True)
    t2 = threading.Thread(target=gcs_to_drone_thread, daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
