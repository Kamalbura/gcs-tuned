# ==============================================================================
# drone_kyber_hybrid.py
#
# Drone-Side Proxy for Hybrid Post-Quantum Cryptography
#
# METHOD:
#   1. KEY EXCHANGE (PQC): Connects to the GCS to perform a Kyber key exchange.
#      - Receives the GCS's public key.
#      - Generates and encapsulates a shared secret.
#      - Sends the resulting ciphertext to the GCS.
#   2. DATA EXCHANGE (Symmetric): Uses the derived shared secret as a key for
#      AES-256-GCM to secure all MAVLink messages.
#
# DEPENDENCIES:
#   - oqs (pip install oqs)
#   - cryptography (pip install cryptography)
#   - ip_config.py
# ==============================================================================

import socket
import threading
import os
import time
import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from ip_config import *

## 1. POST-QUANTUM KEY EXCHANGE ##

print("[KYBER Drone] Starting Post-Quantum Key Exchange...")

# Drone acts as the client in the key exchange.
kem = oqs.KeyEncapsulation("Kyber1024")

# Connect to the GCS to exchange keys.
# Retry connection in case the GCS proxy isn't ready yet.
exchange_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
while True:
    try:
        exchange_sock.connect((GCS_HOST, PORT_KEY_EXCHANGE))
        break
    except ConnectionRefusedError:
        print("[KYBER Drone] Connection refused. GCS not ready? Retrying in 2 seconds...")
        time.sleep(2)

print(f"[KYBER Drone] Connected to GCS at {GCS_HOST}:{PORT_KEY_EXCHANGE}")

# Receive the GCS's public key.
gcs_public_key = exchange_sock.recv(4096)
print("[KYBER Drone] Public key received.")

# Encapsulate a secret using the public key. This generates both the
# ciphertext (to send back) and the shared secret (to keep).
ciphertext, shared_secret = kem.encap_secret(gcs_public_key)

# Send the ciphertext back to the GCS.
exchange_sock.sendall(ciphertext)
print("[KYBER Drone] Ciphertext sent.")

# The first 32 bytes of the shared secret become our AES key.
AES_KEY = shared_secret[:32]
aesgcm = AESGCM(AES_KEY)
print("✅ [KYBER Drone] Secure shared key established successfully!")
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
        print(f"[AES Drone] Decryption failed: {e}")
        return None

## 3. NETWORKING THREADS ##

def telemetry_to_gcs_thread():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((DRONE_HOST, PORT_DRONE_LISTEN_PLAINTEXT_TLM))
    print(f"[KYBER Drone] Now listening for plaintext telemetry on {DRONE_HOST}:{PORT_DRONE_LISTEN_PLAINTEXT_TLM}")
    while True:
        data, addr = sock.recvfrom(4096)
        encrypted = encrypt_message(data)
        sock.sendto(encrypted, (GCS_HOST, PORT_GCS_LISTEN_ENCRYPTED_TLM))

def commands_from_gcs_thread():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((DRONE_HOST, PORT_DRONE_LISTEN_ENCRYPTED_CMD))
    print(f"[KYBER Drone] Now listening for encrypted GCS commands on {DRONE_HOST}:{PORT_DRONE_LISTEN_ENCRYPTED_CMD}")
    while True:
        data, addr = sock.recvfrom(4096)
        plaintext = decrypt_message(data)
        if plaintext:
            sock.sendto(plaintext, (DRONE_HOST, PORT_DRONE_FORWARD_DECRYPTED_CMD))

## 4. MAIN LOGIC ##
if __name__ == "__main__":
    print("--- DRONE KYBER HYBRID PROXY ---")
    t1 = threading.Thread(target=telemetry_to_gcs_thread, daemon=True)
    t2 = threading.Thread(target=commands_from_gcs_thread, daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
