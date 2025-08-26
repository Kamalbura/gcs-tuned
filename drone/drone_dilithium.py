# ==============================================================================
# drone_dilithium.py
#
# Drone-Side Proxy for Post-Quantum Digital Signatures (ML-DSA/Dilithium)
#
# METHOD:
#   Mirrors the GCS-side signature proxy.
#   1. KEY EXCHANGE: Connects to the GCS and exchanges public keys.
#   2. DATA EXCHANGE:
#      - Signs all outgoing telemetry with the Drone's private key.
#      - Verifies all incoming commands with the GCS's public key.
#
# DEPENDENCIES:
#   - oqs (pip install oqs)
#   - ip_config.py
# ==============================================================================

import socket
import threading
import time
from ip_config import *
import oqs

## 1. POST-QUANTUM KEY EXCHANGE (Public Keys for Signatures) ##

print("[DILITHIUM Drone] Starting PQC Public Key Exchange...")

# Drone generates its own signature keypair.
SIGNATURE_ALGORITHM = "Dilithium3"
drone_signer = oqs.Signature(SIGNATURE_ALGORITHM)
drone_public_key = drone_signer.generate_keypair()

# Connect to the GCS to exchange keys.
exchange_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
while True:
    try:
        exchange_sock.connect((GCS_HOST, PORT_KEY_EXCHANGE))
        break
    except ConnectionRefusedError:
        print("[DILITHIUM Drone] Connection refused. Retrying in 2 seconds...")
        time.sleep(2)

print(f"[DILITHIUM Drone] Connected to GCS at {GCS_HOST}:{PORT_KEY_EXCHANGE}")

# Exchange public keys: Drone receives first, then sends.
gcs_public_key = exchange_sock.recv(4096)
print("[DILITHIUM Drone] GCS public key received.")
exchange_sock.sendall(drone_public_key)
print("[DILITHIUM Drone] Drone public key sent.")
print("✅ [DILITHIUM Drone] Public key exchange complete!")
exchange_sock.close()

## 2. SIGNATURE FUNCTIONS ##
SEPARATOR = b'|SIGNATURE|'

def sign_message(plaintext):
    """Signs a message using the Drone's private key."""
    signature = drone_signer.sign(plaintext)
    return plaintext + SEPARATOR + signature

def verify_message(signed_message):
    """Verifies a message from the GCS using the GCS's public key."""
    try:
        plaintext, signature = signed_message.rsplit(SEPARATOR, 1)
        verifier = oqs.Signature(SIGNATURE_ALGORITHM)
        is_valid = verifier.verify(plaintext, signature, gcs_public_key)
        return plaintext if is_valid else None
    except ValueError as e:
        print(f"[DILITHIUM Drone] Malformed message, could not split signature: {e}")
        return None

## 3. NETWORKING THREADS ##
def telemetry_to_gcs_thread():
    """Listens for plaintext telemetry, signs it, and sends to GCS."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((DRONE_HOST, PORT_DRONE_LISTEN_PLAINTEXT_TLM))
    print(f"[DILITHIUM Drone] Listening for telemetry on {DRONE_HOST}:{PORT_DRONE_LISTEN_PLAINTEXT_TLM}")
    while True:
        data, addr = sock.recvfrom(4096)
        signed_telemetry = sign_message(data)
        sock.sendto(signed_telemetry, (GCS_HOST, PORT_GCS_LISTEN_ENCRYPTED_TLM))

def commands_from_gcs_thread():
    """Listens for signed commands, verifies, and forwards to flight controller."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((DRONE_HOST, PORT_DRONE_LISTEN_ENCRYPTED_CMD))
    print(f"[DILITHIUM Drone] Listening for signed GCS commands on {DRONE_HOST}:{PORT_DRONE_LISTEN_ENCRYPTED_CMD}")
    while True:
        data, addr = sock.recvfrom(8192)
        plaintext = verify_message(data)
        if plaintext:
            sock.sendto(plaintext, (DRONE_HOST, PORT_DRONE_FORWARD_DECRYPTED_CMD))

## 4. MAIN LOGIC ##
if __name__ == "__main__":
    print("--- DRONE DILITHIUM SIGNATURE PROXY ---")
    t1 = threading.Thread(target=telemetry_to_gcs_thread, daemon=True)
    t2 = threading.Thread(target=commands_from_gcs_thread, daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
