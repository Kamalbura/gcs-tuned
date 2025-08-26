# ==============================================================================
# drone_falcon.py
#
# Drone-Side Proxy for Post-Quantum Digital Signatures (Falcon-512)
#
# METHOD:
#   Mirrors the GCS-side Falcon proxy, providing authenticity for telemetry
#   and verifying commands from the GCS.
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

print("[FALCON Drone] Starting PQC Public Key Exchange...")
SIGNATURE_ALGORITHM = "Falcon-512"
drone_signer = oqs.Signature(SIGNATURE_ALGORITHM)
drone_public_key = drone_signer.generate_keypair()

exchange_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
while True:
    try:
        exchange_sock.connect((GCS_HOST, PORT_KEY_EXCHANGE))
        break
    except ConnectionRefusedError:
        print("[FALCON Drone] Connection refused. Retrying in 2 seconds...")
        time.sleep(2)

print(f"[FALCON Drone] Connected to GCS at {GCS_HOST}:{PORT_KEY_EXCHANGE}")

gcs_public_key = exchange_sock.recv(4096)
print("[FALCON Drone] GCS public key received.")
exchange_sock.sendall(drone_public_key)
print("[FALCON Drone] Drone public key sent.")
print("✅ [FALCON Drone] Public key exchange complete!")
exchange_sock.close()

## 2. SIGNATURE FUNCTIONS ##
SEPARATOR = b'|SIGNATURE|'

def sign_message(plaintext):
    signature = drone_signer.sign(plaintext)
    return plaintext + SEPARATOR + signature

def verify_message(signed_message):
    try:
        plaintext, signature = signed_message.rsplit(SEPARATOR, 1)
        verifier = oqs.Signature(SIGNATURE_ALGORITHM)
        return plaintext if verifier.verify(plaintext, signature, gcs_public_key) else None
    except ValueError:
        return None

## 3. NETWORKING THREADS ##
def telemetry_to_gcs_thread():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((DRONE_HOST, PORT_DRONE_LISTEN_PLAINTEXT_TLM))
    print(f"[FALCON Drone] Listening for telemetry on {DRONE_HOST}:{PORT_DRONE_LISTEN_PLAINTEXT_TLM}")
    while True:
        data, addr = sock.recvfrom(4096)
        signed_telemetry = sign_message(data)
        sock.sendto(signed_telemetry, (GCS_HOST, PORT_GCS_LISTEN_ENCRYPTED_TLM))

def commands_from_gcs_thread():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((DRONE_HOST, PORT_DRONE_LISTEN_ENCRYPTED_CMD))
    print(f"[FALCON Drone] Listening for signed GCS commands on {DRONE_HOST}:{PORT_DRONE_LISTEN_ENCRYPTED_CMD}")
    while True:
        data, addr = sock.recvfrom(8192)
        plaintext = verify_message(data)
        if plaintext:
            sock.sendto(plaintext, (DRONE_HOST, PORT_DRONE_FORWARD_DECRYPTED_CMD))

## 4. MAIN LOGIC ##
if __name__ == "__main__":
    print("--- DRONE FALCON SIGNATURE PROXY ---")
    t1 = threading.Thread(target=telemetry_to_gcs_thread, daemon=True)
    t2 = threading.Thread(target=commands_from_gcs_thread, daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
