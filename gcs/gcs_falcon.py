# ==============================================================================
# gcs_falcon.py
#
# GCS-Side Proxy for Post-Quantum Digital Signatures (Falcon-512)
#
# METHOD:
#   This proxy is functionally identical to the Dilithium proxy but uses the
#   Falcon-512 algorithm. It provides authenticity and integrity for MAVLink
#   messages by signing them. It DOES NOT provide confidentiality.
#
# DEPENDENCIES:
#   - oqs (pip install oqs)
#   - ip_config.py
# ==============================================================================

import socket
import threading
from ip_config import *
import oqs

## 1. POST-QUANTUM KEY EXCHANGE (Public Keys for Signatures) ##

print("[FALCON GCS] Starting PQC Public Key Exchange...")
SIGNATURE_ALGORITHM = "Falcon-512"
gcs_signer = oqs.Signature(SIGNATURE_ALGORITHM)
gcs_public_key = gcs_signer.generate_keypair()

exchange_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
exchange_sock.bind((GCS_HOST, PORT_KEY_EXCHANGE))
exchange_sock.listen(1)
print(f"[FALCON GCS] Waiting for Drone on {GCS_HOST}:{PORT_KEY_EXCHANGE}...")
conn, addr = exchange_sock.accept()
print(f"[FALCON GCS] Drone connected from {addr}")

conn.sendall(gcs_public_key)
print("[FALCON GCS] GCS public key sent.")
drone_public_key = conn.recv(4096)
print("[FALCON GCS] Drone public key received.")
print("✅ [FALCON GCS] Public key exchange complete!")
conn.close()
exchange_sock.close()

## 2. SIGNATURE FUNCTIONS ##
SEPARATOR = b'|SIGNATURE|'

def sign_message(plaintext):
    signature = gcs_signer.sign(plaintext)
    return plaintext + SEPARATOR + signature

def verify_message(signed_message):
    try:
        plaintext, signature = signed_message.rsplit(SEPARATOR, 1)
        verifier = oqs.Signature(SIGNATURE_ALGORITHM)
        if verifier.verify(plaintext, signature, drone_public_key):
            return plaintext
        print("[FALCON GCS] !!! SIGNATURE VERIFICATION FAILED !!!")
        return None
    except ValueError:
        print("[FALCON GCS] Malformed message, could not split signature.")
        return None

## 3. NETWORKING THREADS ##
def drone_to_gcs_thread():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((GCS_HOST, PORT_GCS_LISTEN_ENCRYPTED_TLM))
    print(f"[FALCON GCS] Listening for signed telemetry on {GCS_HOST}:{PORT_GCS_LISTEN_ENCRYPTED_TLM}")
    while True:
        data, addr = sock.recvfrom(8192)
        plaintext = verify_message(data)
        if plaintext:
            sock.sendto(plaintext, (GCS_HOST, PORT_GCS_FORWARD_DECRYPTED_TLM))

def gcs_to_drone_thread():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((GCS_HOST, PORT_GCS_LISTEN_PLAINTEXT_CMD))
    print(f"[FALCON GCS] Listening for GCS commands on {GCS_HOST}:{PORT_GCS_LISTEN_PLAINTEXT_CMD}")
    while True:
        data, addr = sock.recvfrom(4096)
        signed_command = sign_message(data)
        sock.sendto(signed_command, (DRONE_HOST, PORT_DRONE_LISTEN_ENCRYPTED_CMD))

## 4. MAIN LOGIC ##
if __name__ == "__main__":
    print("--- GCS FALCON SIGNATURE PROXY ---")
    t1 = threading.Thread(target=drone_to_gcs_thread, daemon=True)
    t2 = threading.Thread(target=gcs_to_drone_thread, daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
