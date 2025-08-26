# ==============================================================================
# gcs_dilithium.py
#
# GCS-Side Proxy for Post-Quantum Digital Signatures (ML-DSA/Dilithium)
#
# METHOD:
#   This proxy DOES NOT ENCRYPT data. It provides authenticity and integrity.
#   1. KEY EXCHANGE: GCS and Drone generate their own Dilithium keypairs and
#      exchange their public keys.
#   2. DATA EXCHANGE:
#      - Every plaintext MAVLink command from the GCS is signed with the GCS's
#        private key. The message and signature are sent to the drone.
#      - Every plaintext MAVLink telemetry packet from the drone is signed.
#      - The GCS verifies the signature on incoming telemetry using the drone's
#        public key before forwarding it.
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

print("[DILITHIUM GCS] Starting PQC Public Key Exchange...")

# GCS generates its own signature keypair.
SIGNATURE_ALGORITHM = "Dilithium3"
gcs_signer = oqs.Signature(SIGNATURE_ALGORITHM)
gcs_public_key = gcs_signer.generate_keypair()
# The secret key is kept within the gcs_signer object.

# Use TCP for reliable key exchange.
exchange_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
exchange_sock.bind((GCS_HOST, PORT_KEY_EXCHANGE))
exchange_sock.listen(1)
print(f"[DILITHIUM GCS] Waiting for Drone to connect for key exchange on {GCS_HOST}:{PORT_KEY_EXCHANGE}...")
conn, addr = exchange_sock.accept()
print(f"[DILITHIUM GCS] Drone connected from {addr}")

# Exchange public keys: GCS sends first, then receives.
conn.sendall(gcs_public_key)
print("[DILITHIUM GCS] GCS public key sent.")
drone_public_key = conn.recv(4096)
print("[DILITHIUM GCS] Drone public key received.")
print("✅ [DILITHIUM GCS] Public key exchange complete!")
conn.close()
exchange_sock.close()


## 2. SIGNATURE FUNCTIONS ##

# A separator to distinguish the message from the signature.
SEPARATOR = b'|SIGNATURE|'

def sign_message(plaintext):
    """Signs a message using the GCS's private key."""
    signature = gcs_signer.sign(plaintext)
    return plaintext + SEPARATOR + signature

def verify_message(signed_message):
    """
    Verifies a message from the drone using the drone's public key.
    Returns the plaintext message if valid, otherwise None.
    """
    try:
        plaintext, signature = signed_message.rsplit(SEPARATOR, 1)
        verifier = oqs.Signature(SIGNATURE_ALGORITHM)
        is_valid = verifier.verify(plaintext, signature, drone_public_key)
        if is_valid:
            return plaintext
        else:
            print("[DILITHIUM GCS] !!! SIGNATURE VERIFICATION FAILED !!!")
            return None
    except (ValueError) as e:
        print(f"[DILITHIUM GCS] Malformed message received, could not split signature: {e}")
        return None

## 3. NETWORKING THREADS ##

def drone_to_gcs_thread():
    """Listens for signed telemetry, verifies, and forwards plaintext."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((GCS_HOST, PORT_GCS_LISTEN_ENCRYPTED_TLM))
    print(f"[DILITHIUM GCS] Listening for signed telemetry on {GCS_HOST}:{PORT_GCS_LISTEN_ENCRYPTED_TLM}")
    while True:
        data, addr = sock.recvfrom(8192) # Increased buffer for signature
        plaintext = verify_message(data)
        if plaintext:
            sock.sendto(plaintext, (GCS_HOST, PORT_GCS_FORWARD_DECRYPTED_TLM))

def gcs_to_drone_thread():
    """Listens for plaintext commands, signs them, and sends to drone."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((GCS_HOST, PORT_GCS_LISTEN_PLAINTEXT_CMD))
    print(f"[DILITHIUM GCS] Listening for GCS commands on {GCS_HOST}:{PORT_GCS_LISTEN_PLAINTEXT_CMD}")
    while True:
        data, addr = sock.recvfrom(4096)
        signed_command = sign_message(data)
        sock.sendto(signed_command, (DRONE_HOST, PORT_DRONE_LISTEN_ENCRYPTED_CMD))

## 4. MAIN LOGIC ##
if __name__ == "__main__":
    print("--- GCS DILITHIUM SIGNATURE PROXY ---")
    t1 = threading.Thread(target=drone_to_gcs_thread, daemon=True)
    t2 = threading.Thread(target=gcs_to_drone_thread, daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
