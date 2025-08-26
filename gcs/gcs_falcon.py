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
#   - liboqs-python (pip install liboqs-python)
#   - ip_config.py
# ==============================================================================

import socket
import threading
import os
try:
    import oqs.oqs as oqs
    USING_LIBOQS = True
except ImportError:
    print("[WARNING] liboqs not found, falling back to RSA signatures")
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import serialization, hashes
    USING_LIBOQS = False

from ip_config import *

## 1. POST-QUANTUM KEY EXCHANGE (Public Keys for Signatures) ##

print("[FALCON GCS] Starting Public Key Exchange...")

if USING_LIBOQS:
    # Use actual Falcon from liboqs
    print("[FALCON GCS] Using liboqs Falcon-512")
    SIGNATURE_ALGORITHM = "Falcon-512"
    gcs_signer = oqs.Signature(SIGNATURE_ALGORITHM)
    gcs_public_key = gcs_signer.generate_keypair()
    
    # TCP for reliable key exchange
    exchange_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    exchange_sock.bind((GCS_HOST, PORT_KEY_EXCHANGE))
    exchange_sock.listen(1)
    print(f"[FALCON GCS] Waiting for Drone to connect on {GCS_HOST}:{PORT_KEY_EXCHANGE}...")
    conn, addr = exchange_sock.accept()
    print(f"[FALCON GCS] Drone connected from {addr}")
    
    # Exchange public keys
    conn.sendall(gcs_public_key)
    print("[FALCON GCS] GCS public key sent.")
    drone_public_key = conn.recv(4096)
    print("[FALCON GCS] Drone public key received.")
    
    # Define signature functions
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
else:
    # Fallback to RSA signatures
    print("[FALCON GCS] Falling back to RSA signatures")
    
    # Generate RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    
    # Serialize the public key to send to the drone
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    
    # Use TCP for reliable key exchange
    exchange_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    exchange_sock.bind((GCS_HOST, PORT_KEY_EXCHANGE))
    exchange_sock.listen(1)
    print(f"[FALCON GCS] Waiting for Drone to connect on {GCS_HOST}:{PORT_KEY_EXCHANGE}...")
    conn, addr = exchange_sock.accept()
    print(f"[FALCON GCS] Drone connected from {addr}")
    
    # Exchange public keys
    conn.sendall(pem_public_key)
    print("[FALCON GCS] GCS public key sent.")
    drone_public_key_pem = conn.recv(4096)
    print("[FALCON GCS] Drone public key received.")
    
    # Deserialize the drone's public key
    drone_public_key = serialization.load_pem_public_key(drone_public_key_pem)
    
    # Define signature functions
    def sign_message(plaintext):
        signature = private_key.sign(
            plaintext,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return plaintext + SEPARATOR + signature

    def verify_message(signed_message):
        try:
            plaintext, signature = signed_message.split(SEPARATOR, 1)
            drone_public_key.verify(
                signature,
                plaintext,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return plaintext
        except Exception as e:
            print(f"[FALCON GCS] Signature verification failed: {e}")
            return None

print("✅ [FALCON GCS] Public key exchange complete!")
conn.close()
exchange_sock.close()

## 2. SIGNATURE SEPARATOR ##
# A separator to distinguish the message from the signature
SEPARATOR = b'|SIGNATURE|'

## 3. NETWORKING THREADS ##

def drone_to_gcs_thread():
    """Listens for signed telemetry, verifies, and forwards plaintext."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((GCS_HOST, PORT_GCS_LISTEN_ENCRYPTED_TLM))
    print(f"[FALCON GCS] Listening for signed telemetry on {GCS_HOST}:{PORT_GCS_LISTEN_ENCRYPTED_TLM}")
    while True:
        data, addr = sock.recvfrom(8192)  # Increased buffer for signature
        plaintext = verify_message(data)
        if plaintext:
            sock.sendto(plaintext, (GCS_HOST, PORT_GCS_FORWARD_DECRYPTED_TLM))

def gcs_to_drone_thread():
    """Listens for plaintext commands, signs them, and sends to drone."""
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
