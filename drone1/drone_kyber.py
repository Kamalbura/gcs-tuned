# ==============================================================================
# drone_kyber.py
#
# Drone-Side Proxy for Post-Quantum Key Exchange using ML-KEM (Kyber)
# ==============================================================================

import socket
import threading
import os
import time
try:
    import oqs.oqs as oqs
    USING_LIBOQS = True
except ImportError:
    print("[WARNING] liboqs not found, falling back to RSA key exchange")
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import serialization, hashes
    import hashlib
    USING_LIBOQS = False

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from ip_config import *

print("[KYBER Drone] Starting Key Exchange (ML-KEM-768)...")

if USING_LIBOQS:
    kem = oqs.KeyEncapsulation("ML-KEM-768")

    ex_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    while True:
        try:
            ex_sock.connect((GCS_HOST, PORT_KEY_EXCHANGE))
            break
        except ConnectionRefusedError:
            print("[KYBER Drone] GCS not ready, retry in 2s...")
            time.sleep(2)

    print(f"[KYBER Drone] Connected to {GCS_HOST}:{PORT_KEY_EXCHANGE}")
    gcs_public_key = ex_sock.recv(65536)
    ciphertext, shared_secret = kem.encap_secret(gcs_public_key)
    ex_sock.sendall(ciphertext)
    AES_KEY = shared_secret[:32]
    ex_sock.close()
else:
    shared_secret = os.urandom(32)
    ex_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    while True:
        try:
            ex_sock.connect((GCS_HOST, PORT_KEY_EXCHANGE))
            break
        except ConnectionRefusedError:
            print("[KYBER Drone] GCS not ready, retry in 2s...")
            time.sleep(2)

    print(f"[KYBER Drone] Connected to {GCS_HOST}:{PORT_KEY_EXCHANGE}")
    pem_public_key = ex_sock.recv(65536)
    gcs_public_key = serialization.load_pem_public_key(pem_public_key)
    encrypted_shared_secret = gcs_public_key.encrypt(
        shared_secret,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    ex_sock.sendall(encrypted_shared_secret)
    AES_KEY = hashlib.sha256(shared_secret).digest()
    ex_sock.close()

aesgcm = AESGCM(AES_KEY)
print("✅ [KYBER Drone] Shared key established")


def encrypt_message(plaintext: bytes) -> bytes:
    nonce = os.urandom(NONCE_IV_SIZE)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ct


def decrypt_message(encrypted_message: bytes):
    try:
        nonce = encrypted_message[:NONCE_IV_SIZE]
        ct = encrypted_message[NONCE_IV_SIZE:]
        return aesgcm.decrypt(nonce, ct, None)
    except Exception as e:
        print(f"[KYBER Drone] Decryption failed: {e}")
        return None


def telemetry_to_gcs_thread():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((DRONE_HOST, PORT_DRONE_LISTEN_PLAINTEXT_TLM))
    print(f"[KYBER Drone] Listening plaintext TLM on {DRONE_HOST}:{PORT_DRONE_LISTEN_PLAINTEXT_TLM}")
    while True:
        data, _ = sock.recvfrom(4096)
        enc = encrypt_message(data)
        sock.sendto(enc, (GCS_HOST, PORT_GCS_LISTEN_ENCRYPTED_TLM))


def commands_from_gcs_thread():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((DRONE_HOST, PORT_DRONE_LISTEN_ENCRYPTED_CMD))
    print(f"[KYBER Drone] Listening encrypted CMD on {DRONE_HOST}:{PORT_DRONE_LISTEN_ENCRYPTED_CMD}")
    while True:
        data, _ = sock.recvfrom(4096)
        pt = decrypt_message(data)
        if pt:
            sock.sendto(pt, (DRONE_HOST, PORT_DRONE_FORWARD_DECRYPTED_CMD))


if __name__ == "__main__":
    print("--- DRONE KYBER (ML-KEM-768) PROXY ---")
    t1 = threading.Thread(target=telemetry_to_gcs_thread, daemon=True)
    t2 = threading.Thread(target=commands_from_gcs_thread, daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
