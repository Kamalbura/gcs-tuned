# ==============================================================================
# gcs_kyber.py
#
# GCS-Side Proxy for Post-Quantum Key Exchange using ML-KEM (Kyber)
#
# METHOD:
#   1) Perform a Kyber (ML-KEM-768) key exchange over TCP to derive a shared key.
#   2) Use AES-256-GCM with the derived key for UDP MAVLink streams.
# ==============================================================================

import socket
import threading
import os
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

print("[KYBER GCS] Starting Key Exchange (ML-KEM-768)...")

if USING_LIBOQS:
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    gcs_public_key = kem.generate_keypair()

    ex_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ex_sock.bind((GCS_HOST, PORT_KEY_EXCHANGE))
    ex_sock.listen(1)
    print(f"[KYBER GCS] Waiting on {GCS_HOST}:{PORT_KEY_EXCHANGE}...")
    conn, addr = ex_sock.accept()
    print(f"[KYBER GCS] Drone connected from {addr}")

    conn.sendall(gcs_public_key)
    ciphertext = conn.recv(65536)
    shared_secret = kem.decap_secret(ciphertext)
    AES_KEY = shared_secret[:32]
else:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    ex_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ex_sock.bind((GCS_HOST, PORT_KEY_EXCHANGE))
    ex_sock.listen(1)
    print(f"[KYBER GCS] Waiting on {GCS_HOST}:{PORT_KEY_EXCHANGE} (RSA fallback)...")
    conn, addr = ex_sock.accept()
    print(f"[KYBER GCS] Drone connected from {addr}")
    conn.sendall(pem_public_key)
    encrypted_shared_secret = conn.recv(65536)
    shared_secret = private_key.decrypt(
        encrypted_shared_secret,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    AES_KEY = hashlib.sha256(shared_secret).digest()

aesgcm = AESGCM(AES_KEY)
print("✅ [KYBER GCS] Shared key established")
conn.close()
ex_sock.close()


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
        print(f"[KYBER GCS] Decryption failed: {e}")
        return None


def drone_to_gcs_thread():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((GCS_HOST, PORT_GCS_LISTEN_ENCRYPTED_TLM))
    print(f"[KYBER GCS] Listening encrypted TLM on {GCS_HOST}:{PORT_GCS_LISTEN_ENCRYPTED_TLM}")
    while True:
        data, _ = sock.recvfrom(4096)
        pt = decrypt_message(data)
        if pt:
            sock.sendto(pt, (GCS_HOST, PORT_GCS_FORWARD_DECRYPTED_TLM))


def gcs_to_drone_thread():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((GCS_HOST, PORT_GCS_LISTEN_PLAINTEXT_CMD))
    print(f"[KYBER GCS] Listening plaintext CMD on {GCS_HOST}:{PORT_GCS_LISTEN_PLAINTEXT_CMD}")
    while True:
        data, _ = sock.recvfrom(4096)
        enc = encrypt_message(data)
        sock.sendto(enc, (DRONE_HOST, PORT_DRONE_LISTEN_ENCRYPTED_CMD))


if __name__ == "__main__":
    print("--- GCS KYBER (ML-KEM-768) PROXY ---")
    t1 = threading.Thread(target=drone_to_gcs_thread, daemon=True)
    t2 = threading.Thread(target=gcs_to_drone_thread, daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
