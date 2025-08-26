# ==============================================================================
# gcs_sphincs.py
#
# GCS-Side Proxy for Post-Quantum Digital Signatures (SPHINCS+)
#
# METHOD:
#   Provides authenticity and integrity via stateless hash-based signatures.
#   1) Public key exchange over TCP (send our SPHINCS+ public key, receive drone's).
#   2) Sign outgoing plaintext commands; verify incoming signed telemetry.
#
# DEPENDENCIES:
#   - liboqs-python (pip install liboqs-python)
#   - ip_config.py
# ==============================================================================

import socket
import threading
from ip_config import *
try:
    import oqs.oqs as oqs
    USING_LIBOQS = True
except ImportError:
    print("[WARNING] liboqs not found, falling back to RSA signatures")
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import serialization, hashes
    USING_LIBOQS = False

# Separator to split message and signature
SEPARATOR = b'|SIGNATURE|'

print("[SPHINCS GCS] Starting Public Key Exchange...")

if USING_LIBOQS:
    # Choose a broadly available SPHINCS+ variant
    SIGNATURE_ALGORITHM = "SPHINCS+-SHA2-128s-simple"
    signer = oqs.Signature(SIGNATURE_ALGORITHM)
    gcs_public_key = signer.generate_keypair()

    # TCP server: wait for drone to connect
    ex_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ex_sock.bind((GCS_HOST, PORT_KEY_EXCHANGE))
    ex_sock.listen(1)
    print(f"[SPHINCS GCS] Waiting on {GCS_HOST}:{PORT_KEY_EXCHANGE}...")
    conn, addr = ex_sock.accept()
    print(f"[SPHINCS GCS] Drone connected from {addr}")

    # Exchange public keys
    conn.sendall(gcs_public_key)
    drone_public_key = conn.recv(65536)
    print("[SPHINCS GCS] Public keys exchanged.")

    def sign_message(plaintext: bytes) -> bytes:
        sig = signer.sign(plaintext)
        return plaintext + SEPARATOR + sig

    def verify_message(signed_message: bytes):
        try:
            plaintext, sig = signed_message.rsplit(SEPARATOR, 1)
            verifier = oqs.Signature(SIGNATURE_ALGORITHM)
            if verifier.verify(plaintext, sig, drone_public_key):
                return plaintext
            print("[SPHINCS GCS] Signature verification failed.")
            return None
        except ValueError:
            print("[SPHINCS GCS] Malformed signed message.")
            return None

else:
    # RSA fallback
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import serialization, hashes
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    ex_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ex_sock.bind((GCS_HOST, PORT_KEY_EXCHANGE))
    ex_sock.listen(1)
    print(f"[SPHINCS GCS] Waiting on {GCS_HOST}:{PORT_KEY_EXCHANGE} (RSA fallback)...")
    conn, addr = ex_sock.accept()
    print(f"[SPHINCS GCS] Drone connected from {addr}")

    conn.sendall(pem_public_key)
    drone_public_key_pem = conn.recv(65536)
    drone_public_key = serialization.load_pem_public_key(drone_public_key_pem)

    def sign_message(plaintext: bytes) -> bytes:
        sig = private_key.sign(
            plaintext,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return plaintext + SEPARATOR + sig

    def verify_message(signed_message: bytes):
        try:
            plaintext, sig = signed_message.split(SEPARATOR, 1)
            drone_public_key.verify(
                sig,
                plaintext,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256(),
            )
            return plaintext
        except Exception as e:
            print(f"[SPHINCS GCS] Signature verification failed: {e}")
            return None

print("✅ [SPHINCS GCS] Public key exchange complete!")
conn.close()
ex_sock.close()


def drone_to_gcs_thread():
    """Verify incoming signed telemetry from drone and forward plaintext."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((GCS_HOST, PORT_GCS_LISTEN_ENCRYPTED_TLM))
    print(f"[SPHINCS GCS] Listening for signed telemetry on {GCS_HOST}:{PORT_GCS_LISTEN_ENCRYPTED_TLM}")
    while True:
        data, addr = sock.recvfrom(8192)
        pt = verify_message(data)
        if pt:
            sock.sendto(pt, (GCS_HOST, PORT_GCS_FORWARD_DECRYPTED_TLM))


def gcs_to_drone_thread():
    """Sign outgoing plaintext commands and send to drone."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((GCS_HOST, PORT_GCS_LISTEN_PLAINTEXT_CMD))
    print(f"[SPHINCS GCS] Listening for GCS commands on {GCS_HOST}:{PORT_GCS_LISTEN_PLAINTEXT_CMD}")
    while True:
        data, addr = sock.recvfrom(4096)
        signed_cmd = sign_message(data)
        sock.sendto(signed_cmd, (DRONE_HOST, PORT_DRONE_LISTEN_ENCRYPTED_CMD))


if __name__ == "__main__":
    print("--- GCS SPHINCS+ SIGNATURE PROXY ---")
    t1 = threading.Thread(target=drone_to_gcs_thread, daemon=True)
    t2 = threading.Thread(target=gcs_to_drone_thread, daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
