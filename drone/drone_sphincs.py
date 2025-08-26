# ==============================================================================
# drone_sphincs.py
#
# Drone-Side Proxy for Post-Quantum Digital Signatures (SPHINCS+)
#
# METHOD:
#   Mirrors the GCS-side proxy: exchange public keys, sign telemetry, verify
#   commands.
# ==============================================================================

import socket
import threading
import time
from ip_config import *
try:
    import oqs.oqs as oqs
    USING_LIBOQS = True
except ImportError:
    print("[WARNING] liboqs not found, falling back to RSA signatures")
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import serialization, hashes
    USING_LIBOQS = False

SEPARATOR = b'|SIGNATURE|'

print("[SPHINCS Drone] Starting PQC Public Key Exchange...")

if USING_LIBOQS:
    SIGNATURE_ALGORITHM = "SPHINCS+-SHA2-128s-simple"
    signer = oqs.Signature(SIGNATURE_ALGORITHM)
    drone_public_key = signer.generate_keypair()

    ex_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    while True:
        try:
            ex_sock.connect((GCS_HOST, PORT_KEY_EXCHANGE))
            break
        except ConnectionRefusedError:
            print("[SPHINCS Drone] GCS not ready, retrying in 2s...")
            time.sleep(2)

    print(f"[SPHINCS Drone] Connected to {GCS_HOST}:{PORT_KEY_EXCHANGE}")
    gcs_public_key = ex_sock.recv(65536)
    ex_sock.sendall(drone_public_key)
    print("[SPHINCS Drone] Public keys exchanged.")
    ex_sock.close()

    def sign_message(plaintext: bytes) -> bytes:
        sig = signer.sign(plaintext)
        return plaintext + SEPARATOR + sig

    def verify_message(signed_message: bytes):
        try:
            plaintext, sig = signed_message.rsplit(SEPARATOR, 1)
            verifier = oqs.Signature(SIGNATURE_ALGORITHM)
            return plaintext if verifier.verify(plaintext, sig, gcs_public_key) else None
        except ValueError:
            print("[SPHINCS Drone] Malformed signed message.")
            return None

else:
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import serialization, hashes
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    ex_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    while True:
        try:
            ex_sock.connect((GCS_HOST, PORT_KEY_EXCHANGE))
            break
        except ConnectionRefusedError:
            print("[SPHINCS Drone] GCS not ready, retrying in 2s...")
            time.sleep(2)

    print(f"[SPHINCS Drone] Connected to {GCS_HOST}:{PORT_KEY_EXCHANGE}")
    gcs_public_key_pem = ex_sock.recv(65536)
    ex_sock.sendall(pem_public_key)
    print("[SPHINCS Drone] Keys exchanged.")
    ex_sock.close()

    gcs_public_key = serialization.load_pem_public_key(gcs_public_key_pem)

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
            gcs_public_key.verify(
                sig,
                plaintext,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256(),
            )
            return plaintext
        except Exception as e:
            print(f"[SPHINCS Drone] Signature verification failed: {e}")
            return None


def telemetry_to_gcs_thread():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((DRONE_HOST, PORT_DRONE_LISTEN_PLAINTEXT_TLM))
    print(f"[SPHINCS Drone] Listening for telemetry on {DRONE_HOST}:{PORT_DRONE_LISTEN_PLAINTEXT_TLM}")
    while True:
        data, addr = sock.recvfrom(4096)
        signed = sign_message(data)
        sock.sendto(signed, (GCS_HOST, PORT_GCS_LISTEN_ENCRYPTED_TLM))


def commands_from_gcs_thread():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((DRONE_HOST, PORT_DRONE_LISTEN_ENCRYPTED_CMD))
    print(f"[SPHINCS Drone] Listening for signed GCS commands on {DRONE_HOST}:{PORT_DRONE_LISTEN_ENCRYPTED_CMD}")
    while True:
        data, addr = sock.recvfrom(8192)
        pt = verify_message(data)
        if pt:
            sock.sendto(pt, (DRONE_HOST, PORT_DRONE_FORWARD_DECRYPTED_CMD))


if __name__ == "__main__":
    print("--- DRONE SPHINCS+ SIGNATURE PROXY ---")
    t1 = threading.Thread(target=telemetry_to_gcs_thread, daemon=True)
    t2 = threading.Thread(target=commands_from_gcs_thread, daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()
