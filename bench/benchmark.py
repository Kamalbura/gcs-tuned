"""
Benchmark decrypt/verify performance for GCS <-> Drone crypto proxies.

- Symmetric AEAD/CBC: measure decrypt() on receiver for ciphertext produced by sender.
- KEM (Kyber/ML-KEM): performs in-process TCP key exchange, then times AEAD decrypt.
- Signatures (Dilithium/Falcon/SPHINCS+): performs in-process pubkey exchange, then times verify().

Works on Windows and Raspberry Pi 4B. Run one algorithm at a time (port 5800 is reused).

Examples:
  Windows PowerShell:
    python bench\\benchmark.py --algo aes --iters 2000 --size 256
    python bench\\benchmark.py --algo kyber --iters 500 --size 128

  Raspberry Pi (Drone on Pi):
    python3 bench/benchmark.py --algo ascon --iters 2000 --size 256

Algorithms: aes, ascon, camellia, hight, speck, kyber, kyber_hybrid, dilithium, falcon, sphincs
"""

import argparse
import sys
import threading
import time
import os

# Ensure repo root is importable
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


def bench_symmetric(gcs_mod, drone_mod, size: int, iters: int):
    m = (b"M" * size)
    # g->d
    ct = drone_mod.encrypt_message(m)
    t0 = time.perf_counter()
    for _ in range(iters):
        pt = gcs_mod.decrypt_message(ct)
        if pt != m:
            raise RuntimeError("Decrypt mismatch (g<-d)")
    t1 = time.perf_counter()
    g_from_d_us = (t1 - t0) / iters * 1e6

    # d->g
    ct2 = gcs_mod.encrypt_message(m)
    t2 = time.perf_counter()
    for _ in range(iters):
        pt2 = drone_mod.decrypt_message(ct2)
        if pt2 != m:
            raise RuntimeError("Decrypt mismatch (d<-g)")
    t3 = time.perf_counter()
    d_from_g_us = (t3 - t2) / iters * 1e6

    return g_from_d_us, d_from_g_us


def bench_kyber_normal(size: int, iters: int):
    # Start GCS server (performs ML-KEM-768 exchange at import time)
    G = {}
    def start_gcs():
        import gcs.gcs_kyber as g
        G['g'] = g
    th = threading.Thread(target=start_gcs)
    th.start()
    time.sleep(1.5)
    import drone.drone_kyber as d
    th.join(timeout=5)
    return bench_symmetric(G['g'], d, size, iters)


def bench_kyber_hybrid(size: int, iters: int):
    # Start GCS server (performs Kyber1024 exchange at import time)
    G = {}
    def start_gcs():
        import gcs.gcs_kyber_hybrid as g
        G['g'] = g
    th = threading.Thread(target=start_gcs)
    th.start()
    time.sleep(1.5)
    import drone.drone_kyber_hybrid as d
    th.join(timeout=5)
    return bench_symmetric(G['g'], d, size, iters)


def bench_signature(gcs_module_name: str, drone_module_name: str, size: int, iters: int):
    # Start GCS (performs pubkey exchange at import time)
    G = {}
    def start_gcs():
        mod = __import__(gcs_module_name, fromlist=[''])
        G['g'] = mod
    th = threading.Thread(target=start_gcs)
    th.start()
    time.sleep(1.5)
    D = __import__(drone_module_name, fromlist=[''])
    th.join(timeout=5)

    m = (b"M" * size)
    # GCS -> Drone verify
    signed = G['g'].sign_message(m)
    t0 = time.perf_counter()
    for _ in range(iters):
        pt = D.verify_message(signed)
        if pt != m:
            raise RuntimeError("Verify mismatch (Drone verifying GCS message)")
    t1 = time.perf_counter()
    d_verify_us = (t1 - t0) / iters * 1e6

    # Drone -> GCS verify
    signed2 = D.sign_message(m)
    t2 = time.perf_counter()
    for _ in range(iters):
        pt2 = G['g'].verify_message(signed2)
        if pt2 != m:
            raise RuntimeError("Verify mismatch (GCS verifying Drone message)")
    t3 = time.perf_counter()
    g_verify_us = (t3 - t2) / iters * 1e6

    return g_verify_us, d_verify_us


def main():
    p = argparse.ArgumentParser(description="Benchmark decrypt/verify times for GCS/Drone crypto proxies")
    p.add_argument("--algo", required=True, choices=[
        "aes", "ascon", "camellia", "hight", "speck",
        "kyber", "kyber_hybrid",
        "dilithium", "falcon", "sphincs",
    ])
    p.add_argument("--iters", type=int, default=1000, help="Iterations per timing loop")
    p.add_argument("--size", type=int, default=128, help="Payload size (bytes)")
    args = p.parse_args()

    algo = args.algo
    iters = args.iters
    size = args.size

    if algo == "aes":
        import gcs.gcs_aes as g
        import drone.drone_aes as d
        g_us, d_us = bench_symmetric(g, d, size, iters)
        print(f"AES-256-GCM decrypt avg (Drone->GCS): {g_us:.1f} us ; (GCS->Drone): {d_us:.1f} us")
    elif algo == "ascon":
        import gcs.gcs_ascon as g
        import drone.drone_ascon as d
        g_us, d_us = bench_symmetric(g, d, size, iters)
        print(f"ASCON-128 decrypt avg (Drone->GCS): {g_us:.1f} us ; (GCS->Drone): {d_us:.1f} us")
    elif algo == "camellia":
        import gcs.gcs_camellia as g
        import drone.drone_camellia as d
        g_us, d_us = bench_symmetric(g, d, size, iters)
        print(f"Camellia-CBC decrypt avg (Drone->GCS): {g_us:.1f} us ; (GCS->Drone): {d_us:.1f} us")
    elif algo == "hight":
        import gcs.gcs_hight as g
        import drone.drone_hight as d
        g_us, d_us = bench_symmetric(g, d, size, iters)
        print(f"HIGHT-CBC decrypt avg (Drone->GCS): {g_us:.1f} us ; (GCS->Drone): {d_us:.1f} us")
    elif algo == "speck":
        import gcs.gcs_speck as g
        import drone.drone_speck as d
        g_us, d_us = bench_symmetric(g, d, size, iters)
        print(f"Speck-CBC decrypt avg (Drone->GCS): {g_us:.1f} us ; (GCS->Drone): {d_us:.1f} us")
    elif algo == "kyber":
        g_us, d_us = bench_kyber_normal(size, iters)
        print(f"ML-KEM-768 (Kyber) decrypt avg (Drone->GCS): {g_us:.1f} us ; (GCS->Drone): {d_us:.1f} us")
    elif algo == "kyber_hybrid":
        g_us, d_us = bench_kyber_hybrid(size, iters)
        print(f"Kyber hybrid decrypt avg (Drone->GCS): {g_us:.1f} us ; (GCS->Drone): {d_us:.1f} us")
    elif algo == "dilithium":
        g_us, d_us = bench_signature('gcs.gcs_dilithium', 'drone.drone_dilithium', size, iters)
        print(f"Dilithium verify avg (GCS verifying Drone): {g_us:.1f} us ; (Drone verifying GCS): {d_us:.1f} us")
    elif algo == "falcon":
        g_us, d_us = bench_signature('gcs.gcs_falcon', 'drone.drone_falcon', size, iters)
        print(f"Falcon verify avg (GCS verifying Drone): {g_us:.1f} us ; (Drone verifying GCS): {d_us:.1f} us")
    elif algo == "sphincs":
        g_us, d_us = bench_signature('gcs.gcs_sphincs', 'drone.drone_sphincs', size, iters)
        print(f"SPHINCS+ verify avg (GCS verifying Drone): {g_us:.1f} us ; (Drone verifying GCS): {d_us:.1f} us")
    else:
        raise SystemExit("Unknown algorithm")


if __name__ == "__main__":
    main()
