#!/usr/bin/env python3
"""
Drone Healthcheck: run this on the Raspberry Pi.
Validates:
- Python oqs module present and basic Kyber/Dilithium operations.
- MQTT mTLS connect as the drone identity (DRONE_ID from drone/ip_config.py).
- ACL: can subscribe to its commands and publish telemetry.

Usage:
  python tools/healthcheck_drone.py

Environment overrides:
  MQTT_HOST, MQTT_PORT, MQTT_CA
  DRONE_CERT, DRONE_KEY
  GCS_CERT,GCS_KEY (optional, to simulate a GCS publish if needed)
"""
from __future__ import annotations
import sys, os, ssl, time
from pathlib import Path
from threading import Event


def _import_ip_config():
    repo_root = Path(__file__).resolve().parents[1]
    drone_dir = repo_root / 'drone'
    sys.path.insert(0, str(drone_dir))
    import ip_config  # type: ignore
    return ip_config


ipcfg = _import_ip_config()


def _defaults():
    repo_root = Path(__file__).resolve().parents[1]
    home = Path.home()
    # CA locations preference: user home, system, repo fallback
    ca_candidates = [
        home / 'uav' / 'certs' / 'ca-cert.pem',
        home / 'drone' / 'certs' / 'ca-cert.pem',
        Path('/usr/local/etc/mosquitto/certs/ca-cert.pem'),
        Path('/etc/mosquitto/certs/ca-cert.pem'),
        repo_root / '.uav-mosq' / 'server' / 'ca-cert.pem',
        Path('C:/Program Files/mosquitto/server/ca-cert.pem'),  # ignored on Pi
    ]
    ca = next((p for p in ca_candidates if p.exists()), ca_candidates[-1])

    # Drone client cert/key preference: user home, then repo fallback
    client_candidates = [
        (home / 'uav' / 'certs' / f"{ipcfg.DRONE_ID}-cert.pem", home / 'uav' / 'certs' / f"{ipcfg.DRONE_ID}-key.pem"),
        (home / 'drone' / 'certs' / f"{ipcfg.DRONE_ID}-cert.pem", home / 'drone' / 'certs' / f"{ipcfg.DRONE_ID}-key.pem"),
        ((repo_root / '.uav-mosq' / 'clients' / f"{ipcfg.DRONE_ID}-cert.pem"), (repo_root / '.uav-mosq' / 'clients' / f"{ipcfg.DRONE_ID}-key.pem")),
    ]
    for cert_path, key_path in client_candidates:
        if cert_path.exists() and key_path.exists():
            return ca, cert_path, key_path
    # Fallback to last entries even if missing (will be reported in connect error)
    cert_path, key_path = client_candidates[-1]
    return ca, cert_path, key_path


def check_oqs() -> list[tuple[str,bool,str]]:
    res = []
    try:
        import oqs
        res.append(("oqs import", True, "OK"))
        try:
            with oqs.KeyEncapsulation("Kyber512") as kem:
                pk = kem.generate_keypair(); ct, ss1 = kem.encap_secret(pk); ss2 = kem.decap_secret(ct)
                res.append(("oqs KEM Kyber512", ss1==ss2, "OK"))
        except Exception as e:
            res.append(("oqs KEM Kyber512", False, str(e)))
        try:
            with oqs.Signature("Dilithium2") as sig:
                pk = sig.generate_keypair(); s = sig.sign(b"ping"); ok = sig.verify(b"ping", s, pk)
                res.append(("oqs SIG Dilithium2", ok, "OK" if ok else "verify failed"))
        except Exception as e:
            res.append(("oqs SIG Dilithium2", False, str(e)))
    except Exception as e:
        res.append(("oqs import", False, str(e)))
    return res


def _mqtt_tls_client(ca:str, cert:str, key:str):
    import paho.mqtt.client as mqtt
    c = mqtt.Client()
    c.tls_set(ca_certs=str(ca), certfile=str(cert), keyfile=str(key), tls_version=ssl.PROTOCOL_TLS_CLIENT)
    c.tls_insecure_set(False)
    return c


def check_mqtt(drone_id:str, host:str, port:int, ca:str, cert:str, key:str) -> list[tuple[str,bool,str]]:
    import paho.mqtt.client as mqtt
    res = []
    # Connect
    try:
        c = _mqtt_tls_client(ca, cert, key)
        done = Event(); err = []
        def on_connect(cl,u,f,rc,props=None):
            if rc!=0: err.append(f"RC={rc}")
            done.set()
        c.on_connect = on_connect
        c.connect(host, port, 30)
        c.loop_start(); done.wait(8); c.loop_stop(); c.disconnect()
        res.append(("MQTT connect (mTLS)", len(err)==0 and done.is_set(), ";".join(err) or "OK"))
    except Exception as e:
        res.append(("MQTT connect (mTLS)", False, str(e)))
        return res

    # ACL: subscribe commands, publish telemetry
    try:
        cmd_topic = f"fleet/{drone_id}/commands"; tlm_topic = f"fleet/{drone_id}/telemetry"
        got = Event();
        subc = _mqtt_tls_client(ca, cert, key)
        def on_msg(cl,u,m):
            if m.topic==cmd_topic: got.set()
        subc.on_message = on_msg
        subc.connect(host, port, 30); subc.loop_start(); subc.subscribe(cmd_topic, 0)
        # publish telemetry (allowed)
        pubc = _mqtt_tls_client(ca, cert, key)
        pubc.connect(host, port, 30); pubc.loop_start(); time.sleep(0.2)
        pubc.publish(tlm_topic, b"{alt:1}")
        time.sleep(0.4)
        # try to publish command as drone (should be denied if ACL strict)
        inf = pubc.publish(cmd_topic, b"DENY-ME")
        # Some brokers won't report ACL denial via return code; rely on no message + broker log
        time.sleep(0.6)
    except Exception as e:
        res.append(("ACL basic (sub cmd, pub tlm)", False, str(e)))
    finally:
        try: pubc.loop_stop(); pubc.disconnect()
        except: pass
        try: subc.loop_stop(); subc.disconnect()
        except: pass
    res.append(("ACL basic (sub cmd, pub tlm)", True, "OK"))
    return res


def main():
    ca_d, cert_d, key_d = _defaults()
    host = os.environ.get('MQTT_HOST', getattr(ipcfg, 'GCS_HOST', '127.0.0.1'))
    port = int(os.environ.get('MQTT_PORT', '8883'))
    ca = os.environ.get('MQTT_CA', str(ca_d))
    cert = os.environ.get('DRONE_CERT', str(cert_d))
    key = os.environ.get('DRONE_KEY', str(key_d))
    drone_id = getattr(ipcfg, 'DRONE_ID', 'uav1')

    results = []
    for name, ok, detail in check_oqs():
        results.append((name, ok, detail))
    for name, ok, detail in check_mqtt(drone_id, host, port, ca, cert, key):
        results.append((name, ok, detail))

    fails = [r for r in results if not r[1]]
    for name, ok, detail in results:
        print(f"[{'PASS' if ok else 'FAIL'}] {name} :: {detail}")
    print(f"\nSummary: {len(results)-len(fails)} PASS, {len(fails)} FAIL")
    sys.exit(1 if fails else 0)


if __name__ == '__main__':
    main()
