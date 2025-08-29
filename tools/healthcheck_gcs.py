#!/usr/bin/env python3
"""
GCS Healthcheck: verifies end-to-end MQTT mTLS and ACLs using your generated certs.
- Imports gcs/ip_config.py for host and IDs.
- Connects as gcs1 and uav1 to exercise telemetry and command flows.
- Prints PASS/FAIL per check; exits nonzero if any fail.

Usage (Windows PowerShell):
  python tools/healthcheck_gcs.py

Environment overrides (optional):
  MQTT_HOST  -> broker host (defaults to ip_config.GCS_HOST)
  MQTT_PORT  -> broker port (defaults to 8883)
  MQTT_CA    -> path to CA file (default: Program Files mosquitto or .uav-mosq/server)
  GCS_CERT,GCS_KEY -> gcs1 cert/key paths (default: .uav-mosq/clients)
  UAV_CERT,UAV_KEY -> uav1 cert/key paths (default: .uav-mosq/clients)
"""
from __future__ import annotations
import sys, os, time, ssl, socket
from pathlib import Path
from dataclasses import dataclass
from threading import Event


def _import_ip_config():
    # Ensure we can import gcs/ip_config.py even if 'gcs' isn't a package
    repo_root = Path(__file__).resolve().parents[1]
    gcs_dir = repo_root / 'gcs'
    sys.path.insert(0, str(gcs_dir))
    import ip_config  # type: ignore
    return ip_config


ipcfg = _import_ip_config()


def _default_paths():
    repo_root = Path(__file__).resolve().parents[1]
    # CA: prefer Program Files mosquitto; fallback to .uav-mosq
    ca_candidates = [
        Path('C:/Program Files/mosquitto/server/ca-cert.pem'),
        repo_root / '.uav-mosq' / 'server' / 'ca-cert.pem',
    ]
    ca_file = next((p for p in ca_candidates if p.exists()), ca_candidates[-1])

    clients = repo_root / '.uav-mosq' / 'clients'
    gcs_cert = clients / 'gcs1-cert.pem'
    gcs_key = clients / 'gcs1-key.pem'
    uav_cert = clients / f"{ipcfg.DRONE_ID}-cert.pem"
    uav_key = clients / f"{ipcfg.DRONE_ID}-key.pem"
    return ca_file, gcs_cert, gcs_key, uav_cert, uav_key


def _env_path(name: str, fallback: Path) -> str:
    return os.environ.get(name) or str(fallback)


@dataclass
class CheckResult:
    name: str
    ok: bool
    detail: str = ''


def _mqtt_tls_client(cafile: str, certfile: str, keyfile: str):
    import paho.mqtt.client as mqtt
    client = mqtt.Client(protocol=mqtt.MQTTv311)
    # TLS context
    client.tls_set(ca_certs=cafile, certfile=certfile, keyfile=keyfile, tls_version=ssl.PROTOCOL_TLS_CLIENT)
    client.tls_insecure_set(False)
    return client


def check_connect(host: str, port: int, cafile: str, certfile: str, keyfile: str, timeout=8) -> CheckResult:
    ev = Event()
    err: list[str] = []
    try:
        client = _mqtt_tls_client(cafile, certfile, keyfile)
    except Exception as e:
        return CheckResult('TLS context (certs present/valid)', False, str(e))

    def on_connect(c, u, f, rc, props=None):
        if rc == 0:
            ev.set()
        else:
            err.append(f"RC={rc}")
            ev.set()

    client.on_connect = on_connect
    try:
        client.connect(host, port, keepalive=30)
        client.loop_start()
        ev.wait(timeout)
        client.loop_stop()
        client.disconnect()
    except Exception as e:
        return CheckResult('Broker connect (mTLS)', False, str(e))
    return CheckResult('Broker connect (mTLS)', not err and ev.is_set(), '; '.join(err) or 'OK')


def check_acl_roundtrip(host: str, port: int, cafile: str, gcs_cert: str, gcs_key: str, uav_cert: str, uav_key: str, drone_id: str, timeout=8) -> list[CheckResult]:
    import paho.mqtt.client as mqtt
    results: list[CheckResult] = []

    # GCS subscribe to telemetry, UAV publish telemetry
    telemetry_topic = f"fleet/{drone_id}/telemetry"
    got_tlm = Event(); tlm_payload = b''

    def gcs_on_message(c, u, msg):
        nonlocal tlm_payload
        if msg.topic == telemetry_topic:
            tlm_payload = msg.payload
            got_tlm.set()

    gcs = _mqtt_tls_client(cafile, gcs_cert, gcs_key)
    gcs.on_message = gcs_on_message
    try:
        gcs.connect(host, port, 30)
        gcs.loop_start()
        gcs.subscribe(telemetry_topic, qos=0)
    except Exception as e:
        results.append(CheckResult('GCS subscribe telemetry', False, str(e)))
        try:
            gcs.loop_stop(); gcs.disconnect()
        except: pass
        return results

    uav = _mqtt_tls_client(cafile, uav_cert, uav_key)
    try:
        uav.connect(host, port, 30)
        uav.loop_start()
        time.sleep(0.3)
        uav.publish(telemetry_topic, b'{"alt":12}', qos=0)
        got_tlm.wait(timeout)
    except Exception as e:
        results.append(CheckResult('UAV publish telemetry', False, str(e)))
    finally:
        try:
            uav.loop_stop(); uav.disconnect()
        except: pass

    results.append(CheckResult('Telemetry roundtrip (GCS<=UAV)', got_tlm.is_set(), f"payload={tlm_payload!r}" if got_tlm.is_set() else 'no message'))

    # UAV subscribe to commands, GCS publish command
    cmd_topic = f"fleet/{drone_id}/commands"
    got_cmd = Event(); cmd_payload = b''

    def uav_on_message(c, u, msg):
        nonlocal cmd_payload
        if msg.topic == cmd_topic:
            cmd_payload = msg.payload
            got_cmd.set()

    uav2 = _mqtt_tls_client(cafile, uav_cert, uav_key)
    uav2.on_message = uav_on_message
    try:
        uav2.connect(host, port, 30)
        uav2.loop_start()
        uav2.subscribe(cmd_topic, qos=0)
    except Exception as e:
        results.append(CheckResult('UAV subscribe commands', False, str(e)))
        try: uav2.loop_stop(); uav2.disconnect()
        except: pass
        return results

    gcs2 = _mqtt_tls_client(cafile, gcs_cert, gcs_key)
    try:
        gcs2.connect(host, port, 30)
        gcs2.loop_start()
        time.sleep(0.3)
        gcs2.publish(cmd_topic, b'TAKEOFF', qos=0)
        got_cmd.wait(timeout)
    except Exception as e:
        results.append(CheckResult('GCS publish command', False, str(e)))
    finally:
        try: gcs2.loop_stop(); gcs2.disconnect()
        except: pass
        try: uav2.loop_stop(); uav2.disconnect()
        except: pass

    results.append(CheckResult('Command roundtrip (GCS=>UAV)', got_cmd.is_set(), f"payload={cmd_payload!r}" if got_cmd.is_set() else 'no message'))
    return results


def main():
    ca_file, gcs_cert_d, gcs_key_d, uav_cert_d, uav_key_d = _default_paths()
    host = os.environ.get('MQTT_HOST', getattr(ipcfg, 'GCS_HOST', '127.0.0.1'))
    port = int(os.environ.get('MQTT_PORT', '8883'))
    ca = _env_path('MQTT_CA', ca_file)
    gcs_cert = _env_path('GCS_CERT', gcs_cert_d)
    gcs_key = _env_path('GCS_KEY', gcs_key_d)
    uav_cert = _env_path('UAV_CERT', uav_cert_d)
    uav_key = _env_path('UAV_KEY', uav_key_d)
    drone_id = getattr(ipcfg, 'DRONE_ID', 'uav1')

    checks: list[CheckResult] = []

    # Basic file presence
    for nm, p in [('CA', ca), ('GCS cert', gcs_cert), ('GCS key', gcs_key), ('UAV cert', uav_cert), ('UAV key', uav_key)]:
        ok = Path(p).exists()
        checks.append(CheckResult(f'File: {nm}', ok, p))

    # Connect tests (as GCS and UAV)
    checks.append(check_connect(host, port, ca, gcs_cert, gcs_key))
    checks.append(check_connect(host, port, ca, uav_cert, uav_key))

    # Round-trip ACL checks
    checks.extend(check_acl_roundtrip(host, port, ca, gcs_cert, gcs_key, uav_cert, uav_key, drone_id))

    # Print summary
    failed = [c for c in checks if not c.ok]
    for c in checks:
        status = 'PASS' if c.ok else 'FAIL'
        print(f"[{status}] {c.name} :: {c.detail}")
    print(f"\nSummary: {len(checks)-len(failed)} PASS, {len(failed)} FAIL")
    sys.exit(1 if failed else 0)


if __name__ == '__main__':
    main()
