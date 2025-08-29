#!/usr/bin/env python3
import argparse, ssl, sys, time
from pathlib import Path

try:
    import paho.mqtt.client as mqtt
except ImportError:
    print("Install paho-mqtt: pip install paho-mqtt>=1.6.0"); sys.exit(1)

DEFAULT_CERTS = Path(__file__).resolve().parents[1] / 'certs'

ID_MAP = {
    # maps client-id to file stem
    'uavpi-gcs': 'uavpi-gcs',
}

def map_files(client_id: str):
    stem = ID_MAP.get(client_id, client_id)
    cafile = DEFAULT_CERTS / 'ca-cert.pem'
    certfile = DEFAULT_CERTS / f'{stem}-cert.pem'
    keyfile = DEFAULT_CERTS / f'{stem}-key.pem'
    return cafile, certfile, keyfile


def on_connect(client, userdata, flags, rc, properties=None):
    if rc == 0:
        print("Connected")
    else:
        print(f"Connect failed rc={rc}")


def on_message(client, userdata, msg):
    print(f"< {msg.topic} [{msg.qos}]: {msg.payload[:200]!r}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--host', default='127.0.0.1')
    ap.add_argument('--port', type=int, default=8883)
    ap.add_argument('--client-id', required=True)
    ap.add_argument('--topic', default='swarm/broadcast/crypto')
    ap.add_argument('--qos', type=int, default=1)
    ap.add_argument('--message', default=None)
    ap.add_argument('--cafile', default=None)
    ap.add_argument('--certfile', default=None)
    ap.add_argument('--keyfile', default=None)
    args = ap.parse_args()

    cafile = Path(args.cafile) if args.cafile else map_files(args.client_id)[0]
    certfile = Path(args.certfile) if args.certfile else map_files(args.client_id)[1]
    keyfile = Path(args.keyfile) if args.keyfile else map_files(args.client_id)[2]

    for p in (cafile, certfile, keyfile):
        if not p.exists():
            print(f"Missing: {p}"); sys.exit(2)

    client = mqtt.Client(client_id=args.client_id, protocol=mqtt.MQTTv311, clean_session=True)
    client.on_connect = on_connect
    client.on_message = on_message

    client.tls_set(ca_certs=str(cafile), certfile=str(certfile), keyfile=str(keyfile),
                   cert_reqs=ssl.CERT_REQUIRED, tls_version=ssl.PROTOCOL_TLSv1_2)

    # no insecure overrides

    client.connect(args.host, args.port, keepalive=60)

    # Subscribe common topics
    client.subscribe('swarm/broadcast/#', qos=1)
    if args.client_id.startswith('uavpi-drone-'):
        client.subscribe(f'swarm/commands/individual/{args.client_id}', qos=1)

    client.loop_start()

    time.sleep(1.0)
    msg = args.message or f'hello from {args.client_id}'
    if args.client_id.startswith('uavpi-drone-'):
        topic = f'swarm/status/{args.client_id}'
    elif args.client_id == 'uavpi-gcs':
        topic = 'swarm/broadcast/crypto'
    else:
        topic = args.topic

    print(f"> {topic} [{args.qos}]: {msg}")
    client.publish(topic, msg, qos=args.qos, retain=False)

    time.sleep(2.0)
    client.loop_stop()
    client.disconnect()

if __name__ == '__main__':
    main()
