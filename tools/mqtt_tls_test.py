#!/usr/bin/env python3
"""
MQTT TLS test using repo certs (gcs/certs):
- Uses client cert/key for identity (default: gcs1-cert.pem, gcs1-key.pem)
- Connects to broker, subscribes to a topic, publishes a test message
- Verifies round-trip receive and prints PASS/FAIL

Defaults:
- Broker: hostname from gcs/ip_config.py if available, else localhost
- Port: 8883
- Cert dir: <repo>/gcs/certs (detected relative to this file)
- Topic: swarm/broadcast/alert (GCS commonly allowed to pub/sub)
"""

import argparse
import os
import sys
import time
import ssl
import json
import random
import string
from pathlib import Path

try:
	import paho.mqtt.client as mqtt
except ImportError:
	print("Missing dependency: paho-mqtt. Install with: pip install paho-mqtt>=1.6.0")
	sys.exit(1)


def repo_root() -> Path:
	return Path(__file__).resolve().parent.parent


def default_broker_host() -> str:
	root = repo_root()
	sys.path.insert(0, str(root))
	try:
		# Try gcs/ip_config.py for a broker host
		import gcs.ip_config as gip  # type: ignore
		for name in ("BROKER_HOST", "GCS_HOST", "HOST", "BROKER_IP"):
			v = getattr(gip, name, None)
			if isinstance(v, str) and v.strip():
				return v.strip()
	except Exception:
		pass
	return "localhost"


def random_suffix(n: int = 6) -> str:
	return ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def parse_args() -> argparse.Namespace:
	default_certs = repo_root() / "gcs" / "certs"
	parser = argparse.ArgumentParser(description="MQTT TLS test with client certificates")
	parser.add_argument("--host", default=default_broker_host(), help="Broker hostname or IP (default: autodetected or localhost)")
	parser.add_argument("--port", type=int, default=8883, help="Broker TLS port (default: 8883)")
	parser.add_argument("--cert-dir", default=str(default_certs), help="Directory containing ca-cert.pem and <id>-cert/key.pem (default: gcs/certs)")
	parser.add_argument("--client-id", default="gcs1", help="Client ID (must match cert CN, default: gcs1)")
	parser.add_argument("--topic", default="swarm/broadcast/alert", help="Topic to subscribe/publish for loopback test")
	parser.add_argument("--qos", type=int, default=1, choices=[0,1,2], help="QoS for subscribe/publish (default: 1)")
	parser.add_argument("--verify-hostname", action="store_true", help="Verify broker hostname against server cert (default: disabled)")
	parser.add_argument("--timeout", type=float, default=8.0, help="Seconds to wait for connect and message (default: 8.0)")
	return parser.parse_args()


class MqttTlsTester:
	def __init__(self, host: str, port: int, cert_dir: Path, client_id: str, topic: str, qos: int, verify_hostname: bool, timeout: float):
		self.host = host
		self.port = port
		self.cert_dir = cert_dir
		self.client_id = client_id
		self.topic = topic
		self.qos = qos
		self.verify_hostname = verify_hostname
		self.timeout = timeout
		self.received = None
		# Use v311 clean session client
		self.client = mqtt.Client(client_id=self.client_id, protocol=mqtt.MQTTv311, clean_session=True)
		self._connected = False

	def _paths(self):
		ca = self.cert_dir / "ca-cert.pem"
		cert = self.cert_dir / f"{self.client_id}-cert.pem"
		key = self.cert_dir / f"{self.client_id}-key.pem"
		return ca, cert, key

	def _on_connect(self, client, userdata, flags, rc):
		if rc == 0:
			self._connected = True
		else:
			print(f"Connect failed rc={rc}")

	def _on_message(self, client, userdata, msg):
		try:
			payload = msg.payload.decode('utf-8', errors='ignore')
		except Exception:
			payload = msg.payload
		self.received = {"topic": msg.topic, "payload": payload}

	def run(self) -> bool:
		ca, cert, key = self._paths()
		# Print resolved paths for transparency
		print("Using certificates:")
		print(f"  CA   : {ca}")
		print(f"  Cert : {cert}")
		print(f"  Key  : {key}")

		for p in (ca, cert, key):
			if not p.exists():
				print(f"ERROR: Missing file: {p}")
				return False

		# TLS setup
		self.client.tls_set(ca_certs=str(ca), certfile=str(cert), keyfile=str(key), tls_version=ssl.PROTOCOL_TLS, cert_reqs=ssl.CERT_REQUIRED)
		self.client.tls_insecure_set(not self.verify_hostname)

		# Bind callbacks
		self.client.on_connect = self._on_connect
		self.client.on_message = self._on_message

		# Connect synchronously, then start network loop
		try:
			self.client.connect(self.host, self.port, keepalive=60)
		except Exception as e:
			print(f"ERROR: Connect exception: {e}")
			return False
		self.client.loop_start()

		start = time.time()
		# Wait for on_connect to set the connected flag
		deadline = start + self.timeout
		while time.time() < deadline and not self._connected:
			time.sleep(0.05)
		if not self._connected:
			print("FAIL: Timed out waiting for MQTT TLS connection")
			self.client.loop_stop(); self.client.disconnect()
			return False

		# Subscribe to topic explicitly after connection
		s = self.client.subscribe(self.topic, self.qos)
		if isinstance(s, tuple):
			rc = s[0]
		else:
			rc = getattr(s, 'rc', 0)
		if rc not in (0, mqtt.MQTT_ERR_SUCCESS):
			print(f"ERROR: Subscribe failed rc={rc}")
			self.client.loop_stop(); self.client.disconnect()
			return False

		# Publish a unique payload
		marker = f"mqtt-test-{int(start)}-{random_suffix()}"
		payload = json.dumps({"marker": marker, "ts": start})
		info = self.client.publish(self.topic, payload, qos=self.qos, retain=False)
		if info.rc != mqtt.MQTT_ERR_SUCCESS:
			print(f"Publish failed rc={info.rc}")
			self.client.loop_stop(); self.client.disconnect()
			return False

		# Await receipt of our own message (loopback)
		deadline = start + self.timeout
		while time.time() < deadline and self.received is None:
			time.sleep(0.05)

		self.client.loop_stop(); self.client.disconnect()

		if not self.received:
			print("FAIL: No message received back on subscribed topic (ACL may block subscribe or broker not delivering to same client)")
			return False

		try:
			data = json.loads(self.received["payload"]) if isinstance(self.received["payload"], str) else {}
		except Exception:
			data = {}
		ok = isinstance(data, dict) and data.get("marker") == marker
		if ok:
			print("PASS: Connected and received published message")
			return True
		else:
			print("FAIL: Received message did not match our published marker")
			return False


def main():
	args = parse_args()
	tester = MqttTlsTester(
		host=args.host,
		port=args.port,
		cert_dir=Path(args.cert_dir),
		client_id=args.client_id,
		topic=args.topic,
		qos=args.qos,
		verify_hostname=args.verify_hostname,
		timeout=args.timeout,
	)
	ok = tester.run()
	sys.exit(0 if ok else 2)


if __name__ == "__main__":
	main()

