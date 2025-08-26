# ==============================================================================
# ip_config.py
#
# PURPOSE:
#   Centralized IP and Port Configuration for the GCS and Drone framework.
#   Edit ONLY this file to change network addresses. All other scripts
#   import their settings from here for consistency.
#
# INITIAL SETUP:
#   All hosts are set to "127.0.0.1" (localhost) for easy testing of all
#   components on a single machine.
#
# DEPLOYMENT:
#   When deploying to a real network, change GCS_HOST and DRONE_HOST to the
#   actual IP addresses of your machines.
# ==============================================================================

# --- HOST ADDRESSES ---
# Change these when you move from local testing to a real network.
GCS_HOST = "127.0.0.1"    # The primary IP address of the GCS machine.
DRONE_HOST = "127.0.0.1"  # The primary IP address of the Drone machine.

# --- NETWORK PORTS ---
# A new, clean set of ports to avoid conflicts with old scripts.

# Port for PQC Key Exchange (Kyber public keys, signatures, etc.)
PORT_KEY_EXCHANGE = 5800

# Ports for MAVLink Command Flow (GCS App -> Drone)
# 1. GCS App sends plaintext MAVLink to this local port.
PORT_GCS_LISTEN_PLAINTEXT_CMD = 5810
# 2. Drone's crypto proxy listens for encrypted commands on this port.
PORT_DRONE_LISTEN_ENCRYPTED_CMD = 5811
# 3. Drone's crypto proxy forwards decrypted commands to the flight controller on this local port.
PORT_DRONE_FORWARD_DECRYPTED_CMD = 5812

# Ports for MAVLink Telemetry Flow (Drone -> GCS App)
# 1. Drone's flight controller sends plaintext MAVLink to this local port.
PORT_DRONE_LISTEN_PLAINTEXT_TLM = 5820
# 2. GCS crypto proxy listens for encrypted telemetry on this port.
PORT_GCS_LISTEN_ENCRYPTED_TLM = 5821
# 3. GCS crypto proxy forwards decrypted telemetry to the GCS application on this local port.
PORT_GCS_FORWARD_DECRYPTED_TLM = 5822

# --- CRYPTOGRAPHY CONSTANTS ---
# Standard size for Nonce/IV in bytes for AES-GCM, ASCON, and CBC modes.
NONCE_IV_SIZE = 12

# --- RUNTIME/PERSISTENT UPDATE HELPERS (for Scheduler UI) ---
# Runtime updates affect this module in-memory only (callers already imported it).
# Persistent updates modify this file on disk by replacing the lines for GCS_HOST/DRONE_HOST.
from typing import Optional, List
import re, time

def set_hosts_runtime(new_gcs: Optional[str]=None, new_drone: Optional[str]=None) -> List[str]:
	changed=[]
	global GCS_HOST, DRONE_HOST
	if new_gcs and new_gcs != GCS_HOST:
		GCS_HOST = new_gcs; changed.append(f"GCS_HOST->{new_gcs}")
	if new_drone and new_drone != DRONE_HOST:
		DRONE_HOST = new_drone; changed.append(f"DRONE_HOST->{new_drone}")
	return changed

def update_hosts_persistent(new_gcs: Optional[str]=None, new_drone: Optional[str]=None) -> List[str]:
	"""Edit this ip_config.py to persist new host values. Returns list of changes applied."""
	path = __file__
	try:
		with open(path, 'r', encoding='utf-8') as f:
			content = f.read()
		changes=[]
		def repl_line(src:str, key:str, val:Optional[str]) -> str:
			nonlocal changes
			if not val: return src
			pattern = rf"^(\s*{key}\s*=\s*)\"[^\"]*\""
			ts = time.strftime('%Y-%m-%d %H:%M:%S')
			new_src, n = re.subn(pattern, rf"# updated {ts} \g<0>\n{key} = \"{val}\"", src, count=1, flags=re.MULTILINE)
			if n:
				changes.append(f"{key}->{val}")
				return new_src
			return src
		content2 = repl_line(content, 'GCS_HOST', new_gcs)
		content3 = repl_line(content2, 'DRONE_HOST', new_drone)
		if content3 != content:
			with open(path, 'w', encoding='utf-8') as f:
				f.write(content3)
		return changes
	except Exception:
		return []
