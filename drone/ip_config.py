# ==============================================================================
# ip_config.py (Drone Version)
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
