# ==============================================================================
# gcs_controller.py
#
# PURPOSE:
#   A command-line tool to send control commands to the crypto_manager.py.
#   This simulates the action your main GCS GUI will take when the user
#   clicks a button to switch cryptographic algorithms.
#
#   It connects to the manager via TCP, sends a single command, prints the
#   response from the manager, and exits.
#
# HOW TO RUN:
#   1. Make sure crypto_manager.py is already running in another terminal.
#   2. Open a new terminal and activate the conda environment.
#   3. Run with a command. Examples:
#
#      # Switch to the ASCON proxy (c1)
#      python gcs_controller.py switch c1
#
#      # Switch to the Kyber Hybrid proxy (c6)
#      python gcs_controller.py switch c6
#
#      # Check the status of the manager
#      python gcs_controller.py status
#
#      # Stop the currently running proxy
#      python gcs_controller.py stop
# ==============================================================================

import socket
import argparse

# --- CONFIGURATION ---
# These MUST match the host and port in crypto_manager.py
MANAGER_HOST = '127.0.0.1'
MANAGER_PORT = 5900

def send_command(command):
    """Connects to the manager, sends a command, and prints the response."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((MANAGER_HOST, MANAGER_PORT))
            sock.sendall(command.encode('utf-8'))
            response = sock.recv(1024).decode('utf-8')
            print(f"Response from Manager: {response}")
    except ConnectionRefusedError:
        print(f"ERROR: Connection refused. Is crypto_manager.py running on {MANAGER_HOST}:{MANAGER_PORT}?")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Send control commands to the Crypto Manager.")
    
    # Using subparsers for a clean command structure like 'git push' or 'docker run'
    subparsers = parser.add_subparsers(dest="command", required=True, help="Available commands")

    # 'switch' command
    parser_switch = subparsers.add_parser("switch", help="Switch to a specific crypto proxy.")
    parser_switch.add_argument("code", type=str, help="The crypto code to switch to (e.g., c1, c2, ... c8).")

    # 'status' command
    parser_status = subparsers.add_parser("status", help="Check the current status of the crypto proxy.")

    # 'stop' command
    parser_stop = subparsers.add_parser("stop", help="Stop the currently running crypto proxy.")

    args = parser.parse_args()

    # Construct the command string from the parsed arguments
    if args.command == "switch":
        full_command = f"SWITCH {args.code}"
    else: # For 'status' and 'stop'
        full_command = args.command.upper()

    send_command(full_command)
