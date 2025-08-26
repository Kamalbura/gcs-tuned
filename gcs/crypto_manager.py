# ==============================================================================
# crypto_manager.py
#
# PURPOSE:
#   Acts as a dedicated supervisor for the 8 GCS cryptographic proxies.
#   This script runs as a persistent background service. It listens on a local
#   TCP port for simple text commands (e.g., "SWITCH c1") from the main GCS
#   application or the gcs_controller.py tool.
#
#   This approach decouples process management from your main GUI, making the
#   entire system more robust, modular, and easier to debug.
#
# HOW IT WORKS:
#   1. Starts a TCP server on a local port.
#   2. Waits for a connection.
#   3. Receives a command (e.g., "SWITCH c2").
#   4. If a proxy is already running, it gracefully terminates it. This is
#      CRITICAL to free up the MAVLink network ports.
#   5. It looks up the command code (e.g., "c2") in its script map and starts
#      the corresponding proxy script (e.g., "gcs_kyber.py") as a new
#      subprocess.
#   6. Sends a confirmation reply ("OK" or "ERROR") back to the controller.
#
# HOW TO RUN:
#   1. Make sure all 16 proxy scripts and ip_config.py are in the same directory.
#   2. Open a terminal and activate the conda environment: `conda activate gcs-env`
#   3. Run this script: `python crypto_manager.py`
#   4. Leave this terminal running.
# ==============================================================================

import socket
import subprocess
import threading
import os
import signal
import sys
import time

# --- CONFIGURATION ---
MANAGER_HOST = '127.0.0.1'  # Listen only on localhost for security
MANAGER_PORT = 5900         # Port for receiving commands

# This map is the "brain" of the manager. It connects the simple command
# codes (c1, c2, etc.) to the actual script filenames.
CRYPTO_MAP = {
    "c1": "gcs_ascon.py",
    "c2": "gcs_speck.py",
    "c3": "gcs_camellia.py",
    "c4": "gcs_hight.py",
    "c5": "gcs_dilithium.py",
    "c6": "gcs_kyber.py",
    "c7": "gcs_sphincs.py",
    "c8": "gcs_falcon.py",
}

class CryptoManager:
    """
    Manages the lifecycle of GCS cryptographic proxy subprocesses.
    """
    def __init__(self):
        self.current_process = None
        self.current_code = None
        # Ensure we use the same Python interpreter that's running this script
        self.python_executable = sys.executable

    def stop_current_proxy(self):
        """Gracefully stops the currently running proxy process."""
        if self.current_process and self.current_process.poll() is None:
            print(f"[Manager] Stopping proxy '{self.current_code}' (PID: {self.current_process.pid})...")
            try:
                # Use process group termination for robustness
                if os.name == 'nt': # Windows
                    # Sends CTRL+C, more graceful than taskkill
                    self.current_process.send_signal(signal.CTRL_C_EVENT)
                else: # Linux/macOS
                    os.killpg(os.getpgid(self.current_process.pid), signal.SIGTERM)
                
                self.current_process.wait(timeout=3) # Wait up to 3 seconds
                print("[Manager] Process terminated gracefully.")
            except subprocess.TimeoutExpired:
                print("[Manager] Process did not terminate gracefully. Forcing kill...")
                self.current_process.kill() # Force kill if it doesn't respond
            except Exception as e:
                print(f"[Manager] Error stopping process: {e}")
        self.current_process = None
        self.current_code = None
        # Short delay to allow OS to release network sockets
        time.sleep(0.5)

    def start_proxy(self, code):
        """Starts a new proxy based on the provided code."""
        if code not in CRYPTO_MAP:
            return f"ERROR: Unknown crypto code '{code}'"

        script_name = CRYPTO_MAP[code]
        script_path = os.path.join(os.path.dirname(__file__), script_name)

        if not os.path.exists(script_path):
            return f"ERROR: Script '{script_name}' not found."

        print(f"[Manager] Starting proxy '{code}': {script_name}...")
        try:
            # Creation flags for creating a new process group on Windows
            creationflags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == 'nt' else 0
            
            self.current_process = subprocess.Popen(
                [self.python_executable, script_path],
                creationflags=creationflags,
                preexec_fn=os.setsid if os.name != 'nt' else None # Create new session on POSIX
            )
            self.current_code = code
            # Give it a moment to start and check if it crashed immediately
            time.sleep(1)
            if self.current_process.poll() is not None:
                return f"ERROR: Process for '{script_name}' terminated immediately."
            
            print(f"[Manager] Started '{script_name}' successfully (PID: {self.current_process.pid}).")
            return f"OK: Switched to {code} ({script_name})"
        except Exception as e:
            return f"ERROR: Failed to start process for '{script_name}': {e}"

    def handle_command(self, command_str):
        """Parses and executes a command."""
        parts = command_str.strip().upper().split()
        command = parts[0]

        if command == "SWITCH" and len(parts) > 1:
            code = parts[1].lower()
            self.stop_current_proxy()
            response = self.start_proxy(code)
        elif command == "STOP":
            self.stop_current_proxy()
            response = "OK: Proxy stopped."
        elif command == "STATUS":
            if self.current_process and self.current_process.poll() is None:
                response = f"OK: Running {self.current_code} ({CRYPTO_MAP.get(self.current_code)})"
            else:
                response = "OK: No proxy running."
        else:
            response = "ERROR: Unknown command. Use SWITCH <code>, STOP, or STATUS."
        
        return response

def handle_client_connection(conn, manager):
    """Handles a single client connection to the manager."""
    try:
        data = conn.recv(1024)
        if data:
            command = data.decode('utf-8')
            print(f"[Manager] Received command: {command.strip()}")
            response = manager.handle_command(command)
            conn.sendall(response.encode('utf-8'))
    except Exception as e:
        print(f"[Manager] Error handling client: {e}")
    finally:
        conn.close()

def run_manager():
    manager = CryptoManager()
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((MANAGER_HOST, MANAGER_PORT))
    server_socket.listen(5)
    print(f"--- CRYPTOGRAPHY MANAGER ---")
    print(f"✅ Listening for commands on {MANAGER_HOST}:{MANAGER_PORT}")
    print("Run gcs_controller.py in another terminal to send commands.")

    try:
        while True:
            conn, addr = server_socket.accept()
            # No need for a new thread if commands are quick
            handle_client_connection(conn, manager)
    except KeyboardInterrupt:
        print("\n[Manager] Shutdown signal received.")
    finally:
        print("[Manager] Cleaning up...")
        manager.stop_current_proxy()
        server_socket.close()
        print("[Manager] Shutdown complete.")

if __name__ == "__main__":
    run_manager()
