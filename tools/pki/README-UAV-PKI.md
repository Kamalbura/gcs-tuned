UAV Fleet PKI Generator

This folder contains a non-interactive OpenSSL configuration and a PowerShell generator to build a UAV-focused PKI and Mosquitto configuration on Windows.

Files
- openssl_uav.cnf: OpenSSL profiles for CA, server (with SAN), and client certs.
- generate-uav-pki.ps1: Generator script creating CA, server, clients, ACL, and mosquitto.conf.

Usage
1) Open an elevated PowerShell window.
2) Run:
   powershell -ExecutionPolicy Bypass -File .\generate-uav-pki.ps1 -MosquittoRoot "C:\Program Files\mosquitto" -BrokerCN "uav-broker.local" -UavIds uav1,uav2 -GcsIds gcs1 -Force
3) Restart Mosquitto service after generation.

Notes
- SANs are defined in openssl_uav.cnf under [alt_names]. Add your LAN IP if needed.
- ACL grants GCS read fleet/status/# and write fleet/command/#; UAVs write fleet/status/<id> and read fleet/command/<id>.
- Config paths use forward slashes for Mosquitto on Windows.
