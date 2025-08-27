# GCS Scheduler — Visual Guide and Storyline

This guide explains the Ground Control Station (GCS) side of the system: what it does, how it schedules work, and how it stays reliable and secure. It’s meant for engineers and stakeholders—skim the visuals first, then dive into the details.

## Narrative: What the GCS does and why

In a live mission, the GCS is the control-plane brain. It orchestrates crypto proxies, the MAVLink core, and fleet coordination via MQTT+TLS. Operators can switch algorithms on-the-fly (e.g., upgrade to stronger crypto during higher threat), broadcast alerts, and track telemetry—all without interrupting flight.

## Architecture at a glance

```mermaid
flowchart LR
  subgraph GCS Host
    UI[GCS Scheduler GUI]
  M[MQTT Client TLS]
  P[Crypto Proxy gcs]
    C[MAVLink Core]
  end
  subgraph Broker
    B[(MQTT Broker)]
  end
  subgraph Drone Host
    DP[Drone Proxy]
    FC[Flight Controller]
  end

  UI -- start/stop --> P
  UI -- start/stop --> C
  UI -- publish crypto/alerts --> M
  M <--> B
  B <--> DP
  P <--> DP
  DP <--> FC
```

## Scheduling model (how the GCS “schedules” work)

- Event-driven orchestration: user actions and MQTT messages drive state changes.
- Process lifecycle control: start/stop proxies and core with safe termination and restart.
- Policy toggles:
  - Auto start core on connect
  - Auto apply local crypto when receiving broadcast code
- Connection resilience: TLS MQTT with topic subscriptions and retained status.

### Timeline (typical session)

```mermaid
gantt
  dateFormat  X
  title GCS Orchestration Timeline
  section Connect
  MQTT connect             :done, 0, 1
  Subscribe topics         :done, 1, 1
  section Start
  Start MAVLink Core       :active, 2, 1
  Start Crypto Proxy       :active, 2, 1
  section Operate
  Heartbeats/Telemetry     : 3, 5
  Crypto Switch (broadcast): 4, 1
```

## Component overview

- GcsMqttClient
  - TLS with CA validation; optional hostname verify disabled for IP brokers
  - Connects async with timeout; publishes retained “online” status
- GcsCryptoManager
  - Maps c1..c8 to local `gcs_*.py` proxies; safe process start/stop
- GcsCoreManager
  - Starts MAVLink core script (customizable) with detached stdin
- GcsMavlinkManager
  - Uses pymavlink if available; else raw UDP mode

## Message flows

### MQTT connect and broadcast crypto

```mermaid
sequenceDiagram
  participant UI as GCS UI
  participant MQ as MQTT (TLS)
  participant BR as Broker
  participant DR as Drone
  UI->>MQ: connect()
  MQ->>BR: TLS connect
  BR-->>MQ: connack + subs ok
  UI->>MQ: publish c2 to swarm/broadcast/crypto
  MQ->>BR: PUBLISH c2
  BR->>DR: deliver c2
  Note over DR: Drone switches local crypto proxy
```

### MAVLink routing through proxies

```mermaid
sequenceDiagram
  participant GCS as GCS Proxy
  participant DRN as Drone Proxy
  participant FC as Flight Ctrl
  GCS->>DRN: UDP encrypted cmd
  DRN->>FC: plaintext cmd
  FC->>DRN: telemetry
  DRN->>GCS: UDP encrypted tlm
```

## Crypto codes and mappings

| Code | Algorithm         | Script          |
|------|-------------------|-----------------|
| c1   | ASCON‑128         | gcs_ascon.py    |
| c2   | Speck‑CBC         | gcs_speck.py    |
| c3   | Camellia‑CBC      | gcs_camellia.py |
| c4   | HIGHT‑CBC         | gcs_hight.py    |
| c5   | Dilithium         | gcs_dilithium.py|
| c6   | Kyber (ML‑KEM‑768)| gcs_kyber.py    |
| c7   | SPHINCS+          | gcs_sphincs.py  |
| c8   | Falcon‑512        | gcs_falcon.py   |

## MQTT topics (used by GCS)

| Purpose            | Topic                            | QoS |
|--------------------|----------------------------------|-----|
| Broadcast crypto   | swarm/broadcast/crypto           | 2   |
| Broadcast alerts   | swarm/broadcast/alert            | 2   |
| GCS status         | swarm/status/gcs                 | 1   |
| Fleet status       | swarm/status/+                   | 1   |
| Drone telemetry    | swarm/drones/+/telemetry         | 1   |
| Heartbeats         | swarm/heartbeat/+                | 1   |

## Certificates and security

- Put your TLS certs in `gcs/certs/`:
  - `ca-cert.pem`
  - `gcs-cert.pem`
  - `gcs-key.pem`
- The client also searches common locations (`../certs`, `C:/mqtt/certs`, `/etc/mqtt/certs`, `/home/dev/mqtt/certs`).
- Optional pinning stub is available in code for strict deployments.

## IP configuration (runtime vs persistent)

- Runtime: update in-memory via `ip_config.set_hosts_runtime()` (GUI button)
- Persistent: edits `gcs/ip_config.py` in-place with timestamped comments

## Try it

1) Install deps: `pip install -r gcs/requirements.txt`
2) Ensure certs exist; set broker IP; run `gcs_mqtt_scheduler.py`
3) Switch crypto (c1..c8) and watch the fleet react.

---
For a Drone-side counterpart and deeper reliability features, see `../drone/README.md`.
