#!/usr/bin/env python3
"""
Drone UAV Scheduler v14.0 (Enhanced MQTT Security & Reliability)

Adapted to this repository:
- MQTT/TLS client with cert discovery and robust reconnection.
- Queue-based, thread-safe message handling.
- Crypto task orchestration using local drone_* proxies (c1..c8).
- Heartbeat/status publishing; individual command handling.
- Cross-platform process handling (Windows/Linux).

Notes:
- DDoS and MAVLink tasks are optional and stubbed; focus is on crypto orchestration.
- Broker host/port default from drone/ip_config (GCS_HOST/PORT). Override via CLI.
"""

import os
import sys
import time
import signal
import logging
import subprocess
import threading
import argparse
import json
import queue
import random
import ssl
from enum import IntEnum, Enum
from typing import Dict, List, Optional, Tuple, Any, Callable
from dataclasses import dataclass, asdict

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

try:
    import ip_config
except Exception:
    ip_config = None

try:
    import psutil  # for system metrics
except Exception as e:
    psutil = None

try:
    import paho.mqtt.client as mqtt
except ImportError:
    print("Please install paho-mqtt>=1.6.0"); sys.exit(1)

# --- CONFIGURATION & SETUP ---
LOG_FILE = os.path.join(HERE, 'logs', f'drone_scheduler_v14.log')
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout), logging.FileHandler(LOG_FILE, encoding='utf-8')]
)
logger = logging.getLogger('DroneSchedulerV14')

def is_windows(): return os.name == 'nt'

# --- CORE DATA STRUCTURES & ENUMS ---
class TaskPriority(IntEnum):
    CRITICAL = 0
    HIGH = 1
    MEDIUM = 2

class AlgorithmType(str, Enum):
    ASCON_128 = "ascon_128"
    KYBER_CRYPTO = "kyber_crypto"
    DILITHIUM3 = "dilithium3"
    FALCON512 = "falcon512"
    CAMELLIA = "camellia"
    SPECK = "speck"
    HIGHT = "hight"
    AES_GCM = "aes_gcm"

ALGO_CODE_MAP: Dict[str, AlgorithmType] = {
    'c1': AlgorithmType.ASCON_128,
    'c2': AlgorithmType.KYBER_CRYPTO,
    'c3': AlgorithmType.DILITHIUM3,
    'c4': AlgorithmType.FALCON512,
    'c5': AlgorithmType.CAMELLIA,
    'c6': AlgorithmType.SPECK,
    'c7': AlgorithmType.HIGHT,
    'c8': AlgorithmType.AES_GCM,
}

CRYPTO_SCRIPT_MAP: Dict[AlgorithmType, Tuple[str, float]] = {
    AlgorithmType.ASCON_128: ("drone_ascon.py", 1.5),
    AlgorithmType.KYBER_CRYPTO: ("drone_kyber_hybrid.py", 2.5),
    AlgorithmType.DILITHIUM3: ("drone_dilithium.py", 2.6),
    AlgorithmType.FALCON512: ("drone_falcon.py", 2.7),
    AlgorithmType.CAMELLIA: ("drone_camellia.py", 2.2),
    AlgorithmType.SPECK: ("drone_speck.py", 2.8),
    AlgorithmType.HIGHT: ("drone_hight.py", 2.8),
    AlgorithmType.AES_GCM: ("drone_aes.py", 2.0),
}

@dataclass
class ResourceProfile:
    power_watts: float = 0.0

@dataclass
class SystemState:
    timestamp: float = 0.0
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    battery_percent: float = 100.0
    temperature: float = 45.0
    power_draw_watts: float = 0.0

@dataclass
class Task:
    id: str
    name: str
    command: List[str]
    priority: TaskPriority
    algorithm: Optional[AlgorithmType] = None
    resource_profile: Optional[ResourceProfile] = None
    status: str = "CREATED"
    start_time: Optional[float] = None
    process: Optional[subprocess.Popen] = None
    pid: Optional[int] = None
    auto_restart: bool = False

@dataclass
class MQTTMessage:
    topic: str
    payload: bytes
    qos: int
    retain: bool = False

class CertificateManager:
    def __init__(self, client_id: str):
        self.client_id = client_id
        self.ca_cert: Optional[str] = None
        self.client_cert: Optional[str] = None
        self.client_key: Optional[str] = None
        self.cert_error: Optional[str] = None
        # Common cert paths
        self.paths = [
            os.path.join(HERE, 'certs'),
            os.path.join(os.path.dirname(HERE), 'certs'),
            'C:/mqtt/certs', 'C\\mqtt\\certs', '/etc/mqtt/certs', '/home/dev/mqtt/certs'
        ]
        self.ca_name = 'ca-cert.pem'
    def resolve_certificates(self) -> bool:
        for base in self.paths:
            if not os.path.isdir(base):
                continue
            ca = os.path.join(base, self.ca_name)
            for flat in (True, False):
                cert = os.path.join(base, f"{self.client_id}-cert.pem") if flat else os.path.join(base, 'clients', f"{self.client_id}-cert.pem")
                key  = os.path.join(base, f"{self.client_id}-key.pem")  if flat else os.path.join(base, 'clients', f"{self.client_id}-key.pem")
                if all(os.path.isfile(p) for p in (ca, cert, key)):
                    self.ca_cert, self.client_cert, self.client_key = ca, cert, key
                    logger.info(f"Certs found at: {base}")
                    return True
        self.cert_error = 'No valid certificate set found'
        logger.error(self.cert_error)
        return False

class MQTTClient:
    BASE_RECONNECT_WAIT = 1.0
    MAX_RECONNECT_WAIT = 60.0
    def __init__(self, client_id: str, on_msg: Callable[[MQTTMessage], None], broker_host: str, broker_port: int):
        self.client_id = client_id
        self.on_msg_cb = on_msg
        self.broker_host = broker_host
        self.broker_port = broker_port
        self.client: Optional[mqtt.Client] = None
        self.connected = False
        self.connected_event = threading.Event()
        self.stop_event = threading.Event()
        self.reconnect_timer: Optional[threading.Timer] = None
        self.reconnect_count = 0
        self.metrics = {"tx":0, "rx":0, "sent":0, "recv":0, "reconnects":0}
        self.certmgr = CertificateManager(client_id)
        self.protocol = mqtt.MQTTv5
    def initialize(self) -> bool:
        if not self.certmgr.resolve_certificates():
            return False
        return self._setup()
    def _setup(self) -> bool:
        try:
            try:
                self.client = mqtt.Client(protocol=self.protocol, client_id=self.client_id)
            except Exception:
                self.protocol = mqtt.MQTTv311
                self.client = mqtt.Client(protocol=self.protocol, client_id=self.client_id, clean_session=True)
            self.client.on_connect = self._on_connect
            self.client.on_disconnect = self._on_disconnect
            self.client.on_message = self._on_message
            self.client.on_publish = self._on_publish
            # TLS
            ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=self.certmgr.ca_cert)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.load_cert_chain(certfile=self.certmgr.client_cert, keyfile=self.certmgr.client_key)
            self.client.tls_set_context(ctx)
            return True
        except Exception as e:
            logger.error(f"MQTT setup failed: {e}")
            return False
    def connect(self) -> bool:
        if not self.client: return False
        try:
            self.client.connect_async(self.broker_host, self.broker_port, 60)
            self.client.loop_start()
            if self.connected_event.wait(15):
                return True
            logger.error("MQTT connect timeout")
            return False
        except Exception as e:
            logger.error(f"Connect error: {e}")
            return False
    def disconnect(self):
        self.stop_event.set()
        if self.reconnect_timer: 
            try: self.reconnect_timer.cancel()
            except Exception: pass
        try:
            if self.client:
                self.client.disconnect(); self.client.loop_stop()
        except Exception: pass
    def publish(self, topic: str, obj: Any, qos: int=1, retain: bool=False) -> bool:
        if not (self.client and self.connected): return False
        try:
            payload = obj if isinstance(obj, (str, bytes, bytearray)) else json.dumps(obj)
            r = self.client.publish(topic, payload, qos=qos, retain=retain)
            ok = (r.rc == mqtt.MQTT_ERR_SUCCESS)
            if ok:
                self.metrics["sent"] += 1
                try: self.metrics["tx"] += len(payload)
                except Exception: pass
            return ok
        except Exception as e:
            logger.error(f"Publish error: {e}")
            return False
    def _on_connect(self, client, userdata, flags, rc, properties=None):
        if rc == 0:
            self.connected = True; self.connected_event.set(); self.reconnect_count = 0
            try:
                client.subscribe("swarm/broadcast/#", qos=2)
                client.subscribe(f"swarm/commands/individual/{self.client_id}", qos=2)
            except Exception as e:
                logger.error(f"Subscribe failed: {e}")
            logger.info("Connected to broker")
        else:
            logger.error(f"Connect failed rc={rc}"); self.connected=False; self._schedule_reconnect()
    def _on_disconnect(self, client, userdata, rc, properties=None):
        self.connected = False; self.connected_event.clear()
        if rc != 0 and not self.stop_event.is_set():
            self._schedule_reconnect()
    def _schedule_reconnect(self):
        if self.stop_event.is_set(): return
        self.metrics["reconnects"] += 1
        wait = min(self.MAX_RECONNECT_WAIT, self.BASE_RECONNECT_WAIT * (2 ** min(self.reconnect_count, 6))) + random.uniform(0, 0.5)
        if self.reconnect_timer:
            try: self.reconnect_timer.cancel()
            except Exception: pass
        self.reconnect_timer = threading.Timer(wait, self._reconnect)
        self.reconnect_timer.daemon = True
        self.reconnect_timer.start(); self.reconnect_count += 1
    def _reconnect(self):
        if self.stop_event.is_set() or not self.client: return
        try:
            self.client.loop_stop(); self.client.reconnect(); self.client.loop_start()
        except Exception as e:
            logger.error(f"Reconnect failed: {e}"); self._schedule_reconnect()
    def _on_message(self, client, userdata, msg):
        try:
            self.metrics["recv"] += 1; self.metrics["rx"] += len(msg.payload)
        except Exception: pass
        try:
            self.on_msg_cb(MQTTMessage(msg.topic, msg.payload, msg.qos, getattr(msg, 'retain', False)))
        except Exception as e:
            logger.error(f"on_msg error: {e}")
    def _on_publish(self, client, userdata, mid):
        pass

def terminate_process_tree(proc: subprocess.Popen):
    if not proc: return
    try:
        if is_windows():
            try:
                import ctypes
                ctypes.windll.kernel32.GenerateConsoleCtrlEvent(0, proc.pid)
            except Exception:
                subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except Exception:
        try: proc.terminate()
        except Exception: pass

class DroneScheduler:
    def __init__(self, drone_id: str, broker: str, port: int, initial_battery: float = 100.0):
        self.drone_id = drone_id
        self.state = SystemState(battery_percent=float(initial_battery))
        self.mqtt = MQTTClient(drone_id, self._queue_message, broker, port)
        self.msg_queue: "queue.Queue[MQTTMessage]" = queue.Queue()
        self.lock = threading.RLock()
        self.running = False
        self.tasks: Dict[str, Task] = {}
        self.crypto_task_id: Optional[str] = None
        self.current_crypto: Optional[AlgorithmType] = None
        self.monitor_thread: Optional[threading.Thread] = None
        self.msg_thread: Optional[threading.Thread] = None
        # metrics CSV
        self._csv_path = os.path.join(HERE, 'logs', f'metrics_{self.drone_id}.csv')
        try:
            os.makedirs(os.path.dirname(self._csv_path), exist_ok=True)
            if not os.path.exists(self._csv_path):
                with open(self._csv_path, 'w', encoding='utf-8') as f:
                    f.write('timestamp,cpu_usage,battery_percent,temperature,power_draw_watts,crypto\n')
        except Exception:
            pass
    # --- life cycle ---
    def start(self):
        self.running = True
        if not self.mqtt.initialize():
            logger.error("MQTT init failed (TLS certs missing?) – continuing offline")
        else:
            self.mqtt.connect()
        self.msg_thread = threading.Thread(target=self._process_messages, daemon=True); self.msg_thread.start()
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True); self.monitor_thread.start()
        logger.info("Drone Scheduler v14 started")
    def stop(self):
        self.running = False
        try: self.mqtt.disconnect()
        except Exception: pass
        for tid in list(self.tasks.keys()):
            self._stop_task(tid)
        if self.monitor_thread and self.monitor_thread.is_alive(): self.monitor_thread.join(timeout=1.5)
        if self.msg_thread and self.msg_thread.is_alive(): self.msg_thread.join(timeout=1.5)
        logger.info("Scheduler stopped")
    # --- MQTT ---
    def _queue_message(self, m: MQTTMessage):
        self.msg_queue.put(m)
    def _process_messages(self):
        while self.running:
            try:
                msg = self.msg_queue.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                with self.lock:
                    self._handle_message(msg)
            except Exception as e:
                logger.error(f"Handle msg error: {e}")
            finally:
                try: self.msg_queue.task_done()
                except Exception: pass
    def _handle_message(self, m: MQTTMessage):
        topic = m.topic
        # Individual commands may be plain text
        if topic == f"swarm/commands/individual/{self.drone_id}":
            cmd = (m.payload.decode(errors='ignore') or '').strip().lower()
            if cmd == 'status' or cmd == 'status_update':
                self._publish_status()
            elif cmd.startswith('crypto:'):
                code = cmd.split(':',1)[1].strip()
                self._apply_crypto_code(code)
            return
        if topic == 'swarm/broadcast/crypto':
            code = (m.payload.decode(errors='ignore') or '').strip()
            self._apply_crypto_code(code)
            return
        if topic.startswith('swarm/broadcast/'):
            # future: alerts/other
            return
        # JSON payloads (optional)
        try:
            _ = json.loads(m.payload.decode('utf-8'))
        except Exception:
            pass
    # --- crypto mgmt ---
    def _apply_crypto_code(self, code: str):
        if code not in ALGO_CODE_MAP:
            logger.warning(f"Unknown crypto code: {code}"); return
        algo = ALGO_CODE_MAP[code]
        if algo == self.current_crypto and self.crypto_task_id and self.crypto_task_id in self.tasks:
            logger.info(f"Crypto already active: {algo.value}"); return
        # Stop previous
        if self.crypto_task_id: self._stop_task(self.crypto_task_id)
        # Start new
        t = self._create_crypto_task(algo)
        self._start_task(t)
        self.crypto_task_id = t.id
        self.current_crypto = algo
        self._publish_status()
    def _create_crypto_task(self, algo: AlgorithmType) -> Task:
        script, pwr = CRYPTO_SCRIPT_MAP.get(algo, CRYPTO_SCRIPT_MAP[AlgorithmType.ASCON_128])
        script_path = os.path.join(HERE, script)
        py = sys.executable
        if is_windows():
            cmd = [py, script_path]
        else:
            cmd = [py, script_path]
        tid = f"crypto-{algo.value}-{int(time.time())}"
        return Task(tid, f"Crypto {algo.value}", cmd, TaskPriority.HIGH, algo, ResourceProfile(pwr), auto_restart=True)
    # --- task control ---
    def _start_task(self, task: Task) -> bool:
        if task.id in self.tasks: return False
        try:
            logger.info(f"Starting task: {task.name}")
            if is_windows():
                task.process = subprocess.Popen(task.command, creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
            else:
                task.process = subprocess.Popen(task.command, preexec_fn=os.setsid)
            task.pid = task.process.pid
            task.start_time = time.time()
            task.status = 'RUNNING'
            self.tasks[task.id] = task
            return True
        except Exception as e:
            logger.error(f"Task start failed: {e}")
            return False
    def _stop_task(self, task_id: str):
        task = self.tasks.pop(task_id, None)
        if not task: return
        try:
            logger.info(f"Stopping task: {task.name}")
            if task.process and task.process.poll() is None:
                terminate_process_tree(task.process)
        except Exception as e:
            logger.error(f"Stop task error: {e}")
        finally:
            if self.crypto_task_id == task_id:
                self.crypto_task_id = None; self.current_crypto = None
    # --- monitoring ---
    def _monitor_loop(self):
        while self.running:
            with self.lock:
                self._update_state()
                # restart crashed auto-restart tasks
                for tid, t in list(self.tasks.items()):
                    if t.auto_restart and t.process and t.process.poll() is not None:
                        logger.warning(f"Restarting crashed task: {t.name}")
                        self._start_task(t)
                self._publish_heartbeat()
                self._log_metrics_row()
            time.sleep(2.0)
    def _update_state(self):
        self.state.timestamp = time.time()
        if psutil:
            try:
                self.state.cpu_usage = float(psutil.cpu_percent())
                self.state.memory_usage = float(psutil.virtual_memory().percent)
            except Exception:
                pass
        # temperature best effort (Linux)
        try:
            with open('/sys/class/thermal/thermal_zone0/temp','r') as f:
                self.state.temperature = float(f.read().strip())/1000.0
        except Exception:
            self.state.temperature = 50.0
        # rough power draw estimate
        base = 2.5 + (self.state.cpu_usage/100.0 * 5.0)
        task_pwr = sum((t.resource_profile.power_watts if t.resource_profile else 0.0) for t in self.tasks.values())
        self.state.power_draw_watts = base + task_pwr
        # simple battery decay (no Thevenin model to keep dependencies light)
        self.state.battery_percent = max(0.0, self.state.battery_percent - 0.01)
    # --- publish ---
    def _publish_heartbeat(self):
        if not (self.mqtt and self.mqtt.connected): return
        data = {
            "cpu_usage": self.state.cpu_usage,
            "memory_usage": self.state.memory_usage,
            "temperature": self.state.temperature,
            "power_draw_watts": self.state.power_draw_watts,
            "battery_percent": self.state.battery_percent,
            "crypto_algorithm": (self.current_crypto.value if self.current_crypto else None)
        }
        payload = {"type":"heartbeat","drone_id": self.drone_id, "timestamp": time.time(), "data": data}
        self.mqtt.publish(f"swarm/status/{self.drone_id}", payload, qos=0)
    def _publish_status(self):
        if not (self.mqtt and self.mqtt.connected): return
        payload = {"type":"status","drone_id": self.drone_id, "ts": time.time(), "crypto": (self.current_crypto.value if self.current_crypto else '-')}
        self.mqtt.publish(f"swarm/status/{self.drone_id}", payload, qos=1)
    def _log_metrics_row(self):
        try:
            row = f"{int(time.time())},{self.state.cpu_usage:.1f},{self.state.battery_percent:.2f},{self.state.temperature:.1f},{self.state.power_draw_watts:.2f},{(self.current_crypto.value if self.current_crypto else '-') }\n"
            with open(self._csv_path, 'a', encoding='utf-8') as f:
                f.write(row)
        except Exception:
            pass

def parse_args():
    p = argparse.ArgumentParser(description='Drone Scheduler v14 (MQTT+TLS)')
    p.add_argument('--drone-id', default=os.environ.get('DRONE_ID','drone1'))
    p.add_argument('--broker', default=(getattr(ip_config,'GCS_HOST','localhost') if ip_config else 'localhost'))
    p.add_argument('--port', type=int, default=8883)
    p.add_argument('--start-crypto', choices=list(ALGO_CODE_MAP.keys()), help='Start with crypto code c1..c8')
    p.add_argument('--battery', type=float, default=100.0, help='Initial battery percentage')
    return p.parse_args()

def main():
    args = parse_args()
    sched = DroneScheduler(args.drone_id, args.broker, args.port, initial_battery=args.battery)
    def _sig(_s,_f): sched.stop(); sys.exit(0)
    try:
        signal.signal(signal.SIGINT, _sig)
        if hasattr(signal, 'SIGTERM'):
            signal.signal(signal.SIGTERM, _sig)
    except Exception:
        pass
    sched.start()
    if args.start_crypto:
        sched._apply_crypto_code(args.start_crypto)
    logger.info(f"Running as {args.drone_id} -> broker {args.broker}:{args.port}")
    try:
        while True:
            time.sleep(10)
    except KeyboardInterrupt:
        pass
    finally:
        sched.stop()

if __name__ == '__main__':
    main()
