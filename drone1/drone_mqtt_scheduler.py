#!/usr/bin/env python3
"""
Drone MQTT Scheduler GUI with TLS MQTT, crypto proxy orchestration, and runtime/persistent IP config.

Features:
- TLS MQTT (v3.1.1/v5) with certificate discovery similar to GCS scheduler.
- Subscribes to broadcast crypto commands and this drone's individual command topic.
- Starts/stops local drone crypto proxies (drone_*.py) based on received crypto code c1..c8.
- Publishes retained status and periodic heartbeat; optional telemetry send.
- Runtime and persistent IP updates via drone/ip_config.py helper functions.
"""

import os, sys, json, time, ssl, re, queue, logging, threading, subprocess, signal, importlib
from pathlib import Path
from dataclasses import dataclass
from typing import Dict, Optional, Tuple, Any

# Ensure local folder import takes precedence
HERE = Path(__file__).parent.resolve()
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

try:
    import ip_config  # drone/ip_config.py
except Exception:
    ip_config = None

try:
    import paho.mqtt.client as mqtt
except ImportError:
    print("Install paho-mqtt: pip install paho-mqtt>=1.6.0"); sys.exit(1)

# Tkinter GUI
try:
    import tkinter as tk
    from tkinter import ttk, messagebox
except Exception as e:
    print("Tkinter required:", e); sys.exit(1)

APP_NAME = "Drone MQTT Scheduler"
LOG_DIR = HERE / "logs"; LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / "drone_mqtt_scheduler.log"
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', handlers=[logging.StreamHandler(sys.stdout), logging.FileHandler(LOG_FILE, encoding='utf-8')])
logger = logging.getLogger("DRONE-SCHED")
PYTHON_EXE = sys.executable

def is_windows(): return os.name == 'nt'

def terminate_process_tree(proc: subprocess.Popen):
    if not proc: return
    try:
        if is_windows():
            try: proc.send_signal(signal.CTRL_BREAK_EVENT)
            except Exception: subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            os.killpg(os.getpgid(proc.pid), 15)
    except Exception:
        try: proc.terminate()
        except Exception: pass

DEFAULTS: Dict[str, Any] = {
    "drone": {"id": "drone1", "battery": 92.0},
    "broker": {"address": "localhost", "port": 8883, "keepalive": 60, "connection_timeout": 15},
    "client": {"id": "drone1", "protocol": 4},  # 4=MQTTv311, 5=MQTTv5
    "security": {
        "cert_paths": [
            "C:/mqtt/certs", "C\\mqtt\\certs",
            str(HERE / "certs"), str(HERE.parent / "certs"),
            "/home/dev/mqtt/certs", "/etc/mqtt/certs"
        ],
        "ca_cert": "ca-cert.pem",
        "verify_hostname": False
    },
    "crypto_map": {
        # Standardized c1..c8 mapping
        "c1": {"name": "ASCON_128", "script": "drone_ascon.py"},
        "c2": {"name": "SPECK", "script": "drone_speck.py"},
        "c3": {"name": "CAMELLIA", "script": "drone_camellia.py"},
        "c4": {"name": "HIGHT", "script": "drone_hight.py"},
        "c5": {"name": "DILITHIUM3", "script": "drone_dilithium.py"},
        "c6": {"name": "KYBER (ML-KEM-768)", "script": "drone_kyber.py"},
        "c7": {"name": "SPHINCS+", "script": "drone_sphincs.py"},
        "c8": {"name": "FALCON512", "script": "drone_falcon.py"}
    }
}

def topics_for(drone_id: str) -> Dict[str, Any]:
    return {
        "subscribe": [
            {"topic": "swarm/broadcast/crypto", "qos": 2},
            {"topic": f"swarm/commands/individual/{drone_id}", "qos": 1},
            {"topic": "swarm/broadcast/alert", "qos": 2},
            {"topic": "swarm/status/+", "qos": 1}
        ],
        "publish": {
            "status": {"topic": f"swarm/status/{drone_id}", "qos": 1},
            "heartbeat": {"topic": f"swarm/heartbeat/{drone_id}", "qos": 1},
            "telemetry": {"topic": f"swarm/drones/{drone_id}/telemetry", "qos": 1}
        }
    }

# --- Certificate discovery ---
def discover_certs(cfg: Dict[str, Any], client_id: str) -> Optional[Tuple[str,str,str]]:
    paths = cfg["security"].get("cert_paths", [])
    ca_name = cfg["security"].get("ca_cert", "ca-cert.pem")
    client_cert = f"{client_id}-cert.pem"; client_key = f"{client_id}-key.pem"
    for base in paths:
        bp = Path(base)
        if not bp.exists(): continue
        ca_path = bp / ca_name
        for flat in (True, False):
            cert_path = (bp / client_cert) if flat else (bp / "clients" / client_cert)
            key_path  = (bp / client_key)  if flat else (bp / "clients" / client_key)
            if ca_path.exists() and cert_path.exists() and key_path.exists():
                logger.info(f"Using certs from: {bp}")
                return str(ca_path), str(cert_path), str(key_path)
    logger.error("Certificates not found")
    return None

class DroneMqttClient:
    def __init__(self, config: Dict[str, Any], topics: Dict[str, Any], on_message_cb):
        self.config=config; self.topics=topics; self.client_id=config["client"]["id"]
        self.on_message_cb=on_message_cb; self.connected=False; self.connected_event=threading.Event()
        self.metrics={"rx":0,"tx":0,"errors":0}
        self.client: Optional[mqtt.Client]=None
        self.certs=discover_certs(config, self.client_id)
        if not self.certs: raise FileNotFoundError("TLS certs missing")
        self._setup()
    def _setup(self):
        proto=self.config["client"].get("protocol",4)
        if proto==5: self.client=mqtt.Client(client_id=self.client_id, protocol=mqtt.MQTTv5)
        else: self.client=mqtt.Client(client_id=self.client_id, protocol=mqtt.MQTTv311, clean_session=True)
        self.client.on_connect=self._on_connect; self.client.on_disconnect=self._on_disconnect; self.client.on_message=self._on_message
        ca, cert, key = self.certs
        verify_hostname=self.config["security"].get("verify_hostname",False)
        self.client.tls_set(ca_certs=ca, certfile=cert, keyfile=key, tls_version=ssl.PROTOCOL_TLS, cert_reqs=ssl.CERT_REQUIRED)
        self.client.tls_insecure_set(not verify_hostname)
    def connect(self)->bool:
        try:
            self.client.connect_async(self.config["broker"]["address"], self.config["broker"]["port"], self.config["broker"].get("keepalive",60))
            self.client.loop_start()
            if self.connected_event.wait(self.config["broker"].get("connection_timeout",15)):
                return True
            logger.error("MQTT connect timeout")
            return False
        except Exception as e:
            logger.error(f"MQTT connect error: {e}")
            return False
    def disconnect(self):
        try: self.client.disconnect(); self.client.loop_stop()
        except Exception: pass
    def _on_connect(self, client, userdata, flags, rc, properties=None):
        if rc==0:
            self.connected=True; self.connected_event.set()
            for sub in self.topics["subscribe"]:
                client.subscribe(sub["topic"], sub.get("qos",1))
            logger.info("Connected to broker")
        else:
            logger.error(f"Connect failed rc={rc}")
    def _on_disconnect(self, client, userdata, rc, properties=None):
        self.connected=False; self.connected_event.clear(); logger.warning(f"Disconnected (rc={rc})")
    def _on_message(self, client, userdata, msg):
        self.metrics["rx"]+=len(msg.payload)
        try: self.on_message_cb(msg)
        except Exception as e: logger.error(f"on_message error: {e}"); self.metrics["errors"]+=1
    def publish(self, topic:str, payload:Any, qos:int=1, retain:bool=False)->bool:
        if not self.connected: return False
        try:
            data=payload if isinstance(payload,(bytes,bytearray)) else (payload if isinstance(payload,str) else json.dumps(payload))
            try: self.metrics["tx"]+=len(data)
            except Exception: self.metrics["tx"]+=len(str(data))
            r=self.client.publish(topic, data, qos=qos, retain=retain)
            return r.rc==mqtt.MQTT_ERR_SUCCESS
        except Exception as e:
            logger.error(f"Publish error: {e}")
            return False

class DroneCryptoManager:
    def __init__(self, crypto_map: Dict[str, Any]): self.map=crypto_map; self.current=None; self.proc:Optional[subprocess.Popen]=None
    def _script_path(self,name:str)->Path: return (HERE / name).resolve()
    def switch(self, code:str)->Tuple[bool,str]:
        m=self.map
        if code not in m: return False, f"Unknown crypto code: {code}"
        if self.current==code and self.proc and self.proc.poll() is None: return True, f"Already running {m[code]['name']} ({code})"
        self.stop(); target=m[code]; path=self._script_path(target['script'])
        if not path.exists(): return False, f"Script not found: {path}"
        try:
            if is_windows(): self.proc=subprocess.Popen([PYTHON_EXE,str(path)], creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
            else: self.proc=subprocess.Popen([PYTHON_EXE,str(path)], preexec_fn=os.setsid)
            self.current=code; return True, f"Started {target['name']} ({code}) via {path.name}"
        except Exception as e: return False, f"Failed to start {path.name}: {e}"
    def stop(self):
        if self.proc and self.proc.poll() is None:
            try: terminate_process_tree(self.proc)
            except Exception:
                try: self.proc.kill()
                except Exception: pass
        self.proc=None; self.current=None

@dataclass
class DroneState:
    drone_id: str
    battery: float = 100.0
    crypto: Optional[str] = None  # c1..c8
    online: bool = False
    last_cmd: Optional[str] = None

class DroneSchedulerApp:
    def __init__(self, root: tk.Tk, cfg: Dict[str, Any]):
        self.root=root; root.title(APP_NAME)
        self.cfg=cfg
        self.drone_id=tk.StringVar(value=cfg["drone"]["id"])
        self.battery=tk.DoubleVar(value=cfg["drone"]["battery"])  # percent
        self.client_id=tk.StringVar(value=cfg["client"]["id"])
        self.broker=tk.StringVar(value=cfg["broker"]["address"])
        self.port=tk.IntVar(value=cfg["broker"]["port"])
        self.auto_apply_crypto=tk.BooleanVar(value=True)
        self.auto_telemetry=tk.BooleanVar(value=True)
        self.hb_rate=tk.DoubleVar(value=1.0)
        self.status=tk.StringVar(value="Disconnected")
        self.stats=tk.StringVar(value="Rx: 0B Tx: 0B")
        self.ipc_gcs=tk.StringVar(value=getattr(ip_config,'GCS_HOST',''))
        self.ipc_drone=tk.StringVar(value=getattr(ip_config,'DRONE_HOST',''))
        self.crypto=DroneCryptoManager(cfg["crypto_map"])  
        self.mqtt: Optional[DroneMqttClient] = None
        self.topics=topics_for(self.drone_id.get())
        self.hb_running=False; self.hb_thread=None
        self.msg_queue: "queue.Queue[mqtt.MQTTMessage]" = queue.Queue()
        self._build_ui(); self._ui_tick()

    # UI
    def _build_ui(self):
        notebook=ttk.Notebook(self.root); notebook.pack(fill=tk.BOTH, expand=True)

        # Main tab
        tab=ttk.Frame(notebook); notebook.add(tab, text="Main")

        # Connection frame
        lf_conn=ttk.LabelFrame(tab, text="Connection", padding=8); lf_conn.pack(fill=tk.X, padx=8, pady=6)
        ttk.Label(lf_conn, text="Drone ID").grid(row=0, column=0, sticky=tk.W)
        ttk.Entry(lf_conn, textvariable=self.drone_id, width=16).grid(row=0, column=1)
        ttk.Label(lf_conn, text="Client ID").grid(row=0, column=2, sticky=tk.W)
        ttk.Entry(lf_conn, textvariable=self.client_id, width=16).grid(row=0, column=3)
        ttk.Label(lf_conn, text="Broker").grid(row=1, column=0, sticky=tk.W)
        ttk.Entry(lf_conn, textvariable=self.broker, width=22).grid(row=1, column=1)
        ttk.Label(lf_conn, text=":").grid(row=1, column=2)
        ttk.Entry(lf_conn, textvariable=self.port, width=6).grid(row=1, column=3)
        ttk.Button(lf_conn, text="Connect", command=self._connect).grid(row=0, column=4, rowspan=2, padx=6)
        ttk.Label(lf_conn, textvariable=self.status).grid(row=0, column=5, rowspan=2, padx=8)

        # Crypto frame
        lf_crypto=ttk.LabelFrame(tab, text="Crypto", padding=8); lf_crypto.pack(fill=tk.X, padx=8, pady=6)
        codes=list(self.cfg["crypto_map"].keys())
        names=[f"{c} - {self.cfg['crypto_map'][c]['name']}" for c in codes]
        self.crypto_combo=ttk.Combobox(lf_crypto, values=names, state="readonly", width=40)
        self.crypto_combo.current(0)
        self.crypto_combo.grid(row=0, column=0, padx=4)
        ttk.Checkbutton(lf_crypto, text="Auto apply on broadcast", variable=self.auto_apply_crypto).grid(row=0, column=1, padx=8)
        ttk.Button(lf_crypto, text="Apply", command=self._apply_crypto).grid(row=0, column=2, padx=6)
        ttk.Button(lf_crypto, text="Stop", command=self._stop_proxy).grid(row=0, column=3)

        # Telemetry frame
        lf_tel=ttk.LabelFrame(tab, text="Telemetry", padding=8); lf_tel.pack(fill=tk.X, padx=8, pady=6)
        ttk.Label(lf_tel, text="Battery %").grid(row=0, column=0, sticky=tk.W)
        ttk.Entry(lf_tel, textvariable=self.battery, width=8).grid(row=0, column=1)
        ttk.Checkbutton(lf_tel, text="Auto send status/telemetry", variable=self.auto_telemetry).grid(row=0, column=2, padx=8)
        ttk.Button(lf_tel, text="Send Status Now", command=self._send_status).grid(row=0, column=3, padx=6)
        ttk.Button(lf_tel, text="Send Telemetry", command=self._send_telemetry).grid(row=0, column=4)

        # Config tab
        cfg_tab=ttk.Frame(notebook); notebook.add(cfg_tab, text="Config")
        lf_ips=ttk.LabelFrame(cfg_tab, text="Runtime IP Configuration", padding=8); lf_ips.pack(fill=tk.X, padx=8, pady=8)
        ttk.Label(lf_ips, text="GCS_HOST").grid(row=0, column=0, sticky=tk.W)
        ttk.Entry(lf_ips, textvariable=self.ipc_gcs, width=18).grid(row=0, column=1)
        ttk.Label(lf_ips, text="DRONE_HOST").grid(row=1, column=0, sticky=tk.W)
        ttk.Entry(lf_ips, textvariable=self.ipc_drone, width=18).grid(row=1, column=1)
        ttk.Button(lf_ips, text="Apply Runtime", command=self._apply_ip_runtime).grid(row=0, column=2, padx=8)
        ttk.Button(lf_ips, text="Apply & Persist", command=self._apply_ip_persistent).grid(row=1, column=2, padx=8)
        ttk.Button(lf_ips, text="Reload File", command=self._reload_ip_module).grid(row=0, column=3, padx=8)

        # Logs tab
        logs_tab=ttk.Frame(notebook); notebook.add(logs_tab, text="Logs")
        toolbar=ttk.Frame(logs_tab); toolbar.pack(fill=tk.X, padx=8, pady=(8,0))
        ttk.Button(toolbar, text="Clear", command=self._clear_log).pack(side=tk.LEFT)
        self.log_txt=tk.Text(logs_tab, height=18); self.log_txt.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        # Status bar
        sb=ttk.Frame(self.root, relief=tk.SUNKEN); sb.pack(side=tk.BOTTOM, fill=tk.X)
        ttk.Label(sb, textvariable=self.stats).pack(side=tk.RIGHT, padx=8)

    # MQTT
    def _connect(self):
        try:
            did=self.drone_id.get().strip() or "drone1"; cid=self.client_id.get().strip() or did
            self.cfg["drone"]["id"]=did; self.cfg["client"]["id"]=cid
            self.topics=topics_for(did)
            self.mqtt=DroneMqttClient(self.cfg, self.topics, self._on_mqtt_message)
            if self.mqtt.connect():
                self.status.set("Connected"); self._log("Connected to broker")
                # Publish retained online status
                self._publish_status(retain=True)
                # Start heartbeat thread
                self._start_heartbeat()
            else:
                self.status.set("Disconnected"); self._log("Connect timeout")
        except Exception as e:
            self.status.set("Disconnected"); self._log(f"MQTT init/connect error: {e}")

    def _on_mqtt_message(self, msg: mqtt.MQTTMessage):
        self.msg_queue.put(msg)

    # Crypto actions
    def _apply_crypto(self):
        code=self.crypto_combo.get().split(" ")[0]
        ok,msg=self.crypto.switch(code); self._log(msg)
        if self.auto_telemetry.get(): self._publish_status()

    def _stop_proxy(self):
        self.crypto.stop(); self._log("Proxy stopped")
        if self.auto_telemetry.get(): self._publish_status()

    # Telemetry/status
    def _publish_status(self, retain: bool=False):
        if not self.mqtt or not self.mqtt.connected: return
        topic=self.topics["publish"]["status"]["topic"]
        payload={"type":"status","drone_id":self.cfg['drone']['id'],"battery":float(self.battery.get()),"crypto":self.crypto.current or '-',"online":True,"ts":time.time()}
        self.mqtt.publish(topic, payload, qos=1, retain=retain)

    def _send_status(self):
        if not self.mqtt or not self.mqtt.connected:
            self._log("Not connected")
            return
        self._publish_status(retain=False)
        messagebox.showinfo(APP_NAME, "Status published")

    def _send_telemetry(self):
        if not self.mqtt or not self.mqtt.connected: self._log("Not connected"); return
        topic=self.topics["publish"]["telemetry"]["topic"]
        payload={"type":"telemetry","drone_id":self.cfg['drone']['id'],"lat":41.01,"lon":29.00,"alt":20.3,"battery":float(self.battery.get()),"crypto":self.crypto.current or '-',"ts":time.time()}
        self.mqtt.publish(topic, payload, qos=1, retain=False)

    def _start_heartbeat(self):
        if self.hb_running: return
        self.hb_running=True
        def loop():
            it=lambda: max(0.1, 1.0/float(self.hb_rate.get() or 1.0))
            while self.hb_running:
                try:
                    if self.mqtt and self.mqtt.connected:
                        topic=self.topics["publish"]["heartbeat"]["topic"]
                        payload={"type":"heartbeat","drone_id":self.cfg['drone']['id'],"crypto":self.crypto.current or '-',"battery":float(self.battery.get()),"ts":time.time()}
                        self.mqtt.publish(topic, payload, qos=1, retain=False)
                    time.sleep(it())
                except Exception:
                    time.sleep(1.0)
        self.hb_thread=threading.Thread(target=loop, daemon=True)
        self.hb_thread.start()

    def _stop_heartbeat(self): self.hb_running=False

    # IP helpers
    def _validate_ip(self, ip: str) -> bool:
        import ipaddress
        try: ipaddress.IPv4Address(ip); return True
        except Exception: return False

    def _apply_ip_runtime(self):
        if not ip_config: self._log("ip_config unavailable"); return
        gcs=self.ipc_gcs.get().strip(); drone=self.ipc_drone.get().strip()
        if gcs and not self._validate_ip(gcs): self._log(f"Invalid GCS IP: {gcs}"); return
        if drone and not self._validate_ip(drone): self._log(f"Invalid DRONE IP: {drone}"); return
        try:
            changes=ip_config.set_hosts_runtime(gcs or None, drone or None)
            self._log("Runtime IP update: "+(", ".join(changes) if changes else "no changes"))
        except Exception as e: self._log(f"Runtime update failed: {e}")

    def _apply_ip_persistent(self):
        if not ip_config: self._log("ip_config unavailable"); return
        gcs=self.ipc_gcs.get().strip(); drone=self.ipc_drone.get().strip()
        if gcs and not self._validate_ip(gcs): self._log(f"Invalid GCS IP: {gcs}"); return
        if drone and not self._validate_ip(drone): self._log(f"Invalid DRONE IP: {drone}"); return
        try:
            changes=ip_config.update_hosts_persistent(gcs or None, drone or None)
            if changes:
                self._log("Persistent IP update: "+", ".join(changes))
                self._reload_ip_module()
            else:
                self._log("No persistent changes applied")
        except Exception as e: self._log(f"Persistent update failed: {e}")

    def _reload_ip_module(self):
        if not ip_config: return
        try:
            importlib.reload(ip_config)
            self.ipc_gcs.set(getattr(ip_config,'GCS_HOST', self.ipc_gcs.get()))
            self.ipc_drone.set(getattr(ip_config,'DRONE_HOST', self.ipc_drone.get()))
            self._log("ip_config reloaded")
        except Exception as e:
            self._log(f"Reload failed: {e}")

    # Message handling
    def _handle_msg(self, msg: mqtt.MQTTMessage):
        topic=msg.topic; raw=msg.payload
        try:
            text=raw.decode('utf-8')
        except Exception:
            text=f"<binary {len(raw)} bytes>"
        # Broadcast crypto
        if topic == "swarm/broadcast/crypto":
            code=str(text).strip()
            if re.fullmatch(r"c[1-8]", code):
                self._log(f"Broadcast crypto: {code}")
                self._select_crypto_in_combo(code)
                if self.auto_apply_crypto.get():
                    ok,msg=self.crypto.switch(code); self._log(msg)
                    if self.auto_telemetry.get(): self._publish_status()
            return
        # Individual command
        if topic == self.topics["subscribe"][1]["topic"]:
            decoded = self._safe_json(text)
            cmd = (decoded.get('command') if isinstance(decoded, dict) else str(decoded)).strip()
            self._log(f"RX cmd: {cmd}")
            if cmd == 'status': self._publish_status()
            elif cmd == 'telemetry': self._send_telemetry()
            elif cmd.startswith('crypto:'):
                code = cmd.split(':',1)[1].strip()
                if re.fullmatch(r"c[1-8]", code):
                    ok,msg=self.crypto.switch(code); self._log(msg)
                    if self.auto_telemetry.get(): self._publish_status()
            else:
                # Echo generic ack to status topic
                ack = {"type":"ack","drone_id":self.cfg['drone']['id'],"command":cmd,"ok":True,"ts":time.time()}
                self.mqtt and self.mqtt.publish(self.topics["publish"]["status"]["topic"], ack, qos=1)

    def _safe_json(self, s: str):
        try: return json.loads(s)
        except Exception: return {"text": s}

    def _select_crypto_in_combo(self, code: str):
        try:
            for idx,label in enumerate(self.crypto_combo['values']):
                if label.startswith(code+" "):
                    self.crypto_combo.current(idx)
                    break
        except Exception:
            pass

    # UI loop
    def _ui_tick(self):
        # Drain queue
        try:
            while True:
                msg=self.msg_queue.get_nowait(); self._handle_msg(msg)
        except queue.Empty:
            pass
        # Update status and stats
        if self.mqtt and self.mqtt.connected: self.status.set("Connected")
        else: self.status.set("Disconnected")
        rx = (self.mqtt.metrics["rx"] if self.mqtt else 0); tx = (self.mqtt.metrics["tx"] if self.mqtt else 0)
        self.stats.set(f"Rx: {rx}B Tx: {tx}B")
        self.root.after(300, self._ui_tick)

    def _clear_log(self): self.log_txt.delete("1.0", tk.END)
    def _log(self, line:str): ts=time.strftime("%H:%M:%S"); self.log_txt.insert(tk.END, f"[{ts}] {line}\n"); self.log_txt.see(tk.END); logger.info(line)

def main():
    # Seed defaults from ip_config when available
    try:
        if ip_config:
            DEFAULTS["broker"]["address"]=getattr(ip_config,'GCS_HOST', DEFAULTS["broker"]["address"]) or DEFAULTS["broker"]["address"]
    except Exception:
        pass
    root=tk.Tk(); app=DroneSchedulerApp(root, DEFAULTS); root.mainloop()

if __name__ == "__main__":
    main()
