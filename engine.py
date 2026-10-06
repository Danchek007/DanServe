"""
DanServe engine.
Координатор + клиент + WireGuard + сети.
Windows: через wireguard.exe (служба).
Linux/Mac: через wg-quick.
"""
import os
import sys
import json
import time
import hashlib
import platform
import threading
import subprocess
import urllib.request
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

# ============================================================
# ПЛАТФОРМА
# ============================================================
IS_WINDOWS = platform.system() == "Windows"
IS_MAC     = platform.system() == "Darwin"
CREATE_NO_WINDOW = 0x08000000

IFACE       = "wg0"
SERVER_PORT = 8765
WG_PORT     = 51820
SUBNET_PFX  = "10.66."
PUBLIC_SERVERS = []   # при желании — список чужих координаторов

if IS_WINDOWS:
    WG_EXE     = Path(r"C:\Program Files\WireGuard\wireguard.exe")
    WG_CLI     = Path(r"C:\Program Files\WireGuard\wg.exe")
    WG_CONFIGS = Path(r"C:\ProgramData\DanServe")
    STATE_DIR  = Path(os.environ.get("APPDATA", ".")) / "DanServe"
elif IS_MAC:
    WG_EXE     = Path("/usr/local/bin/wg-quick")
    WG_CLI     = Path("/usr/local/bin/wg")
    WG_CONFIGS = Path("/usr/local/etc/wireguard")
    STATE_DIR  = Path.home() / ".danserve"
else:
    WG_EXE     = Path("/usr/bin/wg-quick")
    WG_CLI     = Path("/usr/bin/wg")
    WG_CONFIGS = Path("/etc/wireguard")
    STATE_DIR  = Path.home() / ".danserve"

STATE_FILE = STATE_DIR / "state.json"


# ============================================================
# ТИХИЙ ЗАПУСК
# ============================================================
def run_silent(cmd, input_data=None, shell=False):
    kw = {
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "stdin":  subprocess.DEVNULL,
        "shell":  shell,
    }
    if IS_WINDOWS:
        kw["creationflags"] = CREATE_NO_WINDOW
    try:
        return subprocess.run(cmd, input=input_data, **kw)
    except Exception:
        return None


def wg_installed() -> bool:
    return WG_CLI.exists() and WG_EXE.exists()


def is_admin() -> bool:
    if IS_WINDOWS:
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    return os.geteuid() == 0


# ============================================================
# WIREGUARD
# ============================================================
def genkey() -> str:
    r = run_silent([str(WG_CLI), "genkey"])
    return r.stdout.decode().strip() if r and r.stdout else ""


def pubkey(priv: str) -> str:
    r = run_silent([str(WG_CLI), "pubkey"], input_data=priv.encode())
    return r.stdout.decode().strip() if r and r.stdout else ""


def write_wg_config(private_key, address, listen_port, peers, iface=IFACE):
    WG_CONFIGS.mkdir(parents=True, exist_ok=True)
    conf = WG_CONFIGS / f"{iface}.conf"
    lines = ["[Interface]",
             f"PrivateKey = {private_key}",
             f"Address = {address}",
             f"ListenPort = {listen_port}",
             ""]
    for p in peers:
        lines += ["[Peer]", f"PublicKey = {p['pubkey']}"]
        if p.get("endpoint"):
            lines.append(f"Endpoint = {p['endpoint']}")
        lines.append(f"AllowedIPs = {p['allowed_ips']}")
        lines.append("PersistentKeepalive = 25")
        lines.append("")
    conf.write_text("\n".join(lines))
    return conf


def wg_up(iface=IFACE):
    conf = WG_CONFIGS / f"{iface}.conf"
    if not conf.exists():
        return False
    if IS_WINDOWS:
        run_silent([str(WG_EXE), "/installtunnelservice", str(conf)])
    else:
        run_silent(["sudo", "-n", str(WG_EXE), "up", iface])
    return True


def wg_down(iface=IFACE):
    if IS_WINDOWS:
        run_silent([str(WG_EXE), "/uninstalltunnelservice", iface])
    else:
        run_silent(["sudo", "-n", str(WG_EXE), "down", iface])


def reload_tunnel(iface=IFACE):
    wg_down(iface)
    time.sleep(1)
    wg_up(iface)


# ============================================================
# УТИЛИТЫ
# ============================================================
def network_id(name: str, password: str) -> str:
    return hashlib.sha256(
        f"{name.strip().lower()}:{password}".encode()
    ).hexdigest()[:16]


def get_public_ip() -> str:
    for url in ("https://ifconfig.me", "https://api.ipify.org"):
        try:
            return urllib.request.urlopen(url, timeout=4)\
                .read().decode().strip()
        except Exception:
            continue
    return ""


def _post(url, data):
    req = urllib.request.Request(
        url, data=json.dumps(data).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())


# ============================================================
# КООРДИНАТОР
# ============================================================
class _CoordHandler(BaseHTTPRequestHandler):
    networks = {}
    lock = threading.Lock()
    next_subnet = [1]

    def log_message(self, *a): pass

    def _json(self, data, code=200):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        ln = int(self.headers.get("Content-Length", 0))
        try:
            p = json.loads(self.rfile.read(ln) or b"{}")
        except json.JSONDecodeError:
            return self._json({"error": "bad json"}, 400)
        route = {
            "/network/join":  self._join,
            "/network/peers": self._peers,
            "/network/leave": self._leave,
            "/networks/list": self._list,
        }.get(self.path)
        if not route:
            return self._json({"error": "not found"}, 404)
        route(p)

    def _join(self, p):
        name = p.get("network_name", "").strip()
        password = p.get("network_password", "")
        pub = p.get("pubkey")
        if not (name and pub):
            return self._json({"error": "network_name and pubkey required"}, 400)
        nid = network_id(name, password)
        with self.lock:
            if nid not in self.networks:
                if self.next_subnet[0] > 254:
                    return self._json({"error": "too many networks"}, 507)
                self.networks[nid] = {
                    "name": name,
                    "subnet_idx": self.next_subnet[0],
                    "nodes": {},
                }
                self.next_subnet[0] += 1
            net = self.networks[nid]
            nodes = net["nodes"]
            if pub not in nodes:
                used = {int(n["virtual_ip"].split(".")[3]) for n in nodes.values()}
                free = next((i for i in range(2, 255) if i not in used), None)
                if free is None:
                    return self._json({"error": "network full"}, 507)
                nodes[pub] = {
                    "pubkey": pub,
                    "virtual_ip": f"{SUBNET_PFX}{net['subnet_idx']}.{free}",
                    "name": p.get("name", "node"),
                    "endpoint": p.get("endpoint"),
                    "last_seen": time.time(),
                }
            else:
                nodes[pub]["last_seen"] = time.time()
                if p.get("endpoint"):
                    nodes[pub]["endpoint"] = p["endpoint"]
            my = nodes[pub]
            idx = net["subnet_idx"]
        self._json({
            "network_id": nid,
            "network_name": name,
            "virtual_ip": my["virtual_ip"],
            "subnet": f"{SUBNET_PFX}{idx}.0/24",
        })

    def _peers(self, p):
        nid = p.get("network_id")
        pub = p.get("pubkey")
        if not (nid and pub):
            return self._json({"error": "network_id and pubkey required"}, 400)
        with self.lock:
            net = self.networks.get(nid)
            if not net:
                return self._json({"error": "network not found"}, 404)
            if pub in net["nodes"]:
                net["nodes"][pub]["last_seen"] = time.time()
                if p.get("endpoint"):
                    net["nodes"][pub]["endpoint"] = p["endpoint"]
            peers = [
                {"pubkey": n["pubkey"], "endpoint": n["endpoint"],
                 "virtual_ip": n["virtual_ip"], "name": n["name"]}
                for k, n in net["nodes"].items() if k != pub
            ]
        self._json({"peers": peers})

    def _leave(self, p):
        nid = p.get("network_id")
        pub = p.get("pubkey")
        with self.lock:
            net = self.networks.get(nid)
            if net and pub in net["nodes"]:
                del net["nodes"][pub]
            if net and not net["nodes"]:
                del self.networks[nid]
        self._json({"ok": True})

    def _list(self, p):
        with self.lock:
            data = [
                {"id": nid, "name": n["name"],
                 "subnet": f"{SUBNET_PFX}{n['subnet_idx']}.0/24",
                 "nodes": len(n["nodes"])}
                for nid, n in self.networks.items()
            ]
        self._json({"networks": data})


def start_coord_server(port=SERVER_PORT):
    srv = HTTPServer(("0.0.0.0", port), _CoordHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def gc_loop(timeout=120, interval=30):
    while True:
        time.sleep(interval)
        now = time.time()
        with _CoordHandler.lock:
            empty = []
            for nid, net in _CoordHandler.networks.items():
                dead = [k for k, n in net["nodes"].items()
                        if now - n["last_seen"] > timeout]
                for k in dead:
                    del net["nodes"][k]
                if not net["nodes"]:
                    empty.append(nid)
            for nid in empty:
                del _CoordHandler.networks[nid]


# ============================================================
# КЛИЕНТ
# ============================================================
class DanServeEngine:
    def __init__(self):
        self.state = self._load_state()
        self.peers = {}
        self.log_lines = []
        self.running = False
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self.my_virtual_ip = None
        self.network_id = None
        self.network_name = None
        self._last_hash = None

    def _load_state(self):
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        if STATE_FILE.exists():
            return json.loads(STATE_FILE.read_text())
        priv = genkey()
        st = {"private_key": priv, "public_key": pubkey(priv)}
        STATE_FILE.write_text(json.dumps(st))
        return st

    def log(self, msg):
        line = f"[{time.strftime('%H:%M:%S')}] {msg}"
        with self._lock:
            self.log_lines.append(line)
            self.log_lines = self.log_lines[-200:]
        print(line)

    def get_peers(self):
        with self._lock:
            return list(self.peers.values())

    def start(self, server_url, network_name, network_password,
              node_name, run_local_server=False):
        if self.running:
            return
        if run_local_server:
            start_coord_server(SERVER_PORT)
            threading.Thread(target=gc_loop, daemon=True).start()
            server_url = f"http://127.0.0.1:{SERVER_PORT}"
            self.log(f"Локальный координатор на :{SERVER_PORT}")
        self.server_url = server_url.rstrip("/")
        self.network_name = network_name
        self.network_password = network_password
        self.node_name = node_name
        self.running = True
        self._stop.clear()
        threading.Thread(target=self._run, daemon=True).start()

    def stop(self):
        self._stop.set()
        if self.running and self.network_id:
            try:
                _post(f"{self.server_url}/network/leave",
                      {"network_id": self.network_id,
                       "pubkey": self.state["public_key"]})
            except Exception:
                pass
        self.running = False
        wg_down()
        self.log("Остановлено.")

    def _run(self):
        try:
            my_ip = get_public_ip()
            my_endpoint = f"{my_ip}:{WG_PORT}" if my_ip else None
            self.log(f"Подключаюсь к сети '{self.network_name}' → {self.server_url}")
            join = _post(f"{self.server_url}/network/join", {
                "network_name": self.network_name,
                "network_password": self.network_password,
                "pubkey": self.state["public_key"],
                "name": self.node_name,
                "endpoint": my_endpoint,
            })
            self.network_id = join["network_id"]
            self.my_virtual_ip = join["virtual_ip"]
            self.log(f"В сети. Мой IP: {self.my_virtual_ip}")
            self._sync_peers(force_reload=True)
            while not self._stop.wait(15):
                self._sync_peers()
        except Exception as e:
            self.log(f"ОШИБКА: {e}")
            self.running = False

    def _sync_peers(self, force_reload=False):
        resp = _post(f"{self.server_url}/network/peers", {
            "network_id": self.network_id,
            "pubkey": self.state["public_key"],
            "endpoint": f"{get_public_ip()}:{WG_PORT}",
        })
        remote = {p["pubkey"]: p for p in resp.get("peers", [])}
        h = hashlib.md5(json.dumps(sorted(remote.keys())).encode()).hexdigest()
        if not force_reload and h == self._last_hash:
            return
        for pk, p in remote.items():
            if pk not in self.peers:
                self.log(f"+ {p['name']} ({p['virtual_ip']})")
        for pk in list(self.peers):
            if pk not in remote:
                gone = self.peers[pk]
                self.log(f"- {gone['name']} ({gone['virtual_ip']})")
        self.peers = remote
        self._last_hash = h
        wg_peers = [
            {"pubkey": p["pubkey"], "endpoint": p["endpoint"],
             "allowed_ips": p["virtual_ip"] + "/32"}
            for p in self.peers.values() if p.get("endpoint")
        ]
        write_wg_config(self.state["private_key"],
                        f"{self.my_virtual_ip}/24",
                        WG_PORT, wg_peers)
        reload_tunnel()
        self.log(f"Туннель перезапущен. Пиров: {len(wg_peers)}")


# ============================================================
# РУЧНОЙ ЗАПУСК
# ============================================================
if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "server":
        print(f"Координатор на :{SERVER_PORT}")
        start_coord_server()
        threading.Thread(target=gc_loop, daemon=True).start()
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            pass
    else:
        print("Запускай через gui.py, или: python engine.py server")