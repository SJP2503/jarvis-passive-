
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import os, threading, time, csv, socket, ipaddress
import validators
import pynmea2

app = FastAPI(title="Jarvis Passive URL + BeiDou API", version="1.0.0")

# ---- Config ----
PORT = int(os.getenv("PORT", "7070"))
BEIDOU_ENABLED = os.getenv("BEIDOU_ENABLED", "true").lower() == "true"
BEIDOU_SERIAL_PORT = os.getenv("BEIDOU_SERIAL_PORT", "/dev/ttyUSB0")
BEIDOU_BAUD = int(os.getenv("BEIDOU_BAUD", "9600"))
BEIDOU_LOG_PATH = os.getenv("BEIDOU_LOG_PATH", "./data/beidou_log.csv")
BEIDOU_SIMULATE_FILE = os.getenv("BEIDOU_SIMULATE_FILE", "").strip() or None
DNS_RESOLVE_TIMEOUT = float(os.getenv("DNS_RESOLVE_TIMEOUT", "5"))
BLOCKLIST_IPS = os.getenv("BLOCKLIST_IPS", "./blocklists/blocklist_ips.txt")
BLOCKLIST_CIDRS = os.getenv("BLOCKLIST_CIDRS", "./blocklists/blocklist_cidrs.txt")
BLOCKLIST_DOMAINS = os.getenv("BLOCKLIST_DOMAINS", "./blocklists/blocklist_domains.txt")

os.makedirs(os.path.dirname(BEIDOU_LOG_PATH), exist_ok=True)
os.makedirs("./blocklists", exist_ok=True)

# ---- Blocklists ----
def _read_lines(p):
    try:
        with open(p, "r", encoding="utf-8") as f:
            return [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    except FileNotFoundError:
        return []

def load_blocklists():
    ips = set(_read_lines(BLOCKLIST_IPS))
    cidrs = [ipaddress.ip_network(x) for x in _read_lines(BLOCKLIST_CIDRS)]
    domains = set(_read_lines(BLOCKLIST_DOMAINS))
    return ips, cidrs, domains

BLOCK_IPS, BLOCK_CIDRS, BLOCK_DOMAINS = load_blocklists()

# ---- URL checker ----
class URLCheckReq(BaseModel):
    url: str

@app.post("/url/check")
def url_check(req: URLCheckReq):
    url = req.url.strip()
    if not validators.url(url):
        raise HTTPException(status_code=400, detail="Invalid URL format")
    try:
        host = url.split("//", 1)[1].split("/", 1)[0]
    except Exception:
        raise HTTPException(status_code=400, detail="Unable to parse host from URL")

    socket.setdefaulttimeout(DNS_RESOLVE_TIMEOUT)
    addrs = []
    try:
        infos = socket.getaddrinfo(host, None)
        for info in infos:
            ip = info[4][0]
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                continue
            addrs.append(ip)
    except Exception:
        addrs = []
    addrs = sorted(set(addrs))

    ip_hits, cidr_hits = [], []
    for ip in addrs:
        if ip in BLOCK_IPS:
            ip_hits.append(ip)
        ip_obj = ipaddress.ip_address(ip)
        for net in BLOCK_CIDRS:
            if ip_obj in net:
                cidr_hits.append(str(net))
    domain_hit = host.lower() in BLOCK_DOMAINS

    return JSONResponse({
        "url": url,
        "host": host,
        "resolved_ips": addrs,
        "matches": {
            "domain_blocked": domain_hit,
            "ip_blocked": ip_hits,
            "cidr_blocked": list(sorted(set(cidr_hits))),
        }
    })

# ---- BeiDou listener (logs ALL NMEA to prove pipeline) ----
class BeiDouState:
    def __init__(self):
        self.thread = None
        self.stop_flag = threading.Event()
        self.running = False

BEIDOU = BeiDouState()

def _write_header_if_needed(path: str):
    exists = os.path.exists(path)
    with open(path, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if not exists:
            w.writerow(["timestamp", "sentence_type", "raw"])

def _beidou_loop():
    _write_header_if_needed(BEIDOU_LOG_PATH)

    def write_line(ts: str, line: str):
        try:
            msg = pynmea2.parse(line)
            with open(BEIDOU_LOG_PATH, "a", newline="", encoding="utf-8") as f:
                csv.writer(f).writerow([ts, getattr(msg, "sentence_type", ""), line])
        except Exception:
            # ignore bad lines silently for now
            pass

    if BEIDOU_SIMULATE_FILE and os.path.isfile(BEIDOU_SIMULATE_FILE):
        while not BEIDOU.stop_flag.is_set():
            with open(BEIDOU_SIMULATE_FILE, "r", encoding="utf-8") as sim:
                for line in sim:
                    if BEIDOU.stop_flag.is_set():
                        break
                    s = line.strip()
                    if s.startswith("$"):
                        write_line(time.strftime("%Y-%m-%d %H:%M:%S"), s)
                    time.sleep(0.1)
            # loop file again
    else:
        # no serial path in this minimal build; idle quietly
        while not BEIDOU.stop_flag.is_set():
            time.sleep(1)

@app.get("/beidou/status")
def beidou_status():
    return {"enabled": BEIDOU_ENABLED, "running": BEIDOU.running, "log_path": BEIDOU_LOG_PATH}

@app.post("/beidou/start")
def beidou_start():
    if not BEIDOU_ENABLED:
        raise HTTPException(status_code=400, detail="BeiDou listener disabled via config")
    if BEIDOU.running:
        return {"status": "already_running"}
    BEIDOU.stop_flag.clear()
    BEIDOU.thread = threading.Thread(target=_beidou_loop, daemon=True)
    BEIDOU.thread.start()
    BEIDOU.running = True
    return {"status": "started"}

@app.post("/beidou/stop")
def beidou_stop():
    if not BEIDOU.running:
        return {"status": "not_running"}
    BEIDOU.stop_flag.set()
    if BEIDOU.thread:
        BEIDOU.thread.join(timeout=2)
    BEIDOU.running = False
    return {"status": "stopped"}
