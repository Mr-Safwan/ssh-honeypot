import socket
from datetime import datetime
import os
import threading
import json
import time
import requests
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
from log_rotation import start_rotation_scheduler

# ─── Setup ────────────────────────────────────────────────────────────────────
os.makedirs("logs", exist_ok=True)

HOST        = "0.0.0.0"
PORT        = 2222
MAX_WORKERS = 50
executor    = ThreadPoolExecutor(max_workers=MAX_WORKERS)
SSH_BANNER  = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"

connection_tracker = {}
connection_lock    = threading.Lock()
RATE_LIMIT  = 10
RATE_WINDOW = 60

PRIVATE_PREFIXES = (
    "10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
    "172.30.", "172.31.", "192.168.", "127.", "0.", "::1",
)

# ─── ANSI Colors ──────────────────────────────────────────────────────────────
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    RED     = "\033[91m"
    BRED    = "\033[1;91m"
    CYAN    = "\033[96m"
    MAGENTA = "\033[95m"
    GREY    = "\033[90m"
    WHITE   = "\033[97m"

EVENT_STYLE = {
    "CONNECT":        (C.GREEN,   ">>", "CONNECT"),
    "LOGIN_ATTEMPT":  (C.YELLOW,  "**", "LOGIN ATTEMPT"),
    "LOGIN_SUCCESS":  (C.GREEN,   "++", "LOGIN SUCCESS"),
    "LOGIN_FAILED":   (C.RED,     "--", "LOGIN FAILED"),
    "COMMAND":        (C.MAGENTA, "$$", "COMMAND"),
    "RATE_LIMITED":   (C.BRED,    "!!", "RATE LIMITED"),
    "ERROR":          (C.RED,     "XX", "ERROR"),
    "DISCONNECT":     (C.GREY,    "<<", "DISCONNECT"),
}

# Credentials that get rejected — everything else accepted
REJECTED_CREDENTIALS = {
    ("", ""),
    ("root", ""),
    ("admin", ""),
}

# ─── SQLite ───────────────────────────────────────────────────────────────────
DB_PATH = "logs/honeypot.db"
db_lock = threading.Lock()

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp    TEXT,
                ip           TEXT,
                port         INTEGER,
                event        TEXT,
                country      TEXT,
                city         TEXT,
                isp          TEXT,
                asn          TEXT,
                username     TEXT,
                password     TEXT,
                login_result TEXT,
                command      TEXT,
                error        TEXT,
                session_id   TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS login_attempts (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp  TEXT,
                ip         TEXT,
                username   TEXT,
                password   TEXT,
                result     TEXT,
                country    TEXT,
                city       TEXT,
                session_id TEXT
            )
        """)
        conn.commit()

def db_insert(event_type: str, data: dict, addr: tuple, geo: dict, session_id: str = ""):
    row = (
        datetime.now().isoformat(),
        addr[0], addr[1],
        event_type,
        geo.get("country", ""),
        geo.get("city", ""),
        geo.get("isp", ""),
        geo.get("asn", ""),
        data.get("username", ""),
        data.get("password", ""),
        data.get("login_result", ""),
        data.get("cmd", ""),
        data.get("error", ""),
        session_id,
    )
    with db_lock:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("""
                INSERT INTO events
                (timestamp,ip,port,event,country,city,isp,asn,
                 username,password,login_result,command,error,session_id)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, row)
            if event_type in ("LOGIN_SUCCESS", "LOGIN_FAILED"):
                conn.execute("""
                    INSERT INTO login_attempts
                    (timestamp,ip,username,password,result,country,city,session_id)
                    VALUES (?,?,?,?,?,?,?,?)
                """, (
                    datetime.now().isoformat(),
                    addr[0],
                    data.get("username", ""),
                    data.get("password", ""),
                    data.get("login_result", ""),
                    geo.get("country", ""),
                    geo.get("city", ""),
                    session_id,
                ))
            conn.commit()

# ─── Fake shell responses ─────────────────────────────────────────────────────
FAKE_RESPONSES = {
    "id":              b"uid=0(root) gid=0(root) groups=0(root)\r\n$ ",
    "whoami":          b"root\r\n$ ",
    "uname -a":        b"Linux ubuntu 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux\r\n$ ",
    "hostname":        b"ubuntu-server\r\n$ ",
    "pwd":             b"/root\r\n$ ",
    "ls":              b"snap  .bashrc  .profile  .ssh\r\n$ ",
    "ls -la":          b"total 32\r\ndrwx------ 4 root root 4096 May 2 10:00 .\r\ndrwxr-xr-x 1 root root 4096 May 2 10:00 ..\r\ndrwx------ 2 root root 4096 May 2 10:00 .ssh\r\n$ ",
    "cat /etc/passwd": b"root:x:0:0:root:/root:/bin/bash\r\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\r\n$ ",
    "cat /etc/shadow": b"cat: /etc/shadow: Permission denied\r\n$ ",
    "ps aux":          b"USER       PID %CPU %MEM COMMAND\r\nroot         1  0.0  0.1 /sbin/init\r\nroot       512  0.0  0.1 sshd\r\n$ ",
    "netstat -an":     b"tcp    0.0.0.0:22       0.0.0.0:*        LISTEN\r\n$ ",
    "ifconfig":        b"eth0: flags=4163  inet 192.168.1.100  netmask 255.255.255.0\r\n$ ",
    "ip a":            b"2: eth0: inet 192.168.1.100/24\r\n$ ",
    "df -h":           b"Filesystem  Size  Used Avail Use%\r\n/dev/sda1    50G   12G   35G  26%\r\n$ ",
    "free -m":         b"Mem:   7982   4201   3781\r\nSwap:  2047      0   2047\r\n$ ",
    "history":         b"    1  apt update\r\n    2  apt install nginx\r\n    3  systemctl start nginx\r\n$ ",
    "uptime":          b" 10:00:01 up 12 days,  3:24,  load average: 0.01\r\n$ ",
    "exit":            b"logout\r\n",
}

def fake_response(cmd: str) -> bytes:
    return FAKE_RESPONSES.get(cmd.strip(), b"bash: command not found\r\n$ ")

# ─── GeoIP ────────────────────────────────────────────────────────────────────
@lru_cache(maxsize=1024)
def geoip_lookup(ip: str) -> dict:
    if any(ip.startswith(p) for p in PRIVATE_PREFIXES):
        return {"country": "Private", "country_code": "", "region": "",
                "city": "Private", "isp": "Private", "org": "", "asn": ""}
    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,countryCode,regionName,city,isp,org,as"},
            timeout=5,
        )
        d = resp.json()
        if d.get("status") == "success":
            return {
                "country":      d.get("country", ""),
                "country_code": d.get("countryCode", ""),
                "region":       d.get("regionName", ""),
                "city":         d.get("city", ""),
                "isp":          d.get("isp", ""),
                "org":          d.get("org", ""),
                "asn":          d.get("as", ""),
            }
        return {"geoip_error": d.get("message", "unknown")}
    except Exception as e:
        return {"geoip_error": str(e)}

# ─── Rate limiter ─────────────────────────────────────────────────────────────
def is_rate_limited(ip: str) -> bool:
    now = time.time()
    with connection_lock:
        timestamps = connection_tracker.get(ip, [])
        timestamps = [t for t in timestamps if now - t < RATE_WINDOW]
        if len(timestamps) >= RATE_LIMIT:
            return True
        timestamps.append(now)
        connection_tracker[ip] = timestamps
    return False

# ─── Login check ──────────────────────────────────────────────────────────────
def check_login(username: str, password: str) -> str:
    if (username.strip(), password.strip()) in REJECTED_CREDENTIALS:
        return "LOGIN_FAILED"
    return "LOGIN_SUCCESS"

# ─── Logging ──────────────────────────────────────────────────────────────────
def format_pretty(event_type: str, data: dict, addr: tuple, geo: dict, session_id: str = "") -> str:
    import re
    color, icon, label = EVENT_STYLE.get(event_type, (C.WHITE, "--", event_type))
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    sep_top = C.GREY + "═" * 56 + C.RESET
    sep_mid = C.GREY + "─" * 56 + C.RESET
    sep_bot = C.GREY + "═" * 56 + C.RESET
    header  = f"{color}{C.BOLD}[{ts}]  {icon} {label}{C.RESET}"

    def field(key, val):
        return f"  {C.CYAN}{key:<12}{C.RESET}: {C.WHITE}{val}{C.RESET}"

    lines = [sep_top, header, sep_mid]

    if session_id:
        lines.append(field("Session", session_id[:8] + "..."))

    lines.append(field("IP", f"{addr[0]}  (port {addr[1]})"))

    if geo.get("country") and geo["country"] != "Private":
        loc = ", ".join(filter(None, [geo.get("city"), geo.get("region"), geo.get("country_code")]))
        lines.append(field("Location", loc))
        isp = f"{geo.get('isp', '')}  |  {geo.get('asn', '')}".strip("  |  ")
        if isp:
            lines.append(field("ISP/ASN", isp))
    else:
        lines.append(field("Location", "Private / Loopback"))

    if event_type in ("LOGIN_SUCCESS", "LOGIN_FAILED"):
        lines.append(field("Username", data.get("username", "")))
        lines.append(field("Password", f"{C.YELLOW}{data.get('password', '')}{C.RESET}"))
        result = data.get("login_result", "")
        result_color = C.GREEN if result == "LOGIN_SUCCESS" else C.RED
        lines.append(field("Result", f"{result_color}{result}{C.RESET}"))
    elif event_type == "COMMAND":
        lines.append(field("Command", f"{C.MAGENTA}{data.get('cmd', '')}{C.RESET}"))
    elif event_type == "ERROR":
        lines.append(field("Error", f"{C.RED}{data.get('error', '')}{C.RESET}"))
    elif event_type == "DISCONNECT":
        lines.append(field("Duration", data.get("duration", "")))
    elif event_type == "RATE_LIMITED":
        lines.append(field("Action", "Connection dropped (rate limit)"))

    lines.append(sep_bot)
    return "\n".join(lines)


def log_data(event_type: str, data: dict, addr: tuple, geo: dict = None, session_id: str = ""):
    import re
    geo = geo or {}

    # Terminal colored output
    print(format_pretty(event_type, data, addr, geo, session_id))

    # Plain text log (strip ANSI)
    plain = re.sub(r"\033\[[0-9;]*m", "",
                   format_pretty(event_type, data, addr, geo, session_id))
    with open("logs/attacks.log", "a") as f:
        f.write(plain + "\n")

    # JSON log
    entry = {
        "timestamp":  datetime.now().isoformat(),
        "session_id": session_id,
        "ip": addr[0], "port": addr[1],
        "event": event_type, "geo": geo, "data": data,
    }
    with open("logs/attacks.json", "a") as f:
        f.write(json.dumps(entry) + "\n")

    # SQLite
    db_insert(event_type, data, addr, geo, session_id)

# ─── Client handler ───────────────────────────────────────────────────────────
def handle_client(client: socket.socket, addr: tuple):
    ip           = addr[0]
    geo          = geoip_lookup(ip)
    session_id   = f"{ip}_{addr[1]}_{int(time.time())}"
    connect_time = time.time()

    try:
        if is_rate_limited(ip):
            log_data("RATE_LIMITED", {}, addr, geo, session_id)
            client.close()
            return

        log_data("CONNECT", {}, addr, geo, session_id)
        client.settimeout(10)
        client.send(SSH_BANNER)

        client.send(b"login: ")
        username_raw = client.recv(1024)
        client.send(b"Password: ")
        password_raw = client.recv(1024)

        user = username_raw.decode(errors="ignore").strip()
        pwd  = password_raw.decode(errors="ignore").strip()

        login_result = check_login(user, pwd)
        log_data(
            login_result,
            {"username": user, "password": pwd, "login_result": login_result},
            addr, geo, session_id
        )

        if login_result == "LOGIN_FAILED":
            client.send(b"Permission denied, please try again.\r\n")
            client.close()
            return

        client.send(b"Welcome to Ubuntu 22.04.3 LTS\r\n$ ")

        while True:
            data = client.recv(1024)
            if not data:
                break
            cmd = "".join(
                c for c in data.decode(errors="ignore").strip()
                if c.isprintable()
            )
            if cmd:
                log_data("COMMAND", {"cmd": cmd}, addr, geo, session_id)
                client.send(fake_response(cmd))
                if cmd.strip() == "exit":
                    break

    except Exception as e:
        log_data("ERROR", {"error": str(e)}, addr, geo, session_id)
    finally:
        duration = round(time.time() - connect_time, 1)
        log_data("DISCONNECT", {"duration": f"{duration}s"}, addr, geo, session_id)
        client.close()

# ─── Server ───────────────────────────────────────────────────────────────────
def print_banner():
    print(f"""
{C.CYAN}{C.BOLD}
  ╔══════════════════════════════════════════╗
  ║         SSH HONEYPOT  STARTED            ║
  ╠══════════════════════════════════════════╣
  ║  Port     : {PORT:<29}║
  ║  Workers  : {MAX_WORKERS:<29}║
  ║  JSON log : logs/attacks.json            ║
  ║  Text log : logs/attacks.log             ║
  ║  Database : logs/honeypot.db             ║
  ╚══════════════════════════════════════════╝
{C.RESET}""")

def start_server():
    init_db()
    start_rotation_scheduler()
    print_banner()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(5)

    try:
        while True:
            client, addr = server.accept()
            executor.submit(handle_client, client, addr)
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}[!] Shutting down honeypot.{C.RESET}")
    finally:
        server.close()
        executor.shutdown(wait=False)


if __name__ == "__main__":
    start_server()
