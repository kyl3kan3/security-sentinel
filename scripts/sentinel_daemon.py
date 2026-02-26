#!/usr/bin/env python3
"""
Security Sentinel Daemon
Monitors a Linux server for security threats and sends Telegram alerts.
"""

import os
import sys
import time
import json
import socket
import hashlib
import logging
import subprocess
import threading
from datetime import datetime, timedelta
from pathlib import Path

import requests
import psutil

# ── State persistence ────────────────────────────────────────────────────────
STATE_FILE = "/var/lib/security-sentinel/state.json"

def load_state():
    """Load persisted state from disk."""
    try:
        with open(STATE_FILE, 'r') as f:
            data = json.load(f)
            # Convert lists back to sets
            state = {
                "known_pids": set(data.get("known_pids", [])),
                "known_ports": set(data.get("known_ports", [])),
                "known_ips": set(data.get("known_ips", [])),
                "alerted_pids": set(data.get("alerted_pids", [])),
                "alerted_ports": set(data.get("alerted_ports", [])),
                "alerted_ips": set(data.get("alerted_ips", [])),
                "blocked_ips": set(data.get("blocked_ips", [])),
                "ssh_failures": {},
            }
            return state
    except:
        return None

def save_state(state):
    """Persist state to disk."""
    try:
        os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
        data = {
            "known_pids": list(state["known_pids"]),
            "known_ports": list(state["known_ports"]),
            "known_ips": list(state["known_ips"]),
            "alerted_pids": list(state["alerted_pids"]),
            "alerted_ports": list(state["alerted_ports"]),
            "alerted_ips": list(state["alerted_ips"]),
            "blocked_ips": list(state["blocked_ips"]),
            "ssh_failures": {},
        }
        with open(STATE_FILE, 'w') as f:
            json.dump(data, f)
    except Exception as e:
        log.error("Failed to save state: %s", e)

# Try to load persisted state
persisted = load_state()

# ── Config ────────────────────────────────────────────────────────────────────
TELEGRAM_TOKEN  = os.environ.get("TELEGRAM_TOKEN", "")
TELEGRAM_CHAT   = os.environ.get("TELEGRAM_CHAT_ID", "")
LOG_FILE        = os.environ.get("LOG_FILE", "/var/log/security-sentinel.log")
ALERT_LEVEL     = os.environ.get("ALERT_LEVEL", "medium")  # low | medium | high
HOSTNAME        = socket.gethostname()

# Polling intervals (seconds)
POLL_PROCESS    = 10
POLL_PORTS      = 15
POLL_NETWORK    = 30
POLL_FILES      = 5   # inotify-backed, low overhead
POLL_AUTH       = 10
POLL_DOCKER     = 20
POLL_RESOURCES  = 60

# Thresholds
CPU_WARN        = 85   # % sustained
RAM_WARN        = 90   # %
SSH_BRUTE_LIMIT = 10   # failed attempts before MEDIUM alert
SSH_AUTO_BLOCK  = 20   # failed attempts before HIGH + auto-block
BRUTE_WINDOW    = 60   # seconds window for counting attempts

# Known-bad process name fragments (crypto miners, common RATs)
KNOWN_BAD = [
    "xmrig", "minerd", "cpuminer", "ethminer",
    "kdevtmpfsi", "kinsing", "masscan", "zgrab",
    "nc -e", "bash -i", "python -c.*socket", "perl.*socket",
]

# Known-good root processes to ignore (common system tools)
KNOWN_GOOD_ROOT = ["docker", "containerd", "systemd", "cron", "rsyslog"]

# Sensitive dirs to watch for changes
# Watch only critical directories for security
# Exclude noisy directories (CUPS, NetworkManager, etc)
WATCH_DIRS = ["/root", "/var/spool/cron", "/usr/local/bin", "/usr/local/sbin"]

# Exclude patterns (benign changes to skip)
WATCH_EXCLUDE = ["cups", "NetworkManager", "ssl", "certificates", ".cache", 
                 ".openclaw", "sessions.json", ".jsonl", ".tmp", ".swp"]

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("sentinel")

# ── State ─────────────────────────────────────────────────────────────────────
# Load persisted state or create new
if persisted:
    state = persisted
    log.info("Loaded persisted state with %d known PIDs, %d known ports", 
              len(state.get("known_pids", [])), len(state.get("known_ports", [])))
else:
    state = {
        "known_pids":       set(),
        "known_ports":      set(),
        "known_ips":        set(),
        "ssh_failures":     {},   # ip -> list of timestamps
        "alerted_pids":     set(),
        "alerted_ports":    set(),
        "alerted_ips":      set(),
        "blocked_ips":      set(),
    }

# ── Telegram ──────────────────────────────────────────────────────────────────
def send_alert(message: str, level: str = "medium"):
    """Send a Telegram message. level: low | medium | high"""
    level_map = {"low": "🟡", "medium": "🟠", "high": "🔴"}
    emoji = level_map.get(level, "⚪")
    full_msg = f"{emoji} *Security Sentinel* — `{HOSTNAME}`\n\n{message}"

    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT:
        log.warning("Telegram not configured — alert not sent: %s", message)
        return

    try:
        resp = requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
            json={"chat_id": TELEGRAM_CHAT, "text": full_msg, "parse_mode": "Markdown"},
            timeout=10,
        )
        if not resp.json().get("ok"):
            log.error("Telegram send failed: %s", resp.text)
    except Exception as e:
        log.error("Telegram error: %s", e)


def should_alert(level: str) -> bool:
    order = {"low": 0, "medium": 1, "high": 2}
    return order.get(level, 0) >= order.get(ALERT_LEVEL, 1)


# ── Remediation ───────────────────────────────────────────────────────────────
def block_ip(ip: str, reason: str):
    if ip in state["blocked_ips"]:
        return
    state["blocked_ips"].add(ip)
    try:
        subprocess.run(["ufw", "deny", "from", ip, "to", "any"], check=True, capture_output=True)
        msg = f"🔴 AUTO-BLOCKED IP `{ip}`\nReason: {reason}"
        log.warning("AUTO-BLOCK %s — %s", ip, reason)
        send_alert(msg, "high")
    except Exception as e:
        log.error("Failed to block IP %s: %s", ip, e)


def kill_process(pid: int, reason: str):
    try:
        proc = psutil.Process(pid)
        name = proc.name()
        proc.kill()
        msg = f"🔴 AUTO-KILLED process `{name}` (PID {pid})\nReason: {reason}"
        log.warning("AUTO-KILL PID %d (%s) — %s", pid, name, reason)
        send_alert(msg, "high")
    except Exception as e:
        log.error("Failed to kill PID %d: %s", pid, e)


# ── Monitors ──────────────────────────────────────────────────────────────────

def monitor_processes():
    """Detect new processes, especially ones running as root or matching known-bad names."""
    while True:
        try:
            current_pids = set()
            for proc in psutil.process_iter(["pid", "name", "cmdline", "username", "create_time"]):
                try:
                    pid  = proc.info["pid"]
                    name = proc.info["name"] or ""
                    cmd  = " ".join(proc.info["cmdline"] or [])
                    user = proc.info["username"] or ""
                    current_pids.add(pid)

                    if pid in state["known_pids"] or pid in state["alerted_pids"]:
                        continue

                    # Check against known-bad signatures
                    matched_bad = None
                    for bad in KNOWN_BAD:
                        if bad.lower() in cmd.lower() or bad.lower() in name.lower():
                            matched_bad = bad
                            break

                    if matched_bad:
                        msg = (f"⚠️ Suspicious process detected!\n"
                               f"Name: `{name}`\nPID: `{pid}`\nUser: `{user}`\nCmd: `{cmd[:200]}`\n"
                               f"Matched signature: `{matched_bad}`")
                        log.warning("SUSPICIOUS PROCESS pid=%d name=%s cmd=%s", pid, name, cmd[:100])
                        send_alert(msg, "high")
                        state["alerted_pids"].add(pid)
                        kill_process(pid, f"Matched signature: {matched_bad}")

                    # New root process (excluding common system ones)
                    elif user == "root":
                        safe_roots = {"systemd", "kthread", "migration", "rcu_", "ksoftirqd",
                                      "kworker", "sshd", "python3", "bash", "sh", "python",
                                      "docker", "containerd", "cron", "rsyslog", 
                                      "nm-dispatcher", "NetworkManager", "dbus-daemon"}
                        if not any(s in name for s in safe_roots):
                            if should_alert("medium"):
                                msg = (f"New root process spotted\nName: `{name}`\n"
                                       f"PID: `{pid}`\nCmd: `{cmd[:150]}`")
                                send_alert(msg, "medium")
                                state["alerted_pids"].add(pid)

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            state["known_pids"] = current_pids

        except Exception as e:
            log.error("Process monitor error: %s", e)

        time.sleep(POLL_PROCESS)


def monitor_ports():
    """Detect new open ports."""
    def get_open_ports():
        ports = set()
        for conn in psutil.net_connections(kind="inet"):
            if conn.status == "LISTEN" and conn.laddr:
                ports.add(conn.laddr.port)
        return ports

    # Seed baseline
    state["known_ports"] = get_open_ports()

    while True:
        time.sleep(POLL_PORTS)
        try:
            current = get_open_ports()
            new_ports = current - state["known_ports"]
            for port in new_ports:
                if port in state["alerted_ports"]:
                    continue
                level = "high" if port in {4444, 1337, 31337, 6666, 9001} else "medium"
                msg = f"New open port detected: `{port}`"
                if level == "high":
                    msg += "\n⚠️ This port is commonly used by reverse shells / RATs"
                if should_alert(level):
                    log.warning("NEW PORT %d", port)
                    send_alert(msg, level)
                state["alerted_ports"].add(port)
            state["known_ports"] = current
        except Exception as e:
            log.error("Port monitor error: %s", e)


def monitor_ssh_auth():
    """Watch auth.log for SSH brute force attempts."""
    auth_log = Path("/var/log/auth.log")
    if not auth_log.exists():
        auth_log = Path("/var/log/secure")  # RHEL/CentOS
    if not auth_log.exists():
        log.warning("No auth log found — SSH monitoring disabled")
        return

    def tail_file(path):
        with open(path, "r") as f:
            f.seek(0, 2)  # Go to end
            while True:
                line = f.readline()
                if not line:
                    time.sleep(1)
                    continue
                yield line

    for line in tail_file(auth_log):
        try:
            if "Failed password" not in line and "Invalid user" not in line:
                continue

            # Extract IP
            parts = line.split()
            ip = None
            for i, p in enumerate(parts):
                if p == "from" and i + 1 < len(parts):
                    ip = parts[i + 1]
                    break
            if not ip:
                continue

            now = datetime.now()
            state["ssh_failures"].setdefault(ip, [])
            state["ssh_failures"][ip] = [
                t for t in state["ssh_failures"][ip]
                if now - t < timedelta(seconds=BRUTE_WINDOW)
            ]
            state["ssh_failures"][ip].append(now)
            count = len(state["ssh_failures"][ip])

            if count == SSH_BRUTE_LIMIT and should_alert("medium"):
                msg = (f"SSH brute force in progress\nSource IP: `{ip}`\n"
                       f"Failed attempts: `{count}` in last {BRUTE_WINDOW}s")
                log.warning("SSH BRUTE MEDIUM ip=%s count=%d", ip, count)
                send_alert(msg, "medium")

            elif count >= SSH_AUTO_BLOCK:
                log.warning("SSH BRUTE HIGH — auto-blocking ip=%s count=%d", ip, count)
                block_ip(ip, f"SSH brute force: {count} attempts in {BRUTE_WINDOW}s")

        except Exception as e:
            log.error("SSH monitor error: %s", e)


def monitor_filesystem():
    """Use inotifywait to watch sensitive directories for unexpected changes."""
    watch_args = []
    for d in WATCH_DIRS:
        if Path(d).exists():
            watch_args.append(d)

    if not watch_args:
        return

    cmd = ["inotifywait", "-m", "-r", "-e", "create,modify,delete,moved_to",
           "--format", "%T %w %f %e", "--timefmt", "%Y-%m-%dT%H:%M:%S"] + watch_args

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                parts = line.split(maxsplit=3)
                ts, directory, filename, event = parts
                path = directory + filename

                # Skip noisy irrelevant changes
                skip = [".log", ".pid", ".lock", "/proc/", "/sys/", "utmp", "wtmp", "lastlog",
                        "/.openclaw/", "/.wrangler/", "/.cache/", "/.npm/", "/.yarn/", "/.cargo/",
                        "/node_modules/", "/.git/", "/__pycache__/", ".tmp", ".swp",
                        ".xsession-errors", "sessions.json", ".jsonl",
                        ".bashrc", ".profile", ".bash_history",
                        # Watch exclude patterns
                        "cups", "NetworkManager", "ssl", "certificates"]
                if any(s in path for s in skip):
                    continue

                level = "medium"
                note = ""
                # Higher severity for certain paths/events
                if any(x in path for x in ["/etc/passwd", "/etc/shadow", "/etc/sudoers",
                                             "/root/.ssh", "/etc/crontab", "/etc/cron"]):
                    level = "high"
                    note = "\n⚠️ This is a critical system file"

                if should_alert(level):
                    msg = (f"Filesystem change detected\nPath: `{path}`\n"
                           f"Event: `{event}`\nTime: `{ts}`{note}")
                    log.warning("FS CHANGE %s %s", event, path)
                    send_alert(msg, level)

            except ValueError:
                pass
    except FileNotFoundError:
        log.warning("inotifywait not found — filesystem monitoring disabled. Install: apt install inotify-tools")
    except Exception as e:
        log.error("Filesystem monitor error: %s", e)


def monitor_docker():
    """Watch for new/unexpected Docker containers."""
    def get_containers():
        try:
            result = subprocess.run(
                ["docker", "ps", "--format", "{{.ID}} {{.Names}} {{.Image}}"],
                capture_output=True, text=True, timeout=10
            )
            containers = {}
            for line in result.stdout.strip().splitlines():
                parts = line.split(maxsplit=2)
                if len(parts) == 3:
                    containers[parts[0]] = {"name": parts[1], "image": parts[2]}
            return containers
        except Exception:
            return {}

    known = get_containers()

    while True:
        time.sleep(POLL_DOCKER)
        try:
            current = get_containers()
            for cid, info in current.items():
                if cid not in known:
                    msg = (f"New Docker container started\nName: `{info['name']}`\n"
                           f"Image: `{info['image']}`\nID: `{cid[:12]}`")
                    if should_alert("medium"):
                        log.warning("NEW CONTAINER %s image=%s", info["name"], info["image"])
                        send_alert(msg, "medium")
            known = current
        except Exception as e:
            log.error("Docker monitor error: %s", e)


def monitor_resources():
    """Alert on sustained high CPU/RAM (crypto miner pattern)."""
    high_cpu_count = 0

    while True:
        time.sleep(POLL_RESOURCES)
        try:
            cpu = psutil.cpu_percent(interval=5)
            ram = psutil.virtual_memory().percent

            if cpu > CPU_WARN:
                high_cpu_count += 1
                if high_cpu_count >= 3:  # sustained for 3 minutes
                    top_procs = sorted(psutil.process_iter(["name", "cpu_percent"]),
                                       key=lambda p: p.info.get("cpu_percent") or 0,
                                       reverse=True)[:5]
                    top_str = "\n".join(f"  {p.info['name']}: {p.info['cpu_percent']:.1f}%"
                                        for p in top_procs)
                    msg = (f"Sustained high CPU detected — possible crypto miner\n"
                           f"CPU: `{cpu:.1f}%`\nTop processes:\n```\n{top_str}\n```")
                    if should_alert("medium"):
                        log.warning("HIGH CPU %.1f%%", cpu)
                        send_alert(msg, "medium")
                    high_cpu_count = 0
            else:
                high_cpu_count = 0

            if ram > RAM_WARN and should_alert("low"):
                msg = f"High RAM usage: `{ram:.1f}%`"
                log.info("HIGH RAM %.1f%%", ram)
                send_alert(msg, "low")

        except Exception as e:
            log.error("Resource monitor error: %s", e)


# ── Secrets Scanner ───────────────────────────────────────────────────────────
SENSITIVE_FILES = [
    "/root/.ssh/id_rsa",
    "/root/.ssh/id_ed25519",
    "/root/.aws/credentials",
    "/root/.aws/config",
    "/root/.bashrc",
    "/root/.bash_profile",
    "/root/.profile",
    "/home/*/.ssh/id_rsa",
    "/home/*/.aws/credentials",
    "/home/*/.bashrc",
    "/etc/shadow",
    "/etc/passwd",
]

ALERTED_SECRETS = set()  # Track alerted secrets checks

def monitor_secrets():
    """Check for exposed sensitive files (wrong permissions, new files, etc)."""
    while True:
        time.sleep(3600)  # Run hourly
        try:
            import glob
            
            for pattern in SENSITIVE_FILES:
                expanded = glob.glob(pattern)
                for path in expanded:
                    try:
                        st = os.stat(path)
                        mode = st.st_mode
                        
                        # Check for too-open permissions on private keys
                        if "id_rsa" in path or "id_ed25519" in path:
                            if mode & 0o077:  # Anyone can read
                                if path not in ALERTED_SECRETS:
                                    msg = f"🔴 SSH private key has loose permissions!\nPath: `{path}`\nMode: {oct(mode)}"
                                    send_alert(msg, "high")
                                    ALERTED_SECRETS.add(path)
                                    
                        # Check if secrets file is world-readable
                        if mode & 0o004:  # Others can read
                            if "credentials" in path or "bashrc" in path or ".aws" in path:
                                if path not in ALERTED_SECRETS:
                                    msg = f"🟠 Sensitive file is world-readable!\nPath: `{path}`\nMode: {oct(mode)}"
                                    send_alert(msg, "medium")
                                    ALERTED_SECRETS.add(path)
                                    
                    except (OSError, PermissionError):
                        pass
                        
        except Exception as e:
            log.error("Secrets monitor error: %s", e)


def monitor_network_devices():
    """Detect new devices appearing on the local network via ARP."""
    def get_arp_table():
        try:
            result = subprocess.run(["arp", "-n"], capture_output=True, text=True, timeout=10)
            ips = set()
            for line in result.stdout.splitlines()[1:]:
                parts = line.split()
                if parts and parts[0] not in ("Address", "?"):
                    ips.add(parts[0])
            return ips
        except Exception:
            return set()

    state["known_ips"] = get_arp_table()

    while True:
        time.sleep(POLL_NETWORK)
        try:
            current = get_arp_table()
            new_ips = current - state["known_ips"] - state["alerted_ips"]
            for ip in new_ips:
                if should_alert("low"):
                    msg = f"New device on network: `{ip}`"
                    log.info("NEW DEVICE %s", ip)
                    send_alert(msg, "low")
                state["alerted_ips"].add(ip)
            state["known_ips"] = current
        except Exception as e:
            log.error("Network device monitor error: %s", e)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    log.info("Security Sentinel starting on %s", HOSTNAME)
    send_alert(f"🛡️ Security Sentinel started\nHost: `{HOSTNAME}`\nAlert level: `{ALERT_LEVEL}`", "low")

    threads = [
        threading.Thread(target=monitor_ports,            daemon=True, name="ports"),
        threading.Thread(target=monitor_ssh_auth,         daemon=True, name="ssh"),
        threading.Thread(target=monitor_filesystem,       daemon=True, name="filesystem"),
        threading.Thread(target=monitor_docker,           daemon=True, name="docker"),
        threading.Thread(target=monitor_resources,        daemon=True, name="resources"),
        threading.Thread(target=monitor_network_devices,  daemon=True, name="network"),
        threading.Thread(target=monitor_secrets,          daemon=True, name="secrets"),
    ]

    for t in threads:
        t.start()
        log.info("Started monitor: %s", t.name)

    # Keep main thread alive and log heartbeat
    while True:
        time.sleep(3600)
        log.info("Heartbeat — all monitors running")
        send_alert("💓 Sentinel heartbeat — all systems monitored", "low")
        save_state(state)  # Persist known PIDs/ports


if __name__ == "__main__":
    main()
