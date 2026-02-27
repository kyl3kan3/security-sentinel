# 🛡️ Security Sentinel — OpenClaw Skill

An active security monitoring skill for Linux servers (Raspberry Pi, Ubuntu, Debian). Watches your server 24/7 and sends Telegram alerts when something looks wrong. Auto-remediates only for confirmed high-severity threats.

## What it monitors

| Monitor | What it catches |
|---------|----------------|
| Processes | New root processes, crypto miner signatures, reverse shell patterns |
| Ports | New open ports, known RAT/backdoor ports |
| SSH | Brute force attempts, auto-blocks repeat offenders |
| Filesystem | Changes to `/etc`, `/root`, cron jobs, SSH keys |
| Docker | New or unexpected containers |
| Resources | Sustained high CPU (crypto miner pattern), high RAM |
| Network | New devices appearing on your LAN |

## Severity model

| Level | Examples | Action |
|-------|----------|--------|
| 🟡 Low | New LAN device, high RAM | Log + Telegram alert |
| 🟠 Medium | New root process, SSH brute force starting | Alert + ask before acting |
| 🔴 High | Active brute force >20 attempts, reverse shell port, known miner | Auto-block/kill + immediate alert |

## Requirements

- Linux server (Raspberry Pi OS, Ubuntu, Debian)
- OpenClaw installed
- Python 3
- `apt` packages: `inotify-tools ufw net-tools fail2ban`
- pip: `psutil requests`
- A free Telegram bot (skill walks you through creating one)

## Installation

### 1. Download the skill

Go to [Releases](../../releases) and download `security-sentinel.skill`

### 2. Add to OpenClaw

Copy the `.skill` file to your OpenClaw skills directory:

```bash
# Find your skills directory first
ls ~/openclaw/skills/

# Then install
cp security-sentinel.skill ~/openclaw/skills/
```

Restart OpenClaw:
```bash
cd ~/openclaw && docker compose restart
```

### 3. Run setup

In OpenClaw, just say:

> "Set up security sentinel"

The skill will walk you through:
1. Creating a Telegram bot (takes ~2 minutes)
2. Installing system dependencies
3. Starting the background monitoring daemon
4. Sending a test alert to confirm everything works

## Usage

Once installed, talk to it naturally:

- `"Run a security scan"` — on-demand full scan
- `"Show recent security alerts"` — last 50 log entries
- `"Stop sentinel"` / `"Restart sentinel"` — daemon control
- `"Is anything suspicious running?"` — quick process check

## File structure

```
security-sentinel/
├── SKILL.md                          # OpenClaw skill definition
├── scripts/
│   └── sentinel_daemon.py           # Background monitoring daemon
└── references/
    ├── on_demand_scan.md            # Manual scan procedures
    └── performance_tuning.md        # Pi resource optimization
```

## Performance (Raspberry Pi 5)

| Config | CPU (idle) | RAM |
|--------|-----------|-----|
| Default | 1-3% | ~45MB |
| Minimal (tuned) | <1% | ~30MB |

## License

MIT

## Changelog

### v1.0.2
- Added `/home/kyl3kan3/.openclaw` to `WATCH_DIRS` — agent config, `openclaw.json`, and cron definitions now trigger alerts on change
- Removed `.openclaw` from `WATCH_EXCLUDE` (was previously silencing all OpenClaw config changes)
