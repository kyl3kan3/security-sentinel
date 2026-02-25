---
name: security-sentinel
description: >
  Active security monitoring skill for Linux servers (especially Raspberry Pi). Use this skill
  whenever the user mentions security scanning, monitoring for threats, watching for intrusions,
  checking for suspicious activity, setting up alerts, brute force detection, port scanning,
  malware detection, or anything related to keeping their server secure. Also triggers when user
  asks to "start sentinel", "check security", "run a security scan", "what's happening on my server",
  or "is anything suspicious running". Handles full setup from scratch including Telegram bot
  configuration, daemon installation, and live monitoring management.
---

# Security Sentinel

A live security monitoring skill that watches your server 24/7 and alerts you via Telegram when something looks wrong. Auto-remediates only for confirmed high-severity threats.

## First Run Setup

If the user hasn't set this up before, run setup in this order:

1. Check if the daemon is installed: `systemctl status security-sentinel 2>/dev/null`
2. If not found, run the setup flow below
3. If found, go straight to **Runtime Commands**

---

## Setup Flow

### Step 1: Telegram Bot

Tell the user:

> "We need a Telegram bot to send you alerts. Here's how to get one in 60 seconds:"
> 1. Open Telegram and search for **@BotFather**
> 2. Send `/newbot` and follow the prompts (pick any name and username)
> 3. BotFather will give you a **token** that looks like `123456789:ABCdef...`
> 4. Now message your new bot once (just say hi) so it can find your chat
> 5. Visit: `https://api.telegram.org/bot<YOUR_TOKEN>/getUpdates` in a browser
> 6. Find `"chat":{"id":` in the response — that number is your **Chat ID**

Ask the user to provide their `TELEGRAM_TOKEN` and `TELEGRAM_CHAT_ID` before continuing.

Once provided, store them:
```bash
sudo mkdir -p /etc/security-sentinel
sudo tee /etc/security-sentinel/config.env > /dev/null <<EOF
TELEGRAM_TOKEN=<token>
TELEGRAM_CHAT_ID=<chat_id>
ALERT_LEVEL=medium
LOG_FILE=/var/log/security-sentinel.log
EOF
sudo chmod 600 /etc/security-sentinel/config.env
```

Test the bot immediately:
```bash
source /etc/security-sentinel/config.env
curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage" \
  -d chat_id="${TELEGRAM_CHAT_ID}" \
  -d text="🛡️ Security Sentinel test message — setup working!"
```

If curl returns `"ok":true`, tell the user "Check your Telegram — you should see a message."

### Step 2: Install Dependencies

```bash
sudo apt-get update -qq
sudo apt-get install -y inotify-tools ufw net-tools nmap fail2ban python3 python3-pip curl
pip3 install psutil requests --break-system-packages
```

### Step 3: Install the Daemon

Write the monitoring daemon script:
```bash
sudo cp /path/to/skill/scripts/sentinel_daemon.py /usr/local/bin/sentinel_daemon.py
sudo chmod +x /usr/local/bin/sentinel_daemon.py
```

Install as a systemd service:
```bash
sudo tee /etc/systemd/system/security-sentinel.service > /dev/null <<EOF
[Unit]
Description=Security Sentinel Monitor
After=network.target

[Service]
Type=simple
EnvironmentFile=/etc/security-sentinel/config.env
ExecStart=/usr/bin/python3 /usr/local/bin/sentinel_daemon.py
Restart=always
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable security-sentinel
sudo systemctl start security-sentinel
```

Confirm it's running:
```bash
sudo systemctl status security-sentinel --no-pager
```

Tell the user: "Sentinel is live. You'll get a Telegram message now confirming it started."

---

## Runtime Commands

These are the commands to use once the daemon is running.

### Check status
```bash
sudo systemctl status security-sentinel --no-pager
```

### View recent alerts
```bash
sudo tail -n 50 /var/log/security-sentinel.log
```

### Run an on-demand full scan
Read `references/on_demand_scan.md` for the full scan procedure.

### Stop / restart
```bash
sudo systemctl stop security-sentinel
sudo systemctl restart security-sentinel
```

### Update config (change alert level, token, etc.)
Edit `/etc/security-sentinel/config.env` then restart the service.

---

## Severity Model

Use this when interpreting alerts or deciding remediation:

| Level | Examples | Action |
|-------|----------|--------|
| 🟡 LOW | New LAN device, unusual port, high CPU | Log + Telegram alert |
| 🟠 MEDIUM | New root process, SSH brute force starting, unexpected cron | Alert + ask user before acting |
| 🔴 HIGH | Active brute force (>20 attempts/min), reverse shell indicators, known crypto miner hash | Auto-block + kill + alert immediately |

For HIGH severity auto-remediation:
```bash
# Block an IP
sudo ufw deny from <IP> to any
# Kill a process
sudo kill -9 <PID>
# Log the action
echo "[$(date)] AUTO-REMEDIATED: <reason>" >> /var/log/security-sentinel.log
```

Always send a Telegram message after any auto-remediation explaining what was done and why.

---

## Troubleshooting

- **Daemon not starting**: Check `sudo journalctl -u security-sentinel -n 30`
- **No Telegram alerts**: Re-run the curl test from Step 1 to verify token/chat ID
- **High false positives**: Set `ALERT_LEVEL=high` in config.env and restart
- **Daemon using too much CPU**: Check `references/performance_tuning.md`
