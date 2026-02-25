# On-Demand Security Scan

Run this when the user asks for a manual scan or "what's happening right now".
Execute each section, collect output, summarize findings at the end.

## 1. Open Ports & Services
```bash
ss -tlnp
```
Flag any port that isn't expected (22/SSH, 80/443/web, common app ports the user knows about).

## 2. Active Connections (outbound)
```bash
ss -tnp state established
```
Look for connections to unknown external IPs, especially on unusual ports.

## 3. Running Processes (all users)
```bash
ps auxf --sort=-%cpu | head -40
```
Flag: high CPU processes, processes with random/obfuscated names, processes running as root unexpectedly.

## 4. Recent Auth Log (last 100 lines)
```bash
sudo tail -100 /var/log/auth.log 2>/dev/null || sudo tail -100 /var/log/secure 2>/dev/null
```
Look for: Failed password, Invalid user, Accepted publickey from unexpected IPs.

## 5. Cron Jobs (all users)
```bash
sudo crontab -l 2>/dev/null
ls -la /etc/cron* /var/spool/cron/crontabs/ 2>/dev/null
sudo cat /etc/crontab
```
Flag any entry you don't recognize.

## 6. Recently Modified Files in Sensitive Dirs
```bash
sudo find /etc /usr/local/bin /root -mtime -1 -type f 2>/dev/null
```
Flag anything changed in the last 24h that the user didn't change.

## 7. Listening Services Summary
```bash
systemctl list-units --type=service --state=running
```

## 8. Docker Status
```bash
docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null
```

## 9. Failed Login Summary
```bash
sudo grep "Failed password" /var/log/auth.log 2>/dev/null | awk '{print $11}' | sort | uniq -c | sort -rn | head -20
```
Any IP with >5 failures is worth noting.

## 10. Check for Known Rootkit Signatures (if rkhunter installed)
```bash
which rkhunter && sudo rkhunter --check --skip-keypress --quiet 2>/dev/null | grep -E "Warning|Found"
```

---

## Summarize Findings

After running all checks, present results as:

**Clean** — nothing flagged  
**Warnings** — things worth watching but not urgent  
**Issues** — things that need action

Always end with: "Do you want me to investigate anything specific?"
