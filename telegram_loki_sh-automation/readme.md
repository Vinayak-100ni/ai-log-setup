# AI Alert System Setup Guide
## Telegram + Custom Script + Silent Container Detection

---

## ARCHITECTURE

```
Docker → Loki → Grafana (pure LogQL dashboard — untouched)
                    ↓
              Python AI (every 5 min, reads Loki only)
              ├── Drain clustering   → finds unknown patterns
              ├── Silent container   → finds dead containers
              ├── LLM explanation    → plain English root cause
              ├── Telegram alert     → instant notification
              └── on_anomaly.sh      → your custom actions
```

Nothing is pushed back to Loki. No double storage. No timestamp issues.
Your existing dashboard works exactly as before.

---

## STEP 1 — Create Telegram Bot (2 minutes)

```
1. Open Telegram → search for @BotFather
2. Send: /newbot
3. Choose a name:  EdgeAI Monitor
4. Choose username: edge_ai02_bot  (must end in _bot)
5. BotFather replies with your token:
   1234567890:ABCdefGHIjklMNOpqrSTUvwxYZ
   → Save this as TELEGRAM_TOKEN

6. Get your Chat ID:
   → Open https://t.me/userinfobot in Telegram
   → It replies with your Chat ID number
   → Save this as TELEGRAM_CHAT_ID

7. Start your bot:
   → Search your bot name in Telegram
   → Click Start
```

---

## STEP 2 — Create Directory Structure

```bash
# Create script directory
sudo mkdir -p /opt/scripts
sudo mkdir -p /var/lib/ai-alert
sudo mkdir -p /var/log/ai-anomalies
sudo chown $USER:$USER /var/lib/ai-alert /var/log/ai-anomalies  or sudo chown $(id -un):$(id -gn) /var/lib/ai-alert /var/log/ai-anomalies
```

---

## STEP 3 — Copy the Python Script

```bash
mkdir ~/monitoring/
cp ai_alert.py ~/monitoring/ai_alert.py
```

---

## STEP 4 — Copy and Configure Your Custom Script

```bash
# Copy the template
sudo cp on_anomaly.sh /opt/scripts/on_anomaly.sh
sudo chmod +x /opt/scripts/on_anomaly.sh

# Edit to add your custom actions
nano /opt/scripts/on_anomaly.sh
```

### What the script receives from Python:
```bash
$1 = container name   →  670a8a65-rules-engine
$2 = severity         →  CRITICAL / ERROR / WARNING
$3 = issue type       →  silent_container / new_template / spike
$4 = message          →  plain English description
```

### The script already handles:
```
silent_container → checks docker status, restarts if exited
CRITICAL         → dumps last 100 log lines for investigation
spike            → collects docker stats
```

### Add your own actions at the bottom of the script:
```bash
# Example: restart specific containers automatically
if [[ "$SEVERITY" == "CRITICAL" && "$ISSUE_TYPE" == "silent_container" ]]; then
    docker restart "$CONTAINER"
fi

# Example: call your own webhook
curl -s -X POST "https://your-api.com/alert" \
  -d "container=$CONTAINER&severity=$SEVERITY"

# Example: run diagnostics
/opt/scripts/diagnostics.sh "$CONTAINER"
```

---

## STEP 5 — Create .env File

```bash
cat > ~/monitoring/.env.alert << EOF
# Loki
LOKI_URL=https://loki.edgedock.co.za
LOKI_HOST=edge-ai02
LOKI_LOOKBACK=300
LOKI_LIMIT=5000

# Telegram
TELEGRAM_TOKEN=YOUR_BOT_TOKEN_HERE
TELEGRAM_CHAT_ID=YOUR_CHAT_ID_HERE

# LLM explanation (optional — comment out if not needed)
# ANTHROPIC_API_KEY=your_claude_api_key_here

# Script
ON_ANOMALY_SCRIPT=/opt/scripts/on_anomaly.sh
STATE_FILE=/var/lib/ai-alert/state.json

# Timing
RUN_INTERVAL=300
LOG_LEVEL=INFO
EOF
```

```bash
# Fill in your real values
nano ~/monitoring/.env.alert
```

---

## STEP 6 — Install Python Dependencies

```bash
cd ~/monitoring
source venv/bin/activate
pip install requests pandas scikit-learn
```

---

## STEP 7 — Test Run

```bash
cd ~/monitoring
source venv/bin/activate
export $(cat .env.alert | grep -v '#' | xargs)
python ai_alert.py
```

### Expected output:
```
2026-02-19T06:00:00 [INFO] AI Alert System starting — interval=300s
2026-02-19T06:00:00 [INFO] Fetching logs | host=edge-ai02 lookback=300s
2026-02-19T06:00:02 [INFO] Fetched 1247 log lines from 18 containers
2026-02-19T06:00:03 [INFO] Alerts this run: 2 (silent=0 drain=2)

======================================================================
  ANOMALY ALERTS | host=edge-ai02 | count=2
======================================================================
  [WARNING] new_template — New log pattern never seen before appeared 12x
  [ERROR]   spike — Log pattern spiked to 847x (normal: ~45x)

  AI ANALYSIS:
  ROOT CAUSE: streamer-engine losing TCP connection...
  ...

2026-02-19T06:00:05 [INFO] Telegram alert sent
```

### Check Telegram — you should receive:
```
🚨 AI Alert — edge-ai02
🕐 2026-02-19 06:00:05 UTC

🟡 WARNING — New Template
📦 Containers: 670a8a65-rules-engine
🆕 New pattern (12x):
Connection to <IP>:<NUM> failed No route to host
📝 Sample: Connection to tcp://41.190.94.3:555...

🤖 AI Analysis:
ROOT CAUSE: ...
IMPACT: ...
ACTION: ...

📊 Dashboard: your Grafana URL
```

---

## STEP 8 — Install as Systemd Service

```bash
sudo tee /etc/systemd/system/ai-alert.service << EOF
[Unit]
Description=AI Log Anomaly Alert System
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$HOME/monitoring
EnvironmentFile=$HOME/monitoring/.env.alert
ExecStart=$HOME/monitoring/venv/bin/python $HOME/monitoring/ai_alert.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable ai-alert
sudo systemctl start ai-alert
sudo systemctl status ai-alert
```

---

## VERIFY

```bash
# Service running?
sudo systemctl status ai-alert

# Live logs?
journalctl -fu ai-alert

# State file (shows what detector has learned)?
cat /var/lib/ai-alert/state.json | python3 -m json.tool

# Remediation log (what on_anomaly.sh did)?
tail -f /var/log/ai-anomalies/remediation.log

# Force a test alert (temporarily lower threshold)
RUN_INTERVAL=0 LOKI_LOOKBACK=3600 python ~/monitoring/ai_alert.py
```

---

## ALERT TYPES EXPLAINED

| Alert Type | What triggers it | Severity |
|---|---|---|
| silent_container | Container stops sending logs | CRITICAL |
| new_template | Log pattern never seen before | WARNING |
| spike | Known pattern 3x above normal | ERROR |

---

## HOW THE AI LEARNS

The detector gets smarter every run via state.json:

```
Run 1: Sees template "Connection to <IP>:<NUM> failed" → 50x → stores avg=50
Run 2: Same template → 52x → updates avg=51  (normal, no alert)
Run 3: Same template → 847x → 16x above avg  → SPIKE ALERT
Run 4: New template "SSIM deallocated unexpectedly" → never seen → NEW TEMPLATE ALERT
```

After ~24 hours the detector knows your normal baseline
and only alerts on genuine deviations.

---

## SEPARATE FROM GRAFANA DASHBOARD

Your Grafana dashboard uses pure LogQL — completely untouched:
```
{host="edge-ai02"}                                    → all logs
{host="edge-ai02"} |~ "(?i)error|exception"           → errors
sum by(container_name)(rate({host="edge-ai02"}[5m]))  → volume
```

The AI alert system reads from Loki but never writes back.
Zero interference with your dashboard.
