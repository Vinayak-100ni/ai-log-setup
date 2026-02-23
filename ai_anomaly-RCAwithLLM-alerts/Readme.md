# 🤖 AI Anomaly Detection Engine
> Claude AI-powered RCA · Remote Prometheus + Loki · Email Alerts

---

## Architecture

```
Remote Server (your existing setup)          This Machine
┌──────────────────────────┐                ┌────────────────────────────┐
│  Prometheus  :9090        │ ◄── poll ──── │                            │
│  Loki        :3100        │               │   AI Anomaly Engine :8000  │
│  Grafana     :3000        │               │   Redis (dedup cache)      │
└──────────────────────────┘               └────────────┬───────────────┘
                                                         │
                                              Claude AI API (RCA)
                                                         │
                                              📧 Email → your team
```

---

## Setup in 3 Steps

### Step 1 — Configure
```bash
cp .env.example .env
nano .env
```

Fill in these required values:
```
PROMETHEUS_URL=http://YOUR_SERVER_IP:9090
LOKI_URL=http://YOUR_SERVER_IP:3100
GRAFANA_URL=http://YOUR_SERVER_IP:3000
ANTHROPIC_API_KEY=sk-ant-...
SMTP_USER=your@gmail.com
SMTP_PASS=your-gmail-app-password
EMAIL_TO=oncall@company.com
```

### Step 2 — Start
```bash
docker compose up -d
docker logs -f ai_anomaly_engine    # watch live
```

### Step 3 — Verify
```bash
# Check everything is connected
curl http://localhost:8000/health | jq

# See live metric values from your remote Prometheus
curl http://localhost:8000/metrics_status | jq

# Open dashboard
open http://localhost:8000
```

---

## Gmail App Password Setup

Gmail requires an "App Password" — NOT your real password.

1. Go to [myaccount.google.com](https://myaccount.google.com)
2. Security → 2-Step Verification → enable it
3. Search **"App passwords"** in the search bar
4. Generate → Mail → Your device
5. Copy the 16-character password → paste as `SMTP_PASS` in `.env`

---

## Firewall Rules (remote server)

Your remote server must allow inbound from this machine:

```bash
# On the remote server (Ubuntu/Debian):
sudo ufw allow from YOUR_THIS_MACHINE_IP to any port 9090  # Prometheus
sudo ufw allow from YOUR_THIS_MACHINE_IP to any port 3100  # Loki
sudo ufw allow from YOUR_THIS_MACHINE_IP to any port 3000  # Grafana

# Or to allow all (less secure, dev only):
sudo ufw allow 9090
sudo ufw allow 3100
```

---

## Service → Owner Email Mapping

Edit `ai_engine/main.py` — `SERVICE_OWNER_EMAILS` dict:

```python
SERVICE_OWNER_EMAILS = {
    "api":            ["alice@company.com", "bob@company.com"],
    "database":       ["charlie@company.com"],
    "payments":       ["grace@company.com"],
    "infrastructure": ["ops@company.com"],
    "default":        ["oncall@company.com"],
}
```

Service-specific emails get alerts only for their service.
`EMAIL_TO` in `.env` always gets all alerts as fallback.

---

## Connect Grafana to send alerts here too

In Grafana → Alerting → Contact points → Add:
- Type: **Webhook**
- URL: `http://THIS_MACHINE_IP:8000/webhook/grafana`

This means when Grafana fires an alert, the AI engine gets it too,
enriches it with Claude RCA + logs, and emails it properly.

---

## Adding Your Custom Metrics

Edit `METRIC_CHECKS` in `ai_engine/main.py`:

```python
("my_queue_depth",
 'rabbitmq_queue_messages_ready{queue="orders"}',
 500.0, "warning", "api", "Orders queue depth"),
```

Restart after changes: `docker compose restart ai_anomaly_engine`

---

## API Reference

| Endpoint | Description |
|---|---|
| `GET /` | Dashboard UI (auto-refreshes 30s) |
| `GET /health` | Connectivity + config status |
| `GET /metrics_status` | Live values of all monitored metrics |
| `GET /anomalies` | Last 50 anomalies with full RCA |
| `POST /webhook/grafana` | Receive Grafana alerts |
| `POST /webhook/alertmanager` | Receive AlertManager alerts |

---

## Troubleshooting

**Prometheus unreachable?**
```bash
# From your machine:
curl http://YOUR_SERVER_IP:9090/-/healthy
# If this fails, it's a network/firewall issue, not the engine
```

**Claude API error 401?**
```bash
# Verify key is correct
curl https://api.anthropic.com/v1/messages \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -H "content-type: application/json" \
  -d '{"model":"claude-sonnet-4-6","max_tokens":10,"messages":[{"role":"user","content":"hi"}]}'
```

**Email not sending?**
```bash
docker logs ai_anomaly_engine | grep -i email
# Common: wrong App Password, or Gmail blocking "less secure" access
```

**No metrics data?**
```bash
curl http://localhost:8000/metrics_status | jq
# If all values are null, Prometheus URL is wrong or metrics don't exist yet
# Check your actual metric names in Prometheus UI first
```
