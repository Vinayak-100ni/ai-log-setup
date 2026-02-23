"""
============================================================
 AI Anomaly Detection Engine
 - Connects to remote Prometheus + Loki over HTTP
 - Uses Claude AI (claude-sonnet-4-6) for RCA generation
 - Sends structured Email alerts with full RCA
============================================================
"""

import os, json, time, uuid, logging, asyncio, smtplib
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dataclasses import dataclass, field
from typing import Optional
from collections import defaultdict

import httpx
import redis
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from fastapi import FastAPI, Request, BackgroundTasks
from fastapi.responses import HTMLResponse
import uvicorn

# ─── Logging ────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("anomaly-engine")

# ─── ENV Config ─────────────────────────────────────────────
# Remote server URLs — set your actual IP in .env
PROMETHEUS_URL   = os.getenv("PROMETHEUS_URL",  "http://192.168.1.100:9090")
LOKI_URL         = os.getenv("LOKI_URL",         "http://192.168.1.100:3100")
GRAFANA_URL      = os.getenv("GRAFANA_URL",      "http://192.168.1.100:3000")
REDIS_URL        = os.getenv("REDIS_URL",         "redis://localhost:6379")
CHECK_INTERVAL   = int(os.getenv("CHECK_INTERVAL_SECONDS", "60"))

# Remote auth (if Prometheus/Grafana has basic auth)
PROM_USER        = os.getenv("PROMETHEUS_USER", "")
PROM_PASS        = os.getenv("PROMETHEUS_PASS", "")
LOKI_USER        = os.getenv("LOKI_USER", "")
LOKI_PASS        = os.getenv("LOKI_PASS", "")

# Claude AI (Anthropic)
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
CLAUDE_MODEL      = "claude-sonnet-4-6"   # fixed — best for structured analysis

# Email config
SMTP_HOST        = os.getenv("SMTP_HOST",   "smtp.gmail.com")
SMTP_PORT        = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER        = os.getenv("SMTP_USER",   "")
SMTP_PASS        = os.getenv("SMTP_PASS",   "")   # Gmail: use App Password
EMAIL_FROM       = os.getenv("EMAIL_FROM",  "")
EMAIL_TO         = os.getenv("EMAIL_TO",    "")   # comma-separated list

# ─── Service → Owner Email mapping ───────────────────────────
# Edit this — maps your services to the people who own them
SERVICE_OWNER_EMAILS: dict[str, list[str]] = {
    "api":            ["alice@company.com", "bob@company.com"],
    "database":       ["charlie@company.com"],
    "frontend":       ["eve@company.com"],
    "payments":       ["grace@company.com", "henry@company.com"],
    "infrastructure": ["ops@company.com"],
    "default":        [EMAIL_TO],   # fallback to config
}

# ─── Metric Checks ───────────────────────────────────────────
# (id, promql, static_threshold, severity, service, description)
# Modify these PromQL queries to match your actual metric names
METRIC_CHECKS = [
    ("cpu_high",
     'avg(rate(node_cpu_seconds_total{mode!="idle"}[5m])) * 100',
     85.0, "critical", "infrastructure", "CPU usage %"),

    ("memory_high",
     '(1 - node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes) * 100',
     90.0, "critical", "infrastructure", "Memory usage %"),

    ("http_error_rate",
     'sum(rate(http_requests_total{status=~"5.."}[5m])) / sum(rate(http_requests_total[5m])) * 100',
     5.0, "critical", "api", "HTTP 5xx error rate %"),

    ("http_latency_p99",
     'histogram_quantile(0.99, rate(http_request_duration_seconds_bucket[5m]))',
     2.0, "warning", "api", "P99 request latency (seconds)"),

    ("disk_usage",
     '(1 - node_filesystem_free_bytes{mountpoint="/"} / node_filesystem_size_bytes{mountpoint="/"}) * 100',
     85.0, "warning", "infrastructure", "Disk usage %"),

    ("db_connections",
     'pg_stat_database_numbackends',
     80.0, "warning", "database", "Active DB connections"),

    ("pod_restarts",
     'increase(kube_pod_container_status_restarts_total[1h])',
     5.0, "warning", "kubernetes", "Pod restart count in 1h"),
]

# Log keywords to look for when enriching anomaly context
LOG_PATTERNS = [
    "ERROR", "FATAL", "panic", "exception", "OOMKilled",
    "timeout", "deadlock", "connection refused", "out of memory",
    "segfault", "kill", "failed", "critical",
]


# ════════════════════════════════════════════════════════════
#  DATA MODEL
# ════════════════════════════════════════════════════════════
@dataclass
class Anomaly:
    id:           str
    service:      str
    metric_id:    str
    metric_desc:  str
    value:        float
    threshold:    float
    severity:     str
    timestamp:    str
    detected_by:  str          # "static" | "ml" | "zscore" | combinations
    logs:         list[str]  = field(default_factory=list)
    rca:          dict       = field(default_factory=dict)

    @property
    def severity_emoji(self):
        return {"critical": "🔴", "warning": "🟡", "info": "🔵"}.get(self.severity, "⚠️")

    @property
    def owner_emails(self) -> list[str]:
        emails = SERVICE_OWNER_EMAILS.get(self.service, SERVICE_OWNER_EMAILS.get("default", []))
        # Always include the global EMAIL_TO as well
        all_emails = list(set(emails + [e.strip() for e in EMAIL_TO.split(",") if e.strip()]))
        return all_emails


# ════════════════════════════════════════════════════════════
#  PROMETHEUS CLIENT  (remote server)
# ════════════════════════════════════════════════════════════
class PrometheusClient:
    def __init__(self, url: str, user: str = "", password: str = ""):
        self.url  = url.rstrip("/")
        self.auth = (user, password) if user else None

    def _headers(self) -> dict:
        return {}

    async def instant(self, query: str) -> Optional[float]:
        try:
            async with httpx.AsyncClient(timeout=15, auth=self.auth) as c:
                r = await c.get(f"{self.url}/api/v1/query", params={"query": query})
                r.raise_for_status()
                results = r.json()["data"]["result"]
                if results:
                    return float(results[0]["value"][1])
        except httpx.ConnectError:
            log.error(f"Cannot reach Prometheus at {self.url} — check IP/port and firewall")
        except Exception as e:
            log.warning(f"Prometheus query failed [{query[:50]}]: {e}")
        return None

    async def range_values(self, query: str, minutes: int = 60) -> list[float]:
        end   = datetime.utcnow()
        start = end - timedelta(minutes=minutes)
        try:
            async with httpx.AsyncClient(timeout=15, auth=self.auth) as c:
                r = await c.get(f"{self.url}/api/v1/query_range", params={
                    "query": query,
                    "start": start.isoformat() + "Z",
                    "end":   end.isoformat()   + "Z",
                    "step":  "60s",
                })
                r.raise_for_status()
                results = r.json()["data"]["result"]
                if results:
                    return [float(v[1]) for v in results[0]["values"]]
        except Exception as e:
            log.warning(f"Prometheus range query failed: {e}")
        return []

    async def health_check(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=5, auth=self.auth) as c:
                r = await c.get(f"{self.url}/-/healthy")
                return r.status_code == 200
        except:
            return False


# ════════════════════════════════════════════════════════════
#  LOKI CLIENT  (remote server)
# ════════════════════════════════════════════════════════════
class LokiClient:
    def __init__(self, url: str, user: str = "", password: str = ""):
        self.url  = url.rstrip("/")
        self.auth = (user, password) if user else None

    async def query_logs(self, service: str, minutes_back: int = 15, limit: int = 60) -> list[str]:
        end   = datetime.utcnow()
        start = end - timedelta(minutes=minutes_back)
        # Try multiple label selectors to match your existing Loki labels
        queries = [
            f'{{service="{service}"}}',
            f'{{job="{service}"}}',
            f'{{job=~".*{service}.*"}}',
            f'{{container=~".*{service}.*"}}',
            f'{{app="{service}"}}',
        ]
        for query in queries:
            logs = await self._fetch(query, start, end, limit)
            if logs:
                return logs
        # Fallback: any recent logs
        return await self._fetch('{job=~".+"}', start, end, limit // 2)

    async def _fetch(self, query: str, start, end, limit: int) -> list[str]:
        params = {
            "query":     query,
            "limit":     limit,
            "start":     str(int(start.timestamp() * 1e9)),
            "end":       str(int(end.timestamp()   * 1e9)),
            "direction": "backward",
        }
        try:
            async with httpx.AsyncClient(timeout=15, auth=self.auth) as c:
                r = await c.get(f"{self.url}/loki/api/v1/query_range", params=params)
                r.raise_for_status()
                results = r.json().get("data", {}).get("result", [])
                lines = []
                for stream in results:
                    for _, line in stream.get("values", []):
                        lines.append(line)
                return lines
        except httpx.ConnectError:
            log.error(f"Cannot reach Loki at {self.url} — check IP/port and firewall")
        except Exception as e:
            log.debug(f"Loki query failed [{query}]: {e}")
        return []

    async def health_check(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=5, auth=self.auth) as c:
                r = await c.get(f"{self.url}/ready")
                return r.status_code == 200
        except:
            return False


# ════════════════════════════════════════════════════════════
#  ML ANOMALY DETECTOR  (Isolation Forest + Z-score)
# ════════════════════════════════════════════════════════════
class MLDetector:
    def __init__(self):
        self._models:  dict[str, IsolationForest] = {}
        self._scalers: dict[str, StandardScaler]  = {}

    def isolation_forest(self, metric_id: str, history: list[float], current: float) -> bool:
        """Detects anomalies even when value is below static threshold."""
        if len(history) < 15:
            return False
        model  = self._models.setdefault(metric_id,  IsolationForest(contamination=0.05, random_state=42))
        scaler = self._scalers.setdefault(metric_id, StandardScaler())
        X   = np.array(history + [current]).reshape(-1, 1)
        X_s = scaler.fit_transform(X)
        return int(model.fit_predict(X_s)[-1]) == -1

    def zscore(self, history: list[float], current: float, threshold: float = 3.0) -> bool:
        """Secondary: z-score outlier check."""
        if len(history) < 10:
            return False
        arr = np.array(history)
        std = arr.std()
        if std == 0:
            return False
        return abs((current - arr.mean()) / std) > threshold


# ════════════════════════════════════════════════════════════
#  CLAUDE AI CLIENT  — RCA generation
# ════════════════════════════════════════════════════════════
class ClaudeRCAClient:
    API_URL = "https://api.anthropic.com/v1/messages"

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {
            "x-api-key":         api_key,
            "anthropic-version": "2023-06-01",
            "content-type":      "application/json",
        }

    async def generate_rca(self, anomaly: Anomaly) -> dict:
        if not self.api_key:
            log.warning("ANTHROPIC_API_KEY not set — using rule-based RCA fallback")
            return self._rule_based_rca(anomaly)

        log_sample = "\n".join(anomaly.logs[-30:]) if anomaly.logs else "No logs captured."

        prompt = f"""You are a senior SRE with deep expertise in production systems.
A real anomaly has been detected. Analyze it thoroughly and return structured JSON.

## ANOMALY DETAILS
- Service       : {anomaly.service}
- Metric        : {anomaly.metric_desc}  ({anomaly.metric_id})
- Current Value : {anomaly.value:.4f}
- Threshold     : {anomaly.threshold:.4f}
- Severity      : {anomaly.severity}
- Detected By   : {anomaly.detected_by}  (static threshold + ML isolation forest + z-score)
- Timestamp     : {anomaly.timestamp} UTC
- Alert ID      : {anomaly.id}

## RECENT LOGS (last 30 lines from {anomaly.service})
{log_sample}

## YOUR TASK
Analyze the anomaly and logs carefully. Return ONLY valid JSON, no markdown, no extra text:

{{
  "root_cause": "One precise sentence — the exact technical root cause",
  "affected_component": "Exact file, class, function, query, or config where issue originates",
  "layer": "infrastructure | application | database | network | external | configuration",
  "blast_radius": "Concrete description of what users/systems are impacted right now",
  "confidence": "high | medium | low",
  "why_now": "What likely triggered this at this specific time (deploy, traffic spike, cron job, etc.)",
  "remediation": [
    "IMMEDIATE: Step 1 action to stop the bleeding",
    "SHORT-TERM: Step 2 to fix the root cause",
    "FOLLOW-UP: Step 3 to verify recovery",
    "CLEANUP: Step 4 post-incident"
  ],
  "prevention": "Concrete architectural or process change to permanently prevent recurrence",
  "estimated_fix_time": "realistic estimate e.g. 5min | 30min | 2hr | requires-deployment",
  "related_metrics": "Other metrics that may also be impacted to check",
  "runbook_hint": "One sentence on what runbook or doc to reference"
}}"""

        try:
            async with httpx.AsyncClient(timeout=60) as c:
                r = await c.post(self.API_URL, headers=self.headers, json={
                    "model":      CLAUDE_MODEL,
                    "max_tokens": 1000,
                    "messages":   [{"role": "user", "content": prompt}],
                })
                r.raise_for_status()
                text = r.json()["content"][0]["text"].strip()
                # Parse JSON from response
                start = text.find("{")
                end   = text.rfind("}") + 1
                if start >= 0 and end > start:
                    rca = json.loads(text[start:end])
                    log.info(f"   Claude RCA: confidence={rca.get('confidence','?')} | layer={rca.get('layer','?')}")
                    return rca
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                log.error("Claude API: Invalid ANTHROPIC_API_KEY")
            elif e.response.status_code == 429:
                log.error("Claude API: Rate limited — using fallback RCA")
            else:
                log.error(f"Claude API error {e.response.status_code}: {e.response.text[:200]}")
        except json.JSONDecodeError as e:
            log.error(f"Claude returned invalid JSON: {e}")
        except Exception as e:
            log.error(f"Claude RCA failed: {e}")

        return self._rule_based_rca(anomaly)

    def _rule_based_rca(self, anomaly: Anomaly) -> dict:
        """Fallback when Claude API is unavailable."""
        rules = {
            "cpu_high":       ("High CPU load — possible runaway process or traffic spike",
                               "Check top/htop for process consuming CPU"),
            "memory_high":    ("Memory leak or insufficient heap — process not releasing memory",
                               "Check for memory leaks; consider rolling restart"),
            "http_error_rate":("Application throwing 5xx — check recent deployment or dependency failure",
                               "Check app logs for stack traces; verify downstream services"),
            "http_latency_p99":("High tail latency — possible slow DB query or resource contention",
                                "Check slow query logs; look for GC pauses or lock contention"),
            "disk_usage":     ("Disk filling up — log accumulation or large file growth",
                               "Run du -sh /* to find large directories; clear old logs"),
            "db_connections": ("DB connection pool exhausted — connection leak or traffic surge",
                               "Check for unclosed connections; review connection pool settings"),
            "pod_restarts":   ("Pod crash-looping — OOMKill, config error, or app crash",
                               "kubectl describe pod; check resource limits and app logs"),
        }
        hint, fix = rules.get(anomaly.metric_id, (
            f"{anomaly.metric_id} exceeded threshold of {anomaly.threshold}",
            "Investigate service logs and recent changes"
        ))
        return {
            "root_cause":        hint,
            "affected_component": anomaly.service,
            "layer":             "unknown",
            "blast_radius":      f"{anomaly.service} service degraded",
            "confidence":        "low",
            "why_now":           "Unknown — check recent deployments or traffic patterns",
            "remediation":       [fix, "Check recent deployments", "Review service logs", "Escalate if not resolved in 15min"],
            "prevention":        "Set up auto-scaling and resource limits",
            "estimated_fix_time":"unknown",
            "related_metrics":   "Check related services for cascading issues",
            "runbook_hint":      f"Check {anomaly.service} runbook in your wiki",
        }


# ════════════════════════════════════════════════════════════
#  EMAIL ALERTER  (HTML + Plain text)
# ════════════════════════════════════════════════════════════
class EmailAlerter:
    SEVERITY_COLOR = {"critical": "#dc2626", "warning": "#d97706", "info": "#2563eb"}
    SEVERITY_BG    = {"critical": "#fef2f2", "warning": "#fffbeb", "info": "#eff6ff"}

    def send(self, anomaly: Anomaly):
        if not all([SMTP_HOST, SMTP_USER, SMTP_PASS, EMAIL_FROM]):
            log.warning("Email not configured — printing alert to console only")
            return

        recipients = anomaly.owner_emails
        if not recipients:
            log.warning("No recipient emails configured")
            return

        subject = f"[{anomaly.severity.upper()}] {anomaly.severity_emoji} Anomaly: {anomaly.service} — {anomaly.metric_desc} | ID: {anomaly.id}"

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = EMAIL_FROM
        msg["To"]      = ", ".join(recipients)

        # Plain text version
        msg.attach(MIMEText(self._plain_text(anomaly), "plain"))
        # HTML version (preferred by email clients)
        msg.attach(MIMEText(self._html(anomaly), "html"))

        try:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
                server.ehlo()
                server.starttls()
                server.login(SMTP_USER, SMTP_PASS)
                server.sendmail(EMAIL_FROM, recipients, msg.as_string())
            log.info(f"📧 Email sent to {recipients} for anomaly {anomaly.id}")
        except smtplib.SMTPAuthenticationError:
            log.error("SMTP auth failed — check SMTP_USER/SMTP_PASS. For Gmail use App Password.")
        except Exception as e:
            log.error(f"Email send failed: {e}")

    def _plain_text(self, anomaly: Anomaly) -> str:
        rca = anomaly.rca
        remediation = "\n".join(f"  {i+1}. {s}" for i, s in enumerate(rca.get("remediation", [])))
        log_snippet = "\n".join(f"  > {l}" for l in anomaly.logs[-10:]) if anomaly.logs else "  (none)"
        return f"""
{'='*65}
{anomaly.severity_emoji} ANOMALY DETECTED — {anomaly.severity.upper()}
{'='*65}

SERVICE      : {anomaly.service}
METRIC       : {anomaly.metric_desc} ({anomaly.metric_id})
VALUE        : {anomaly.value:.4f}   (threshold: {anomaly.threshold})
DETECTED BY  : {anomaly.detected_by}
TIME (UTC)   : {anomaly.timestamp}
ALERT ID     : {anomaly.id}
OWNERS       : {', '.join(anomaly.owner_emails)}

{'─'*65}
📍 ROOT CAUSE
{'─'*65}
{rca.get('root_cause', 'Unknown')}

AFFECTED COMPONENT : {rca.get('affected_component', '?')}
LAYER              : {rca.get('layer', '?')}
BLAST RADIUS       : {rca.get('blast_radius', '?')}
WHY NOW            : {rca.get('why_now', '?')}
CONFIDENCE         : {rca.get('confidence', '?')}
EST. FIX TIME      : {rca.get('estimated_fix_time', '?')}
RELATED METRICS    : {rca.get('related_metrics', '?')}

{'─'*65}
🛠 REMEDIATION STEPS
{'─'*65}
{remediation}

{'─'*65}
🔒 PREVENTION
{'─'*65}
{rca.get('prevention', '—')}

{'─'*65}
📋 RUNBOOK
{'─'*65}
{rca.get('runbook_hint', '—')}

{'─'*65}
🗒 RECENT ERROR LOGS ({anomaly.service})
{'─'*65}
{log_snippet}

{'─'*65}
LINKS
{'─'*65}
Grafana   : {GRAFANA_URL}
Prometheus: {PROMETHEUS_URL}
Loki      : {GRAFANA_URL}/explore
{'='*65}
"""

    def _html(self, anomaly: Anomaly) -> str:
        rca       = anomaly.rca
        color     = self.SEVERITY_COLOR.get(anomaly.severity, "#6b7280")
        bg        = self.SEVERITY_BG.get(anomaly.severity, "#f9fafb")
        remediation_rows = "".join(
            f'<tr><td style="padding:6px 0;color:#374151;vertical-align:top;width:24px;font-weight:600">{i+1}.</td>'
            f'<td style="padding:6px 0 6px 8px;color:#374151;line-height:1.6">{s}</td></tr>'
            for i, s in enumerate(rca.get("remediation", []))
        )
        log_lines = "".join(
            f'<div style="padding:3px 0;color:#9ca3af;font-size:12px;word-break:break-all">{l[:200]}</div>'
            for l in anomaly.logs[-10:]
        ) or '<div style="color:#9ca3af;font-size:12px">No error logs captured</div>'

        return f"""
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f3f4f6">
<table width="100%" cellpadding="0" cellspacing="0" style="padding:24px 0">
<tr><td align="center">
<table width="640" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,0.08)">

  <!-- HEADER BANNER -->
  <tr><td style="background:{color};padding:28px 32px">
    <div style="font-size:13px;color:rgba(255,255,255,0.8);letter-spacing:2px;text-transform:uppercase;margin-bottom:8px">
      AI Anomaly Detection Engine
    </div>
    <div style="font-size:26px;font-weight:700;color:#ffffff">
      {anomaly.severity_emoji}&nbsp; {anomaly.service.upper()} — {anomaly.severity.upper()}
    </div>
    <div style="font-size:14px;color:rgba(255,255,255,0.85);margin-top:6px">
      {anomaly.metric_desc}
    </div>
  </td></tr>

  <!-- METRIC SUMMARY BOXES -->
  <tr><td style="padding:24px 32px 0">
    <table width="100%" cellpadding="0" cellspacing="0">
    <tr>
      <td width="25%" style="text-align:center;padding:16px;background:{bg};border-radius:8px;margin:4px">
        <div style="font-size:24px;font-weight:700;color:{color}">{anomaly.value:.3f}</div>
        <div style="font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:1px;margin-top:4px">Current Value</div>
      </td>
      <td width="4%"></td>
      <td width="25%" style="text-align:center;padding:16px;background:#f9fafb;border-radius:8px">
        <div style="font-size:24px;font-weight:700;color:#6b7280">{anomaly.threshold:.1f}</div>
        <div style="font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:1px;margin-top:4px">Threshold</div>
      </td>
      <td width="4%"></td>
      <td width="42%" style="padding:16px;background:#f9fafb;border-radius:8px">
        <div style="font-size:12px;color:#374151"><b>Alert ID:</b> <code style="background:#e5e7eb;padding:2px 6px;border-radius:4px">{anomaly.id}</code></div>
        <div style="font-size:12px;color:#374151;margin-top:6px"><b>Detected by:</b> {anomaly.detected_by}</div>
        <div style="font-size:12px;color:#374151;margin-top:6px"><b>Time (UTC):</b> {anomaly.timestamp}</div>
      </td>
    </tr>
    </table>
  </td></tr>

  <!-- ROOT CAUSE -->
  <tr><td style="padding:24px 32px 0">
    <div style="font-size:13px;font-weight:700;color:#111827;text-transform:uppercase;letter-spacing:1.5px;margin-bottom:12px">
      📍 Root Cause Analysis  <span style="font-size:11px;background:{bg};color:{color};padding:2px 10px;border-radius:12px;margin-left:8px">Confidence: {rca.get('confidence','?')}</span>
    </div>
    <div style="background:{bg};border-left:4px solid {color};padding:16px 20px;border-radius:0 8px 8px 0;margin-bottom:16px">
      <div style="font-size:15px;color:#111827;font-weight:600;line-height:1.5">{rca.get('root_cause','Unknown')}</div>
    </div>
    <table width="100%" cellpadding="0" cellspacing="0">
    <tr>
      <td width="48%" style="vertical-align:top">
        <div style="font-size:12px;color:#6b7280;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px">Affected Component</div>
        <code style="font-size:12px;color:#111827;background:#f3f4f6;padding:6px 10px;border-radius:6px;display:block;word-break:break-all">{rca.get('affected_component','?')}</code>
      </td>
      <td width="4%"></td>
      <td width="48%" style="vertical-align:top">
        <div style="font-size:12px;color:#6b7280;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px">Layer</div>
        <div style="font-size:14px;color:#111827;background:#f3f4f6;padding:6px 10px;border-radius:6px">{rca.get('layer','?')}</div>
      </td>
    </tr>
    <tr><td colspan="3" height="12"></td></tr>
    <tr>
      <td width="48%" style="vertical-align:top">
        <div style="font-size:12px;color:#6b7280;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px">Blast Radius</div>
        <div style="font-size:13px;color:#374151;background:#f3f4f6;padding:6px 10px;border-radius:6px">{rca.get('blast_radius','?')}</div>
      </td>
      <td width="4%"></td>
      <td width="48%" style="vertical-align:top">
        <div style="font-size:12px;color:#6b7280;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px">Why Now</div>
        <div style="font-size:13px;color:#374151;background:#f3f4f6;padding:6px 10px;border-radius:6px">{rca.get('why_now','?')}</div>
      </td>
    </tr>
    <tr><td colspan="3" height="12"></td></tr>
    <tr>
      <td width="48%">
        <div style="font-size:12px;color:#6b7280;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px">Est. Fix Time</div>
        <div style="font-size:14px;font-weight:600;color:{color};background:{bg};padding:6px 10px;border-radius:6px">{rca.get('estimated_fix_time','?')}</div>
      </td>
      <td width="4%"></td>
      <td width="48%">
        <div style="font-size:12px;color:#6b7280;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px">Also Check</div>
        <div style="font-size:13px;color:#374151;background:#f3f4f6;padding:6px 10px;border-radius:6px">{rca.get('related_metrics','?')}</div>
      </td>
    </tr>
    </table>
  </td></tr>

  <!-- REMEDIATION -->
  <tr><td style="padding:24px 32px 0">
    <div style="font-size:13px;font-weight:700;color:#111827;text-transform:uppercase;letter-spacing:1.5px;margin-bottom:12px">🛠 Remediation Steps</div>
    <table width="100%" cellpadding="0" cellspacing="0" style="background:#f9fafb;border-radius:8px;padding:16px 20px">
      {remediation_rows}
    </table>
  </td></tr>

  <!-- PREVENTION -->
  <tr><td style="padding:20px 32px 0">
    <div style="font-size:13px;font-weight:700;color:#111827;text-transform:uppercase;letter-spacing:1.5px;margin-bottom:10px">🔒 Prevention</div>
    <div style="font-size:13px;color:#374151;background:#f0fdf4;border:1px solid #bbf7d0;padding:14px 18px;border-radius:8px;line-height:1.6">
      {rca.get('prevention','—')}
    </div>
  </td></tr>

  <!-- RUNBOOK -->
  <tr><td style="padding:16px 32px 0">
    <div style="font-size:13px;color:#374151;background:#eff6ff;border:1px solid #bfdbfe;padding:12px 16px;border-radius:8px">
      <b>📋 Runbook:</b> {rca.get('runbook_hint','—')}
    </div>
  </td></tr>

  <!-- RECENT LOGS -->
  <tr><td style="padding:20px 32px 0">
    <div style="font-size:13px;font-weight:700;color:#111827;text-transform:uppercase;letter-spacing:1.5px;margin-bottom:10px">
      🗒 Recent Error Logs ({anomaly.service})
    </div>
    <div style="background:#0f172a;border-radius:8px;padding:16px;font-family:'Courier New',monospace;overflow-x:auto">
      {log_lines}
    </div>
  </td></tr>

  <!-- LINKS -->
  <tr><td style="padding:24px 32px">
    <table cellpadding="0" cellspacing="0">
    <tr>
      <td style="padding-right:12px">
        <a href="{GRAFANA_URL}" style="display:inline-block;background:#f97316;color:#fff;padding:10px 20px;border-radius:8px;text-decoration:none;font-size:13px;font-weight:600">
          📊 Open Grafana
        </a>
      </td>
      <td style="padding-right:12px">
        <a href="{GRAFANA_URL}/explore" style="display:inline-block;background:#0ea5e9;color:#fff;padding:10px 20px;border-radius:8px;text-decoration:none;font-size:13px;font-weight:600">
          🔍 Explore Logs
        </a>
      </td>
      <td>
        <a href="{PROMETHEUS_URL}" style="display:inline-block;background:#6366f1;color:#fff;padding:10px 20px;border-radius:8px;text-decoration:none;font-size:13px;font-weight:600">
          📈 Prometheus
        </a>
      </td>
    </tr>
    </table>
  </td></tr>

  <!-- FOOTER -->
  <tr><td style="background:#f9fafb;padding:16px 32px;border-top:1px solid #e5e7eb">
    <div style="font-size:11px;color:#9ca3af">
      AI Anomaly Engine &nbsp;|&nbsp; Alert ID: <code>{anomaly.id}</code> &nbsp;|&nbsp;
      RCA by Claude AI ({CLAUDE_MODEL}) &nbsp;|&nbsp; {anomaly.timestamp} UTC
    </div>
  </td></tr>

</table>
</td></tr>
</table>
</body>
</html>"""


# ════════════════════════════════════════════════════════════
#  MAIN ENGINE
# ════════════════════════════════════════════════════════════
class AnomalyEngine:
    def __init__(self):
        self.prom    = PrometheusClient(PROMETHEUS_URL, PROM_USER, PROM_PASS)
        self.loki    = LokiClient(LOKI_URL, LOKI_USER, LOKI_PASS)
        self.ml      = MLDetector()
        self.claude  = ClaudeRCAClient(ANTHROPIC_API_KEY)
        self.emailer = EmailAlerter()
        self.cache   = redis.from_url(REDIS_URL, decode_responses=True)
        self.history : dict[str, list[float]] = defaultdict(list)
        self.recent  : list[dict] = []

    def _cooldown_ok(self, key: str, minutes: int = 15) -> bool:
        k = f"cooldown:{key}"
        if self.cache.get(k):
            return False
        self.cache.setex(k, minutes * 60, "1")
        return True

    async def _get_relevant_logs(self, service: str) -> list[str]:
        all_logs = await self.loki.query_logs(service)
        relevant = [l for l in all_logs if any(p.lower() in l.lower() for p in LOG_PATTERNS)]
        return relevant[:30] if relevant else all_logs[:10]

    async def _process(self, anomaly: Anomaly):
        log.info(f"🚨 Processing anomaly: {anomaly.service}/{anomaly.metric_id} "
                 f"val={anomaly.value:.3f} [{anomaly.severity}] detected_by={anomaly.detected_by}")

        anomaly.logs = await self._get_relevant_logs(anomaly.service)
        log.info(f"   Logs fetched: {len(anomaly.logs)} relevant lines")

        log.info(f"   Calling Claude AI for RCA...")
        anomaly.rca = await self.claude.generate_rca(anomaly)

        self.emailer.send(anomaly)
        self._print_console(anomaly)

        self.recent.insert(0, {
            "id": anomaly.id, "service": anomaly.service,
            "metric": anomaly.metric_id, "value": anomaly.value,
            "severity": anomaly.severity, "timestamp": anomaly.timestamp,
            "root_cause": anomaly.rca.get("root_cause", ""),
            "confidence": anomaly.rca.get("confidence", ""),
            "fix_time":   anomaly.rca.get("estimated_fix_time", ""),
        })
        self.recent = self.recent[:50]

    async def run_checks(self) -> int:
        tasks = []
        for metric_id, promql, threshold, severity, service, desc in METRIC_CHECKS:
            value = await self.prom.instant(promql)
            if value is None:
                continue

            hist = self.history[metric_id]
            hist.append(value)
            if len(hist) > 60:
                hist.pop(0)

            static_flag = value > threshold
            ml_flag     = self.ml.isolation_forest(metric_id, hist[:-1], value)
            z_flag      = self.ml.zscore(hist[:-1], value)

            if not (static_flag or ml_flag or z_flag):
                continue

            detected_by = "+".join(filter(None, [
                "static"  if static_flag else "",
                "ml"      if ml_flag     else "",
                "zscore"  if z_flag      else "",
            ]))

            if not self._cooldown_ok(f"{service}:{metric_id}"):
                log.debug(f"Cooldown active: {service}:{metric_id}")
                continue

            tasks.append(self._process(Anomaly(
                id          = str(uuid.uuid4())[:8],
                service     = service,
                metric_id   = metric_id,
                metric_desc = desc,
                value       = value,
                threshold   = threshold,
                severity    = severity,
                timestamp   = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
                detected_by = detected_by,
            )))

        if tasks:
            await asyncio.gather(*tasks)
        return len(tasks)

    async def loop(self):
        log.info("=" * 60)
        log.info("🤖 AI Anomaly Detection Engine — Starting")
        log.info(f"   Prometheus  : {PROMETHEUS_URL}")
        log.info(f"   Loki        : {LOKI_URL}")
        log.info(f"   Grafana     : {GRAFANA_URL}")
        log.info(f"   LLM         : Claude AI ({CLAUDE_MODEL})")
        log.info(f"   Email       : {'✅ ' + SMTP_HOST if SMTP_HOST else '❌ not configured'}")
        log.info(f"   Interval    : {CHECK_INTERVAL}s")
        log.info("=" * 60)

        # Connectivity check on startup
        prom_ok = await self.prom.health_check()
        loki_ok = await self.loki.health_check()
        log.info(f"   Prometheus health: {'✅ reachable' if prom_ok else '❌ UNREACHABLE — check PROMETHEUS_URL and firewall'}")
        log.info(f"   Loki health      : {'✅ reachable' if loki_ok else '❌ UNREACHABLE — check LOKI_URL and firewall'}")

        while True:
            try:
                count = await self.run_checks()
                if count == 0:
                    log.info(f"✅ All metrics normal")
                else:
                    log.info(f"🚨 {count} anomalies processed and emailed")
            except Exception as e:
                log.error(f"Engine error: {e}", exc_info=True)
            await asyncio.sleep(CHECK_INTERVAL)

    def _print_console(self, anomaly: Anomaly):
        rca = anomaly.rca
        steps = "\n  ".join(f"{i+1}. {s}" for i, s in enumerate(rca.get("remediation", [])))
        print(f"""
╔══════════════════════════════════════════════════════════════╗
║  {anomaly.severity_emoji}  ANOMALY  |  {anomaly.service.upper()}  |  {anomaly.severity.upper()}
╠══════════════════════════════════════════════════════════════╣
  Metric      : {anomaly.metric_desc} ({anomaly.metric_id})
  Value       : {anomaly.value:.4f}  (threshold: {anomaly.threshold})
  Detected by : {anomaly.detected_by}
  Time (UTC)  : {anomaly.timestamp}
  Alert ID    : {anomaly.id}
  Emailed to  : {', '.join(anomaly.owner_emails)}

  📍 ROOT CAUSE ({rca.get('confidence','?')} confidence)
     {rca.get('root_cause','Unknown')}

  📦 Component : {rca.get('affected_component','?')}
  🗂  Layer     : {rca.get('layer','?')}
  💥 Impact    : {rca.get('blast_radius','?')}
  ❓ Why now   : {rca.get('why_now','?')}
  ⏱  Fix time  : {rca.get('estimated_fix_time','?')}

  🛠  REMEDIATION
  {steps}

  🔒 PREVENTION
     {rca.get('prevention','—')}
╚══════════════════════════════════════════════════════════════╝
""")


# ════════════════════════════════════════════════════════════
#  FASTAPI  — Webhook + Status API
# ════════════════════════════════════════════════════════════
app    = FastAPI(title="AI Anomaly Detection Engine", version="2.0.0")
engine = AnomalyEngine()

@app.on_event("startup")
async def startup():
    asyncio.create_task(engine.loop())

@app.post("/webhook/grafana")
async def grafana_webhook(request: Request, bg: BackgroundTasks):
    """Receive Grafana alerts → enrich with Claude RCA → email."""
    body   = await request.json()
    alerts = body.get("alerts", [body])
    count  = 0
    for a in alerts:
        if a.get("status") != "firing":
            continue
        labels  = a.get("labels", {})
        service = labels.get("service", labels.get("job", "unknown"))
        anomaly = Anomaly(
            id          = str(uuid.uuid4())[:8],
            service     = service,
            metric_id   = labels.get("alertname", "grafana_alert"),
            metric_desc = a.get("annotations", {}).get("summary", "Grafana Alert"),
            value       = 0.0,
            threshold   = 0.0,
            severity    = labels.get("severity", "warning"),
            timestamp   = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            detected_by = "grafana",
        )
        bg.add_task(engine._process, anomaly)
        count += 1
    return {"status": "processing", "alerts_queued": count}

@app.post("/webhook/alertmanager")
async def alertmanager_webhook(request: Request, bg: BackgroundTasks):
    body = await request.json()
    for a in body.get("alerts", []):
        if a.get("status") != "firing":
            continue
        labels  = a.get("labels", {})
        anomaly = Anomaly(
            id          = str(uuid.uuid4())[:8],
            service     = labels.get("service", labels.get("job", "unknown")),
            metric_id   = labels.get("alertname", "alert"),
            metric_desc = a.get("annotations", {}).get("summary", "Alert"),
            value       = 0.0, threshold = 0.0,
            severity    = labels.get("severity", "warning"),
            timestamp   = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            detected_by = "alertmanager",
        )
        bg.add_task(engine._process, anomaly)
    return {"status": "ok"}

@app.get("/health")
async def health():
    return {
        "status":          "ok",
        "prometheus":      "up" if await engine.prom.health_check() else "down",
        "loki":            "up" if await engine.loki.health_check() else "down",
        "llm":             f"Claude ({CLAUDE_MODEL})",
        "anthropic_key":   "configured" if ANTHROPIC_API_KEY else "MISSING",
        "email":           "configured" if SMTP_HOST else "not configured",
        "recent_anomalies": len(engine.recent),
    }

@app.get("/anomalies")
async def get_anomalies():
    return {"count": len(engine.recent), "anomalies": engine.recent}

@app.get("/metrics_status")
async def metrics_status():
    out = {}
    for metric_id, promql, threshold, severity, service, desc in METRIC_CHECKS:
        val = await engine.prom.instant(promql)
        out[metric_id] = {
            "description": desc, "service": service,
            "value":     round(val, 4) if val is not None else None,
            "threshold": threshold,   "severity": severity,
            "status":    ("🔴 ANOMALY" if val and val > threshold
                          else "⚠️ NO DATA" if val is None else "✅ OK"),
        }
    return out

@app.get("/", response_class=HTMLResponse)
async def ui():
    prom_ok = await engine.prom.health_check()
    loki_ok = await engine.loki.health_check()
    rows = "".join(
        f'<tr><td>{a["timestamp"]}</td><td><b>{a["service"]}</b></td>'
        f'<td>{a["metric"]}</td><td style="color:{"#dc2626" if a["severity"]=="critical" else "#d97706"}">'
        f'{a["severity"].upper()}</td><td style="font-size:12px">{a["root_cause"][:80]}...</td>'
        f'<td><span style="background:#dcfce7;color:#166534;padding:2px 8px;border-radius:10px;font-size:11px">'
        f'{a["confidence"]}</span></td></tr>'
        for a in engine.recent[:10]
    ) or '<tr><td colspan="6" style="text-align:center;color:#9ca3af;padding:20px">No anomalies detected yet</td></tr>'

    return f"""<!DOCTYPE html>
<html><head><title>AI Anomaly Engine</title>
<meta http-equiv="refresh" content="30">
<style>
body{{font-family:-apple-system,sans-serif;background:#f3f4f6;margin:0;padding:20px}}
.hdr{{background:linear-gradient(135deg,#1e1b4b,#312e81);color:#fff;padding:24px 32px;border-radius:12px;margin-bottom:20px}}
h1{{margin:0;font-size:22px}}
.sub{{opacity:.7;font-size:13px;margin-top:4px}}
.cards{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:20px}}
.card{{background:#fff;border-radius:10px;padding:18px;box-shadow:0 1px 4px rgba(0,0,0,.06)}}
.card .label{{font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:1px}}
.card .val{{font-size:20px;font-weight:700;margin-top:6px}}
.up{{color:#16a34a}}.down{{color:#dc2626}}.warn{{color:#d97706}}
.table-wrap{{background:#fff;border-radius:10px;padding:20px;box-shadow:0 1px 4px rgba(0,0,0,.06)}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
th{{text-align:left;padding:10px;background:#f9fafb;font-size:11px;text-transform:uppercase;letter-spacing:1px;color:#6b7280;border-bottom:2px solid #e5e7eb}}
td{{padding:10px;border-bottom:1px solid #f3f4f6;vertical-align:top}}
.links a{{display:inline-block;margin-right:10px;color:#4f46e5;text-decoration:none;font-size:13px}}
</style></head>
<body>
<div class="hdr">
  <h1>🤖 AI Anomaly Detection Engine</h1>
  <div class="sub">Remote: {PROMETHEUS_URL} &nbsp;|&nbsp; Claude AI ({CLAUDE_MODEL}) &nbsp;|&nbsp; Auto-refreshes every 30s</div>
</div>
<div class="cards">
  <div class="card"><div class="label">Prometheus</div><div class="val {'up' if prom_ok else 'down'}">{'✅ Online' if prom_ok else '❌ Offline'}</div></div>
  <div class="card"><div class="label">Loki</div><div class="val {'up' if loki_ok else 'down'}">{'✅ Online' if loki_ok else '❌ Offline'}</div></div>
  <div class="card"><div class="label">Claude AI Key</div><div class="val {'up' if ANTHROPIC_API_KEY else 'down'}">{'✅ Set' if ANTHROPIC_API_KEY else '❌ Missing'}</div></div>
  <div class="card"><div class="label">Anomalies (session)</div><div class="val warn">{len(engine.recent)}</div></div>
</div>
<div class="links" style="margin-bottom:16px">
  <a href="/health">🔍 Health JSON</a>
  <a href="/metrics_status">📊 Metric Status</a>
  <a href="/anomalies">🚨 Anomalies JSON</a>
  <a href="{GRAFANA_URL}" target="_blank">📈 Grafana</a>
</div>
<div class="table-wrap">
  <h3 style="margin:0 0 16px;font-size:15px">Recent Anomalies (last 10)</h3>
  <table><thead><tr><th>Time</th><th>Service</th><th>Metric</th><th>Severity</th><th>Root Cause</th><th>Confidence</th></tr></thead>
  <tbody>{rows}</tbody></table>
</div>
</body></html>"""

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
