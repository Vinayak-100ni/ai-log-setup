#!/usr/bin/env python3
"""
AI Log Anomaly Alerting System
================================
- Fetches logs from Loki (read only, nothing pushed back)
- Drain log clustering (catches unknown patterns)
- Silent container detection (catches dead containers)
- LLM explanation (plain English root cause)
- Telegram alerts
- Custom shell script trigger on anomaly

Dashboard stays pure LogQL in Grafana — this script only handles alerts.

Environment Variables:
    LOKI_URL          - Loki read URL
    LOKI_HOST         - Host label to filter
    LOKI_LOOKBACK     - Lookback in seconds (default: 300)
    LOKI_LIMIT        - Max log lines (default: 5000)
    TELEGRAM_TOKEN    - Telegram bot token
    TELEGRAM_CHAT_ID  - Telegram chat ID
    ANTHROPIC_API_KEY - Claude API key for LLM explanation (optional)
    ON_ANOMALY_SCRIPT - Path to your custom shell script
    STATE_FILE        - File to persist container state between runs
    RUN_INTERVAL      - Seconds between runs (default: 300)
    LOG_LEVEL         - Logging verbosity (default: INFO)
"""

import os
import sys
import time
import json
import logging
import re
import subprocess
import hashlib
from dataclasses import dataclass, field
from collections import defaultdict
from typing import Optional

import requests
import pandas as pd
from sklearn.ensemble import IsolationForest
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("ai-alert")


# ─────────────────────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class Config:
    loki_url: str
    host: str
    lookback: int
    limit: int
    telegram_token: str
    telegram_chat_id: str
    anthropic_api_key: str
    on_anomaly_script: str
    state_file: str
    run_interval: int

    @classmethod
    def from_env(cls) -> "Config":
        return cls(
            loki_url          = os.getenv("LOKI_URL",  "https://loki.edgedock.co.za").rstrip("/"),
            host              = os.getenv("LOKI_HOST", "edge-ai02"),
            lookback          = int(os.getenv("LOKI_LOOKBACK", "300")),
            limit             = int(os.getenv("LOKI_LIMIT",    "5000")),
            telegram_token    = os.getenv("TELEGRAM_TOKEN",    ""),
            telegram_chat_id  = os.getenv("TELEGRAM_CHAT_ID",  ""),
            anthropic_api_key = os.getenv("ANTHROPIC_API_KEY", ""),
            on_anomaly_script = os.getenv("ON_ANOMALY_SCRIPT", "/opt/scripts/on_anomaly.sh"),
            state_file        = os.getenv("STATE_FILE", "/var/lib/ai-alert/state.json"),
            run_interval      = int(os.getenv("RUN_INTERVAL", "300")),
        )


# ─────────────────────────────────────────────────────────────────────────────
# HTTP Session
# ─────────────────────────────────────────────────────────────────────────────
def build_session() -> requests.Session:
    session = requests.Session()
    retry = Retry(total=3, backoff_factor=0.5,
                  status_forcelist=[429, 500, 502, 503, 504],
                  allowed_methods=["GET", "POST"])
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


# ─────────────────────────────────────────────────────────────────────────────
# Loki Client
# ─────────────────────────────────────────────────────────────────────────────
def fetch_logs(config: Config, session: requests.Session) -> pd.DataFrame:
    now = int(time.time())
    params = {
        "query": f'{{host="{config.host}"}}',
        "limit": config.limit,
        "start": str((now - config.lookback) * 1_000_000_000),
        "end":   str(now * 1_000_000_000),
    }
    logger.info("Fetching logs | host=%s lookback=%ds", config.host, config.lookback)
    try:
        r = session.get(
            f"{config.loki_url}/loki/api/v1/query_range",
            params=params, timeout=30
        )
        r.raise_for_status()
    except requests.exceptions.RequestException as e:
        logger.error("Loki fetch failed: %s", e)
        return pd.DataFrame()

    data = r.json()
    if data.get("status") != "success":
        logger.error("Loki error: %s", data)
        return pd.DataFrame()

    records = []
    for stream in data["data"]["result"]:
        labels = stream["stream"]
        for ts, msg in stream["values"]:
            records.append({
                "container": labels.get("container_name", "unknown"),
                "host":      labels.get("host",           "unknown"),
                "source":    labels.get("source",         "unknown"),
                "timestamp_ns": ts,
                "message":   msg.strip(),
            })

    if not records:
        return pd.DataFrame()

    df = pd.DataFrame(records)
    df["timestamp"] = pd.to_datetime(df["timestamp_ns"].astype("int64"), unit="ns")
    df.drop(columns=["timestamp_ns"], inplace=True)
    return df.sort_values("timestamp").reset_index(drop=True)


# ─────────────────────────────────────────────────────────────────────────────
# Drain Log Clustering (lightweight implementation)
# Drain paper: https://jiemingzhu.github.io/pub/pjhe_icws2017.pdf
# Used in production by Microsoft, Uber, LinkedIn
# ─────────────────────────────────────────────────────────────────────────────
class DrainParser:
    """
    Drain algorithm — automatically discovers log templates.
    No rules needed. Groups similar log lines into templates.
    Example:
      "Connection to 1.2.3.4:555 failed" 
      "Connection to 5.6.7.8:556 failed"
      → Template: "Connection to <*>:<*> failed"
    """

    def __init__(self, depth: int = 4, sim_threshold: float = 0.4, max_children: int = 100):
        self.depth         = depth
        self.sim_threshold = sim_threshold
        self.max_children  = max_children
        self.root          = {}
        self.templates     = {}   # template_id → template tokens
        self.template_counts = defaultdict(int)

    def _tokenize(self, message: str) -> list:
        # Replace IPs, numbers, hex, paths with wildcards before tokenizing
        message = re.sub(r'\d{1,3}(?:\.\d{1,3}){3}(:\d+)?', '<IP>', message)
        message = re.sub(r'0x[0-9a-fA-F]+', '<HEX>', message)
        message = re.sub(r'\b\d+\b', '<NUM>', message)
        message = re.sub(r'["\'`].*?["\'`]', '<STR>', message)
        return message.split()

    def _seq_dist(self, seq1: list, seq2: list) -> float:
        if len(seq1) != len(seq2):
            return 0.0
        matches = sum(1 for a, b in zip(seq1, seq2) if a == b or a == "<*>" or b == "<*>")
        return matches / len(seq1)

    def _merge_template(self, seq1: list, seq2: list) -> list:
        return [a if a == b else "<*>" for a, b in zip(seq1, seq2)]

    def _template_id(self, tokens: list) -> str:
        return hashlib.md5(" ".join(tokens).encode()).hexdigest()[:8]

    def parse(self, message: str) -> tuple:
        tokens = self._tokenize(message)
        if not tokens:
            return "empty", ["<empty>"]

        length_key = len(tokens)
        first_token = tokens[0] if tokens[0] != "<NUM>" else "<NUM>"

        # Navigate tree
        if length_key not in self.root:
            self.root[length_key] = {}
        length_node = self.root[length_key]

        if first_token not in length_node:
            length_node[first_token] = []
        candidates = length_node[first_token]

        # Find best matching template
        best_sim   = -1
        best_tmpl  = None
        best_idx   = -1
        for idx, tmpl_tokens in enumerate(candidates):
            sim = self._seq_dist(tokens, tmpl_tokens)
            if sim > best_sim:
                best_sim  = sim
                best_tmpl = tmpl_tokens
                best_idx  = idx

        if best_sim >= self.sim_threshold and best_tmpl is not None:
            # Merge into existing template
            merged = self._merge_template(tokens, best_tmpl)
            candidates[best_idx] = merged
            tmpl_id = self._template_id(merged)
            self.templates[tmpl_id] = merged
        else:
            # New template
            if len(candidates) < self.max_children:
                candidates.append(tokens)
            tmpl_id = self._template_id(tokens)
            self.templates[tmpl_id] = tokens

        self.template_counts[tmpl_id] += 1
        return tmpl_id, self.templates[tmpl_id]


# ─────────────────────────────────────────────────────────────────────────────
# State Management (persist between runs)
# ─────────────────────────────────────────────────────────────────────────────
def load_state(state_file: str) -> dict:
    try:
        with open(state_file) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {
            "known_templates":    {},   # template_id → avg count per run
            "known_containers":   [],   # containers seen in last run
            "alerted_templates":  {},   # template_id → last alert time
            "last_run":           0,
        }


def save_state(state: dict, state_file: str) -> None:
    os.makedirs(os.path.dirname(state_file), exist_ok=True)
    with open(state_file, "w") as f:
        json.dump(state, f, indent=2)


# ─────────────────────────────────────────────────────────────────────────────
# Silent Container Detection
# ─────────────────────────────────────────────────────────────────────────────
def detect_silent_containers(
    df: pd.DataFrame,
    state: dict,
    config: Config,
) -> list:
    """
    Detect containers that were active before but sent zero logs this run.
    This catches silent failures that no log query can find.
    """
    alerts = []
    current_containers = set(df["container"].unique()) if not df.empty else set()
    known_containers   = set(state.get("known_containers", []))

    # Containers that disappeared since last run
    silent = known_containers - current_containers
    for container in silent:
        alert = {
            "type":      "silent_container",
            "container": container,
            "host":      config.host,
            "message":   f"Container '{container}' has stopped sending logs. "
                         f"It was active in the previous run but sent 0 logs "
                         f"in the last {config.lookback // 60} minutes. "
                         f"Container may have crashed or stopped.",
            "severity":  "CRITICAL",
        }
        alerts.append(alert)
        logger.warning("Silent container detected: %s", container)

    # Update known containers
    state["known_containers"] = list(current_containers)
    return alerts


# ─────────────────────────────────────────────────────────────────────────────
# Drain-Based Anomaly Detection
# ─────────────────────────────────────────────────────────────────────────────
def detect_drain_anomalies(
    df: pd.DataFrame,
    state: dict,
    config: Config,
) -> list:
    """
    Use Drain to cluster logs into templates.
    Alert on:
      1. Brand new templates never seen before
      2. Known templates with sudden spike (3x normal rate)
      3. Templates with critical keywords
    """
    if df.empty:
        return []

    parser = DrainParser()
    alerts = []
    known_templates  = state.get("known_templates", {})
    alerted_templates = state.get("alerted_templates", {})
    now = time.time()

    # Parse all log lines
    df = df.copy()
    df["template_id"]  = ""
    df["template_str"] = ""

    for idx, row in df.iterrows():
        tmpl_id, tmpl_tokens = parser.parse(row["message"])
        df.at[idx, "template_id"]  = tmpl_id
        df.at[idx, "template_str"] = " ".join(tmpl_tokens)

    # Analyse each template
    for tmpl_id, count in parser.template_counts.items():
        tmpl_str   = " ".join(parser.templates.get(tmpl_id, []))
        containers = df[df["template_id"] == tmpl_id]["container"].unique().tolist()
        sample_msg = df[df["template_id"] == tmpl_id]["message"].iloc[0]

        # Cooldown — don't re-alert same template within 30 min
        last_alert = alerted_templates.get(tmpl_id, 0)
        if now - last_alert < 1800:
            continue

        # ── Check 1: Brand new template ──────────────────────────────────────
        if tmpl_id not in known_templates:
            # Only alert if it appears more than 3 times (filter noise)
            if count >= 3:
                alerts.append({
                    "type":       "new_template",
                    "template":   tmpl_str,
                    "template_id": tmpl_id,
                    "containers": containers,
                    "count":      count,
                    "sample":     sample_msg,
                    "severity":   "WARNING",
                    "message":    f"New log pattern never seen before appeared {count}x",
                })
                alerted_templates[tmpl_id] = now

        # ── Check 2: Known template with spike ───────────────────────────────
        else:
            avg_count = known_templates[tmpl_id].get("avg_count", count)
            if count > avg_count * 3 and count > 10:
                alerts.append({
                    "type":       "spike",
                    "template":   tmpl_str,
                    "template_id": tmpl_id,
                    "containers": containers,
                    "count":      count,
                    "avg_count":  int(avg_count),
                    "sample":     sample_msg,
                    "severity":   "ERROR",
                    "message":    f"Log pattern spiked to {count}x (normal: ~{int(avg_count)}x)",
                })
                alerted_templates[tmpl_id] = now

        # ── Update known templates (rolling average) ──────────────────────────
        if tmpl_id not in known_templates:
            known_templates[tmpl_id] = {"avg_count": count, "template": tmpl_str}
        else:
            # Exponential moving average
            old_avg = known_templates[tmpl_id]["avg_count"]
            known_templates[tmpl_id]["avg_count"] = old_avg * 0.8 + count * 0.2

    state["known_templates"]   = known_templates
    state["alerted_templates"] = alerted_templates
    return alerts


# ─────────────────────────────────────────────────────────────────────────────
# LLM Explanation (Claude API)
# ─────────────────────────────────────────────────────────────────────────────
def get_llm_explanation(alerts: list, config: Config, session: requests.Session) -> str:
    """
    Send anomalies to Claude API for plain English explanation and recommendations.
    Falls back gracefully if API key not set.
    """
    if not config.anthropic_api_key or not alerts:
        return ""

    # Build context for LLM
    alert_text = ""
    for a in alerts:
        alert_text += f"\n- Type: {a['type']}"
        alert_text += f"\n  Containers: {', '.join(a.get('containers', [a.get('container','unknown')]))}"
        alert_text += f"\n  Severity: {a['severity']}"
        alert_text += f"\n  Message: {a['message']}"
        alert_text += f"\n  Sample log: {a.get('sample', a.get('message',''))[:200]}"
        alert_text += "\n"

    prompt = f"""You are a DevOps engineer analyzing Docker container log anomalies.

System: edge-ai02 running AI/computer-vision Docker containers.

Anomalies detected in the last 5 minutes:
{alert_text}

Provide a concise analysis in this exact format:
1. ROOT CAUSE: (1-2 sentences on what is actually wrong)
2. IMPACT: (which containers/services are affected and how)
3. ACTION: (exact steps to fix it, be specific)

Be direct and technical. Max 150 words total."""

    try:
        r = session.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key":         config.anthropic_api_key,
                "anthropic-version": "2023-06-01",
                "content-type":      "application/json",
            },
            json={
                "model":      "claude-haiku-4-5-20251001",
                "max_tokens": 300,
                "messages":   [{"role": "user", "content": prompt}],
            },
            timeout=30,
        )
        r.raise_for_status()
        return r.json()["content"][0]["text"].strip()
    except Exception as e:
        logger.error("LLM explanation failed: %s", e)
        return ""


# ─────────────────────────────────────────────────────────────────────────────
# Telegram Alert
# ─────────────────────────────────────────────────────────────────────────────
def send_telegram(message: str, config: Config, session: requests.Session) -> bool:
    if not config.telegram_token or not config.telegram_chat_id:
        logger.warning("Telegram not configured — skipping alert")
        return False

    url = f"https://api.telegram.org/bot{config.telegram_token}/sendMessage"
    payload = {
        "chat_id":    config.telegram_chat_id,
        "text":       message,
        "parse_mode": "HTML",
    }
    try:
        r = session.post(url, json=payload, timeout=10)
        r.raise_for_status()
        logger.info("Telegram alert sent")
        return True
    except Exception as e:
        logger.error("Telegram alert failed: %s", e)
        return False


def build_telegram_message(alerts: list, llm_explanation: str, config: Config) -> str:
    severity_icons = {
        "CRITICAL": "🔴",
        "ERROR":    "🟠",
        "WARNING":  "🟡",
        "INFO":     "🟢",
    }

    lines = [
        f"🚨 <b>AI Alert — {config.host}</b>",
        f"🕐 {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')} UTC",
        "",
    ]

    for alert in alerts:
        icon = severity_icons.get(alert["severity"], "⚪")
        lines.append(f"{icon} <b>{alert['severity']} — {alert['type'].replace('_',' ').title()}</b>")

        if alert["type"] == "silent_container":
            lines.append(f"📦 Container: <code>{alert['container']}</code>")
            lines.append(f"💀 No logs received in last {config.lookback // 60} min")

        elif alert["type"] == "new_template":
            containers = ", ".join(alert.get("containers", []))
            lines.append(f"📦 Containers: <code>{containers}</code>")
            lines.append(f"🆕 New pattern ({alert['count']}x):")
            lines.append(f"<code>{alert['template'][:120]}</code>")
            lines.append(f"📝 Sample: <i>{alert['sample'][:150]}</i>")

        elif alert["type"] == "spike":
            containers = ", ".join(alert.get("containers", []))
            lines.append(f"📦 Containers: <code>{containers}</code>")
            lines.append(f"📈 Spike: {alert['count']}x (normal: ~{alert['avg_count']}x)")
            lines.append(f"<code>{alert['template'][:120]}</code>")

        lines.append("")

    if llm_explanation:
        lines.append("🤖 <b>AI Analysis:</b>")
        lines.append(llm_explanation)
        lines.append("")

    lines.append(f"📊 Dashboard: your Grafana URL")
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# Shell Script Trigger
# ─────────────────────────────────────────────────────────────────────────────
def run_custom_script(alerts: list, config: Config) -> None:
    """
    Run your custom shell script for each anomaly detected.
    Script receives: container severity issue_type message
    """
    if not config.on_anomaly_script:
        return

    if not os.path.isfile(config.on_anomaly_script):
        logger.warning("Script not found: %s", config.on_anomaly_script)
        return

    if not os.access(config.on_anomaly_script, os.X_OK):
        logger.warning("Script not executable: %s — run: chmod +x %s",
                       config.on_anomaly_script, config.on_anomaly_script)
        return

    for alert in alerts:
        container  = alert.get("container", ",".join(alert.get("containers", ["unknown"])))
        severity   = alert.get("severity",  "UNKNOWN")
        issue_type = alert.get("type",      "unknown")
        message    = alert.get("sample",    alert.get("message", ""))[:200]

        cmd = [
            config.on_anomaly_script,
            container,
            severity,
            issue_type,
            message,
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
            )
            if result.returncode == 0:
                logger.info("Script ran OK for container=%s | output: %s",
                            container, result.stdout.strip()[:200])
            else:
                logger.error("Script failed for container=%s | stderr: %s",
                             container, result.stderr.strip()[:200])
        except subprocess.TimeoutExpired:
            logger.error("Script timed out for container=%s", container)
        except Exception as e:
            logger.error("Script error: %s", e)


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────
def main() -> None:
    config  = Config.from_env()
    session = build_session()
    state   = load_state(config.state_file)

    # ── Fetch logs ────────────────────────────────────────────────────────────
    df = fetch_logs(config, session)
    if df.empty:
        logger.warning("No logs found for host=%s", config.host)
        # Still check for silent containers even if no logs returned
        silent_alerts = detect_silent_containers(df, state, config)
        if silent_alerts:
            msg = build_telegram_message(silent_alerts, "", config)
            send_telegram(msg, config, session)
            run_custom_script(silent_alerts, config)
        save_state(state, config.state_file)
        return

    logger.info("Fetched %d log lines from %d containers",
                len(df), df["container"].nunique())

    # ── Detect anomalies ──────────────────────────────────────────────────────
    all_alerts = []

    # 1. Silent containers (nothing to do with log content)
    silent_alerts = detect_silent_containers(df, state, config)
    all_alerts.extend(silent_alerts)

    # 2. Drain clustering (new patterns + spikes)
    drain_alerts = detect_drain_anomalies(df, state, config)
    all_alerts.extend(drain_alerts)

    logger.info("Alerts this run: %d (silent=%d drain=%d)",
                len(all_alerts), len(silent_alerts), len(drain_alerts))

    # ── Print report ──────────────────────────────────────────────────────────
    if all_alerts:
        print(f"\n{'='*70}")
        print(f"  ANOMALY ALERTS | host={config.host} | count={len(all_alerts)}")
        print(f"{'='*70}")
        for a in all_alerts:
            print(f"  [{a['severity']}] {a['type']} — {a['message'][:100]}")
        print()

        # ── LLM explanation ───────────────────────────────────────────────────
        llm_explanation = get_llm_explanation(all_alerts, config, session)
        if llm_explanation:
            print(f"  AI ANALYSIS:\n{llm_explanation}\n")

        # ── Telegram alert ────────────────────────────────────────────────────
        telegram_msg = build_telegram_message(all_alerts, llm_explanation, config)
        send_telegram(telegram_msg, config, session)

        # ── Run custom script ─────────────────────────────────────────────────
        run_custom_script(all_alerts, config)

    else:
        logger.info("No anomalies detected this run.")

    # ── Save state for next run ───────────────────────────────────────────────
    state["last_run"] = int(time.time())
    save_state(state, config.state_file)


# ─────────────────────────────────────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    interval = int(os.getenv("RUN_INTERVAL", "300"))
    logger.info("AI Alert System starting — interval=%ds", interval)

    # First run immediately
    try:
        main()
    except Exception as e:
        logger.error("Run failed: %s", e)

    # Then loop
    while True:
        logger.info("Sleeping %ds until next run...", interval)
        time.sleep(interval)
        try:
            main()
        except Exception as e:
            logger.error("Run failed: %s", e)
