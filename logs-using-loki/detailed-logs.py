#!/usr/bin/env python3
"""
Loki Anomaly Detector — Advanced Edition
-----------------------------------------
Fetches Docker container logs from Loki, detects anomalies using
Isolation Forest with rich feature engineering, and produces a
detailed report grouped by container, error type, and severity.

Environment Variables:
    LOKI_URL         - Loki base URL (default: https://loki.edgedock.co.za)
    LOKI_HOST        - Host label to filter (default: edge-ai02)
    LOKI_LOOKBACK    - Lookback window in seconds (default: 3600)
    LOKI_LIMIT       - Max log lines to fetch (default: 5000)
    ANOMALY_RATE     - IsolationForest contamination rate (default: 0.05)
    OUTPUT_CSV       - Optional path to export full results CSV
    LOG_LEVEL        - Logging verbosity (default: INFO)
"""

import os
import sys
import time
import logging
import re
from collections import defaultdict
from dataclasses import dataclass

import requests
import pandas as pd
from sklearn.ensemble import IsolationForest
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ─────────────────────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("loki-detector")


# ─────────────────────────────────────────────────────────────────────────────
# Error Pattern Definitions
# ─────────────────────────────────────────────────────────────────────────────
PATTERNS = {
    "is_exception":       r"exception|traceback|Exception in thread",
    "is_error":           r"\berror\b|\bERROR\b",
    "is_critical":        r"critical|CRITICAL|fatal|FATAL|panic|PANIC",
    "is_warning":         r"\bwarn(ing)?\b|\bWARN(ING)?\b",
    "is_connection_fail": r"(connection|connect).{0,30}(failed|refused|timeout|timed out|no route)",
    "is_no_route":        r"no route to host|Network is unreachable",
    "is_timeout":         r"timeout|timed out|deadline exceeded",
    "is_oom":             r"out of memory|OOMKilled|MemoryError|cannot allocate",
    "is_segfault":        r"segmentation fault|Segfault|signal 11",
    "is_permission":      r"permission denied|Access Denied|EACCES",
    "is_disk":            r"no space left|disk full|I/O error|input/output error",
    "is_http_error":      r"HTTP [45]\d{2}|status.?code.?[45]\d{2}",
    "is_restart":         r"restarting|container.*restart|restart.*container",
    "is_stacktrace":      r'File ".*\.py", line \d+',
    "is_tcp_error":       r"\[tcp @|tcp://.*(failed|error|refused)",
}


def classify_severity(row) -> str:
    if row["is_critical"]:
        return "CRITICAL"
    if row["is_exception"] or row["is_oom"] or row["is_segfault"]:
        return "EXCEPTION"
    if row["is_error"] or row["is_connection_fail"] or row["is_no_route"]:
        return "ERROR"
    if row["is_timeout"] or row["is_http_error"] or row["is_stacktrace"] or row["is_tcp_error"]:
        return "WARNING"
    if row["is_warning"]:
        return "WARNING"
    return "INFO"


# ─────────────────────────────────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class Config:
    loki_url: str
    host: str
    lookback_seconds: int
    limit: int
    anomaly_rate: float
    output_csv: str

    @classmethod
    def from_env(cls) -> "Config":
        loki_url = os.getenv("LOKI_URL", "https://loki.edgedock.co.za")
        return cls(
            loki_url=loki_url.rstrip("/"),
            host=os.getenv("LOKI_HOST", "edge-ai02"),
            lookback_seconds=int(os.getenv("LOKI_LOOKBACK", "3600")),
            limit=int(os.getenv("LOKI_LIMIT", "5000")),
            anomaly_rate=float(os.getenv("ANOMALY_RATE", "0.05")),
            output_csv=os.getenv("OUTPUT_CSV", ""),
        )


# ─────────────────────────────────────────────────────────────────────────────
# HTTP Session
# ─────────────────────────────────────────────────────────────────────────────
def build_session() -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


# ─────────────────────────────────────────────────────────────────────────────
# Loki Client
# ─────────────────────────────────────────────────────────────────────────────
class LokiClient:
    def __init__(self, config: Config, session: requests.Session):
        self.config = config
        self.session = session
        self.query_url = f"{config.loki_url}/loki/api/v1/query_range"

    def fetch_logs(self) -> list:
        now = int(time.time())
        params = {
            "query": f'{{host="{self.config.host}"}}',
            "limit": self.config.limit,
            "start": str((now - self.config.lookback_seconds) * 1_000_000_000),
            "end": str(now * 1_000_000_000),
        }
        logger.info("Fetching logs | host=%s lookback=%ds limit=%d",
                    self.config.host, self.config.lookback_seconds, self.config.limit)
        try:
            r = self.session.get(self.query_url, params=params, timeout=30)
            r.raise_for_status()
        except requests.exceptions.HTTPError as e:
            logger.error("HTTP error: %s | body: %s", e, r.text[:300])
            sys.exit(1)
        except requests.exceptions.ConnectionError as e:
            logger.error("Connection error: %s", e)
            sys.exit(1)
        except requests.exceptions.Timeout:
            logger.error("Request timed out.")
            sys.exit(1)

        data = r.json()
        if data.get("status") != "success":
            logger.error("Loki error: %s", data)
            sys.exit(1)

        streams = data["data"]["result"]
        logger.info("Got %d streams from Loki.", len(streams))
        return streams

    def parse_streams(self, streams: list) -> pd.DataFrame:
        records = []
        for stream in streams:
            labels = stream["stream"]
            container   = labels.get("container_name", "unknown")
            host        = labels.get("host", "unknown")
            source      = labels.get("source", "unknown")
            compose_svc = labels.get("compose_service", "unknown")
            for ts, message in stream["values"]:
                records.append({
                    "container":       container,
                    "host":            host,
                    "source":          source,
                    "compose_service": compose_svc,
                    "timestamp_ns":    ts,
                    "message":         message.strip(),
                })

        if not records:
            return pd.DataFrame()

        df = pd.DataFrame(records)
        df["timestamp"] = pd.to_datetime(df["timestamp_ns"].astype("int64"), unit="ns")
        df.drop(columns=["timestamp_ns"], inplace=True)
        df.sort_values("timestamp", inplace=True)
        df.reset_index(drop=True, inplace=True)
        return df


# ─────────────────────────────────────────────────────────────────────────────
# Feature Engineering
# ─────────────────────────────────────────────────────────────────────────────
def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()

    # Basic
    df["message_length"] = df["message"].str.len()

    # Pattern flags
    for name, pattern in PATTERNS.items():
        df[name] = df["message"].str.contains(pattern, case=False, regex=True).astype(int)

    # Severity
    df["severity"] = df.apply(classify_severity, axis=1)
    severity_map = {"CRITICAL": 5, "EXCEPTION": 4, "ERROR": 3, "WARNING": 2, "INFO": 1}
    df["severity_score"] = df["severity"].map(severity_map)

    # Burst detection: logs per container per 10s window
    df["time_bucket"] = df["timestamp"].dt.floor("10s")
    burst = df.groupby(["container", "time_bucket"]).size().reset_index(name="burst_count")
    df = df.merge(burst, on=["container", "time_bucket"], how="left")

    # Repeated message count per container
    df["msg_repeat_count"] = df.groupby(["container", "message"])["message"].transform("count")

    return df


# ─────────────────────────────────────────────────────────────────────────────
# Anomaly Detection
# ─────────────────────────────────────────────────────────────────────────────
FEATURE_COLS = [
    "message_length",
    "severity_score",
    "burst_count",
    "msg_repeat_count",
    "is_exception",
    "is_connection_fail",
    "is_no_route",
    "is_timeout",
    "is_stacktrace",
    "is_tcp_error",
    "is_oom",
]

def detect_anomalies(df: pd.DataFrame, contamination: float) -> pd.DataFrame:
    model = IsolationForest(contamination=contamination, random_state=42, n_jobs=-1)
    df = df.copy()
    df["anomaly_score"] = model.fit_predict(df[FEATURE_COLS])
    df["is_anomaly"] = df["anomaly_score"] == -1
    return df


# ─────────────────────────────────────────────────────────────────────────────
# Report
# ─────────────────────────────────────────────────────────────────────────────
SEP  = "=" * 80
SEP2 = "-" * 80

def print_report(df: pd.DataFrame) -> None:
    anomalies     = df[df["is_anomaly"]]
    total         = len(df)
    anomaly_count = len(anomalies)
    normal_count  = total - anomaly_count

    # ── Header ───────────────────────────────────────────────────────────────
    print(f"\n{SEP}")
    print("  LOKI ANOMALY DETECTION REPORT")
    print(SEP)
    print(f"  Host          : {df['host'].iloc[0]}")
    print(f"  Time Range    : {df['timestamp'].min()}  ->  {df['timestamp'].max()}")
    print(f"  Total Logs    : {total}")
    print(f"  Containers    : {df['container'].nunique()}")
    print(f"  Normal        : {normal_count}")
    print(f"  Anomalies     : {anomaly_count}")
    print(SEP)

    if anomaly_count == 0:
        print("\n  No anomalies detected.\n")
        return

    # ── Severity Breakdown ───────────────────────────────────────────────────
    print("\n  SEVERITY BREAKDOWN (all logs)")
    print(SEP2)
    sev_counts = df["severity"].value_counts()
    icons = {"CRITICAL": "[CRIT]", "EXCEPTION": "[EXCP]", "ERROR": "[ERR] ",
             "WARNING": "[WARN]", "INFO": "[INFO]"}
    for sev in ["CRITICAL", "EXCEPTION", "ERROR", "WARNING", "INFO"]:
        count = sev_counts.get(sev, 0)
        bar   = "#" * min(count, 50)
        print(f"  {icons.get(sev, '')} {sev:<12} {count:>6}  {bar}")

    # ── Anomalies per Container ──────────────────────────────────────────────
    print(f"\n  ANOMALIES PER CONTAINER")
    print(SEP2)
    container_summary = (
        anomalies.groupby("container")
        .agg(
            anomaly_count=("is_anomaly", "sum"),
            severities=("severity", lambda x: ", ".join(sorted(x.unique()))),
            sample=("message", lambda x: x.iloc[0][:80]),
        )
        .sort_values("anomaly_count", ascending=False)
        .reset_index()
    )
    for _, row in container_summary.iterrows():
        print(f"\n  Container : {row['container']}")
        print(f"  Anomalies : {int(row['anomaly_count'])}")
        print(f"  Severities: {row['severities']}")
        print(f"  Sample    : {row['sample']}")

    # ── Pattern Hits ─────────────────────────────────────────────────────────
    print(f"\n\n  DETECTED ISSUE PATTERNS (anomalous logs only)")
    print(SEP2)
    pattern_cols = [c for c in PATTERNS.keys() if c in anomalies.columns]
    pattern_hits = {col: anomalies[col].sum() for col in pattern_cols if anomalies[col].sum() > 0}
    pattern_hits = dict(sorted(pattern_hits.items(), key=lambda x: -x[1]))
    for pattern, count in pattern_hits.items():
        label = pattern.replace("is_", "").replace("_", " ").upper()
        bar   = "#" * min(count, 40)
        print(f"  {label:<22} {count:>6}  {bar}")

    # ── Detailed Anomaly Lines ───────────────────────────────────────────────
    print(f"\n\n  DETAILED ANOMALY LOG LINES")
    print(SEP2)
    for container, group in anomalies.groupby("container"):
        print(f"\n  +-- Container: {container} ({len(group)} anomalies)")
        for _, row in group.iterrows():
            sev_label = f"[{row['severity'][:4]}]"
            ts  = str(row["timestamp"])[:19]
            src = row["source"]
            msg = row["message"][:120]
            print(f"  |   {sev_label} [{ts}] [{src}] {msg}")
        print(f"  +{'-' * 70}")

    # ── Top Repeated Errors ──────────────────────────────────────────────────
    print(f"\n\n  TOP REPEATED ERROR MESSAGES")
    print(SEP2)
    error_logs = df[df["severity"].isin(["ERROR", "EXCEPTION", "CRITICAL"])]
    if not error_logs.empty:
        top_repeated = (
            error_logs.groupby(["container", "message"])
            .size()
            .reset_index(name="count")
            .sort_values("count", ascending=False)
            .head(10)
        )
        for _, row in top_repeated.iterrows():
            print(f"\n  Count     : {row['count']}")
            print(f"  Container : {row['container']}")
            print(f"  Message   : {row['message'][:120]}")

    # ── Network Failures ─────────────────────────────────────────────────────
    network_errors = df[
        (df["is_connection_fail"] == 1) |
        (df["is_no_route"] == 1) |
        (df["is_tcp_error"] == 1)
    ]
    if not network_errors.empty:
        print(f"\n\n  NETWORK FAILURES")
        print(SEP2)
        net_summary = (
            network_errors.groupby("container")
            .size()
            .reset_index(name="count")
            .sort_values("count", ascending=False)
        )
        for _, row in net_summary.iterrows():
            print(f"  {row['container']:<50} {row['count']} failures")

        ip_pattern = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+)")
        all_ips = defaultdict(int)
        for msg in network_errors["message"]:
            for ip in ip_pattern.findall(msg):
                all_ips[ip] += 1
        if all_ips:
            print(f"\n  Failing endpoints:")
            for ip, count in sorted(all_ips.items(), key=lambda x: -x[1])[:10]:
                print(f"    {ip:<35} {count} failures")

    # ── Exception Summary ────────────────────────────────────────────────────
    exceptions = df[df["is_exception"] == 1]
    if not exceptions.empty:
        print(f"\n\n  EXCEPTION / TRACEBACK SUMMARY")
        print(SEP2)
        exc_summary = (
            exceptions.groupby("container")
            .size()
            .reset_index(name="count")
            .sort_values("count", ascending=False)
        )
        for _, row in exc_summary.iterrows():
            print(f"  {row['container']:<50} {row['count']} exceptions")

        exc_type_pattern = re.compile(r"([A-Z][a-zA-Z]+Error|[A-Z][a-zA-Z]+Exception)")
        exc_types = defaultdict(int)
        for msg in exceptions["message"]:
            for exc_type in exc_type_pattern.findall(msg):
                exc_types[exc_type] += 1
        if exc_types:
            print(f"\n  Exception types found:")
            for exc_type, count in sorted(exc_types.items(), key=lambda x: -x[1]):
                print(f"    {exc_type:<45} {count}x")

    # ── Burst Activity ───────────────────────────────────────────────────────
    print(f"\n\n  HIGH BURST ACTIVITY (>50 logs in a 10s window)")
    print(SEP2)
    burst = (
        df[df["burst_count"] > 50][["container", "time_bucket", "burst_count"]]
        .drop_duplicates()
        .sort_values("burst_count", ascending=False)
        .head(10)
    )
    if not burst.empty:
        for _, row in burst.iterrows():
            print(f"  {row['container']:<50} {row['burst_count']} logs at {row['time_bucket']}")
    else:
        print("  No burst activity detected.")

    print(f"\n{SEP}\n")


# ─────────────────────────────────────────────────────────────────────────────
# Export
# ─────────────────────────────────────────────────────────────────────────────
def export_results(df: pd.DataFrame, output_path: str) -> None:
    if output_path:
        df.to_csv(output_path, index=False)
        logger.info("Results exported to %s", output_path)


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────
def main() -> None:
    config  = Config.from_env()
    session = build_session()
    client  = LokiClient(config, session)

    streams = client.fetch_logs()
    df      = client.parse_streams(streams)

    if df.empty:
        logger.warning("No logs returned for host=%s.", config.host)
        sys.exit(0)

    logger.info("Parsed %d log lines from %d containers.", len(df), df["container"].nunique())

    df = engineer_features(df)
    df = detect_anomalies(df, contamination=config.anomaly_rate)

    print_report(df)
    export_results(df, config.output_csv)


if __name__ == "__main__":
    main()
