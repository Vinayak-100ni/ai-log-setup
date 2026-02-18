#!/usr/bin/env python3
"""
Loki Anomaly Detector
---------------------
Fetches Docker container logs from Loki for a specific host
and uses Isolation Forest to detect anomalies.

Usage:
    python loki_anomaly_detector.py

Environment Variables:
    LOKI_URL        - Loki base URL (required)
    LOKI_HOST       - Host label to filter logs (default: edge-ai02)
    LOKI_LOOKBACK   - Lookback window in seconds (default: 3600)
    LOKI_LIMIT      - Max log lines to fetch (default: 1000)
    ANOMALY_RATE    - Contamination rate for IsolationForest (default: 0.05)
    LOG_LEVEL       - Logging verbosity (default: INFO)
"""

import os
import sys
import time
import logging
from dataclasses import dataclass
from typing import Optional

import requests
import pandas as pd
from sklearn.ensemble import IsolationForest
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ---------------------------------------------------------------------------
# Logging Setup
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("loki-anomaly-detector")


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
@dataclass
class Config:
    loki_url: str
    host: str
    lookback_seconds: int
    limit: int
    anomaly_rate: float

    @classmethod
    def from_env(cls) -> "Config":
        loki_url = os.getenv("LOKI_URL", "https://loki.edgedock.co.za")
        if not loki_url:
            logger.error("LOKI_URL environment variable is required.")
            sys.exit(1)
        return cls(
            loki_url=loki_url.rstrip("/"),
            host=os.getenv("LOKI_HOST", "edge-ai02"),
            lookback_seconds=int(os.getenv("LOKI_LOOKBACK", "3600")),
            limit=int(os.getenv("LOKI_LIMIT", "1000")),
            anomaly_rate=float(os.getenv("ANOMALY_RATE", "0.05")),
        )


# ---------------------------------------------------------------------------
# HTTP Client with retries
# ---------------------------------------------------------------------------
def build_http_session(
    retries: int = 3,
    backoff_factor: float = 0.5,
    timeout: int = 30,
) -> requests.Session:
    session = requests.Session()
    retry_strategy = Retry(
        total=retries,
        backoff_factor=backoff_factor,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"],
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.request = lambda method, url, **kwargs: requests.Session.request(
        session, method, url, timeout=timeout, **kwargs
    )
    return session


# ---------------------------------------------------------------------------
# Loki Client
# ---------------------------------------------------------------------------
class LokiClient:
    def __init__(self, config: Config, session: requests.Session):
        self.config = config
        self.session = session
        self.query_url = f"{config.loki_url}/loki/api/v1/query_range"

    def fetch_logs(self) -> list[dict]:
        now = int(time.time())
        params = {
            "query": f'{{host="{self.config.host}"}}',
            "limit": self.config.limit,
            "start": str((now - self.config.lookback_seconds) * 1_000_000_000),
            "end": str(now * 1_000_000_000),
        }

        logger.info(
            "Fetching logs from Loki | host=%s lookback=%ds limit=%d",
            self.config.host,
            self.config.lookback_seconds,
            self.config.limit,
        )

        try:
            response = self.session.get(self.query_url, params=params)
            response.raise_for_status()
        except requests.exceptions.HTTPError as e:
            logger.error("HTTP error from Loki: %s | body: %s", e, response.text[:300])
            sys.exit(1)
        except requests.exceptions.ConnectionError as e:
            logger.error("Connection error reaching Loki: %s", e)
            sys.exit(1)
        except requests.exceptions.Timeout:
            logger.error("Request to Loki timed out.")
            sys.exit(1)

        data = response.json()
        if data.get("status") != "success":
            logger.error("Loki returned non-success status: %s", data)
            sys.exit(1)

        streams = data["data"]["result"]
        logger.info("Received %d log streams from Loki.", len(streams))
        return streams

    def parse_streams(self, streams: list[dict]) -> pd.DataFrame:
        records = []
        for stream in streams:
            labels = stream["stream"]
            container = labels.get("container_name", "unknown")
            host = labels.get("host", "unknown")
            source = labels.get("source", "unknown")
            compose_service = labels.get("compose_service", "unknown")

            for ts, message in stream["values"]:
                records.append({
                    "container": container,
                    "host": host,
                    "source": source,
                    "compose_service": compose_service,
                    "timestamp_ns": ts,
                    "message": message.strip(),
                })

        if not records:
            return pd.DataFrame()

        df = pd.DataFrame(records)
        df["timestamp"] = pd.to_datetime(df["timestamp_ns"].astype("int64"), unit="ns")
        df.drop(columns=["timestamp_ns"], inplace=True)
        df.sort_values("timestamp", inplace=True)
        df.reset_index(drop=True, inplace=True)
        return df


# ---------------------------------------------------------------------------
# Feature Engineering
# ---------------------------------------------------------------------------
ERROR_PATTERN = r"error|fail|critical|panic|exception|traceback|fatal|warning"

def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["message_length"] = df["message"].str.len()
    df["level_score"] = df["message"].str.contains(
        ERROR_PATTERN, case=False, regex=True
    ).astype(int)
    return df


# ---------------------------------------------------------------------------
# Anomaly Detection
# ---------------------------------------------------------------------------
def detect_anomalies(df: pd.DataFrame, contamination: float) -> pd.DataFrame:
    model = IsolationForest(contamination=contamination, random_state=42, n_jobs=-1)
    features = df[["message_length", "level_score"]]
    df = df.copy()
    df["anomaly_score"] = model.fit_predict(features)
    df["is_anomaly"] = df["anomaly_score"] == -1
    df["status"] = df["is_anomaly"].map({True: "❌ Anomaly", False: "✅ Normal"})
    return df


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
def print_report(df: pd.DataFrame) -> None:
    total = len(df)
    anomalies = df[df["is_anomaly"]]
    anomaly_count = len(anomalies)
    normal_count = total - anomaly_count

    print("\n" + "=" * 70)
    print("  🔍 LOKI ANOMALY DETECTION REPORT")
    print("=" * 70)
    print(f"  Host          : {df['host'].iloc[0]}")
    print(f"  Total Logs    : {total}")
    print(f"  Containers    : {df['container'].nunique()}")
    print(f"  Normal        : {normal_count}")
    print(f"  Anomalies     : {anomaly_count}")
    print("=" * 70)

    if anomaly_count == 0:
        print("\n✅ No anomalies detected.\n")
        return

    print("\n❌ Anomalous Log Lines:\n")
    display_cols = ["timestamp", "container", "source", "message"]
    print(anomalies[display_cols].to_string(index=False, max_colwidth=80))

    print("\n📦 Anomalies per Container:\n")
    summary = (
        anomalies.groupby("container")
        .size()
        .reset_index(name="anomaly_count")
        .sort_values("anomaly_count", ascending=False)
    )
    print(summary.to_string(index=False))
    print()


# ---------------------------------------------------------------------------
# Optional: Export to CSV
# ---------------------------------------------------------------------------
def export_results(df: pd.DataFrame, output_path: Optional[str] = None) -> None:
    if not output_path:
        output_path = os.getenv("OUTPUT_CSV", "")
    if output_path:
        df.to_csv(output_path, index=False)
        logger.info("Results exported to %s", output_path)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    config = Config.from_env()
    session = build_http_session()
    client = LokiClient(config, session)

    streams = client.fetch_logs()
    df = client.parse_streams(streams)

    if df.empty:
        logger.warning("No logs returned for host=%s. Check your query or time range.", config.host)
        sys.exit(0)

    logger.info("Parsed %d log lines across %d containers.", len(df), df["container"].nunique())

    df = engineer_features(df)
    df = detect_anomalies(df, contamination=config.anomaly_rate)

    print_report(df)
    export_results(df)


if __name__ == "__main__":
    main()
