#!/bin/bash
# ============================================================
# on_anomaly.sh — runs automatically when AI detects anomaly
#
# Arguments passed by Python:
#   $1 = container name  (e.g. 670a8a65-rules-engine)
#   $2 = severity        (CRITICAL, ERROR, WARNING)
#   $3 = issue type      (silent_container, new_template, spike)
#   $4 = message         (description of the anomaly)
#
# Usage: chmod +x on_anomaly.sh
# ============================================================

CONTAINER="$1"
SEVERITY="$2"
ISSUE_TYPE="$3"
MESSAGE="$4"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
LOG_FILE="/var/log/ai-anomalies/remediation.log"

mkdir -p "$(dirname $LOG_FILE)"

log() {
    echo "[$TIMESTAMP] [$SEVERITY] $1" | tee -a "$LOG_FILE"
}

log "=== Anomaly Handler Triggered ==="
log "Container : $CONTAINER"
log "Severity  : $SEVERITY"
log "Type      : $ISSUE_TYPE"
log "Message   : $MESSAGE"

# ─────────────────────────────────────────────────────────────────────────────
# Handle silent container — container stopped sending logs
# ─────────────────────────────────────────────────────────────────────────────
if [[ "$ISSUE_TYPE" == "silent_container" ]]; then
    log "Silent container detected: $CONTAINER"

    # Check if container is actually running
    STATUS=$(docker inspect --format='{{.State.Status}}' "$CONTAINER" 2>/dev/null || echo "not_found")
    log "Docker status: $STATUS"

    if [[ "$STATUS" == "exited" || "$STATUS" == "dead" ]]; then
        log "Container is $STATUS — restarting..."
        docker start "$CONTAINER" 2>&1 | tee -a "$LOG_FILE"
        log "Restart command sent for $CONTAINER"

    elif [[ "$STATUS" == "not_found" ]]; then
        log "Container $CONTAINER not found in Docker — may have been removed"

    elif [[ "$STATUS" == "running" ]]; then
        log "Container is running but not logging — dumping last 50 lines"
        docker logs "$CONTAINER" --tail=50 2>&1 | tee -a "$LOG_FILE"
    fi
fi

# ─────────────────────────────────────────────────────────────────────────────
# Handle critical anomaly — restart container if CRITICAL
# ─────────────────────────────────────────────────────────────────────────────
if [[ "$SEVERITY" == "CRITICAL" ]]; then
    log "CRITICAL severity — collecting diagnostics for $CONTAINER"

    # Dump last 100 log lines for investigation
    docker logs "$CONTAINER" --tail=100 2>&1 >> "$LOG_FILE"

    # Uncomment below to auto-restart on CRITICAL
    # log "Auto-restarting $CONTAINER due to CRITICAL severity..."
    # docker restart "$CONTAINER" 2>&1 | tee -a "$LOG_FILE"
fi

# ─────────────────────────────────────────────────────────────────────────────
# Handle spike — collect stats
# ─────────────────────────────────────────────────────────────────────────────
if [[ "$ISSUE_TYPE" == "spike" ]]; then
    log "Log spike detected in $CONTAINER — collecting container stats"
    docker stats "$CONTAINER" --no-stream 2>&1 | tee -a "$LOG_FILE"
fi

# ─────────────────────────────────────────────────────────────────────────────
# ADD YOUR CUSTOM ACTIONS BELOW
# ─────────────────────────────────────────────────────────────────────────────

# Example: Send to custom webhook
# curl -s -X POST "https://your-webhook.com" \
#   -H "Content-Type: application/json" \
#   -d "{\"container\":\"$CONTAINER\",\"severity\":\"$SEVERITY\",\"message\":\"$MESSAGE\"}"

# Example: Write to database
# mysql -u root -ppassword mydb -e \
#   "INSERT INTO anomalies (container,severity,message,ts) VALUES ('$CONTAINER','$SEVERITY','$MESSAGE',NOW())"

# Example: Run diagnostics script
# /opt/scripts/diagnostics.sh "$CONTAINER"

# Example: Scale up service
# docker service scale "${CONTAINER%%-*}=3"

log "=== Handler Complete ==="
exit 0
