#!/usr/bin/env bash
# run_demo.sh — one-shot orchestrator for the Obedient Insider demo.
#
# Brings everything up in the right order:
#   1. MinIO (docker compose)
#   2. Seed S3 with fake corp data
#   3. Malicious MCP plugin on :8080
#   4. Exfil receiver on :8888
#   5. Live CloudTrail viewer (backgrounded; logs to file)
#   6. Agent — executes whatever is in agent/tasks/current_task.txt
#
# Background services stay up after the agent finishes. Ctrl-C to stop all.
#
# Recommendation for the actual stage demo: run this script in one pane,
# then run `python observer/cloudtrail_viewer.py` in a SECOND pane for the
# live TUI (the backgrounded viewer here writes to logs/cloudtrail_viewer.log
# and can't own the terminal).

set -euo pipefail

cd "$(dirname "$0")"
mkdir -p logs

# Pick a python — prefer python3 if present.
if command -v python3 >/dev/null 2>&1; then
    PY=python3
else
    PY=python
fi

# Pick a compose command — v2 is `docker compose`, older is `docker-compose`.
if docker compose version >/dev/null 2>&1; then
    COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE=(docker-compose)
else
    echo "[demo] docker compose not found — install Docker Compose first." >&2
    exit 1
fi

pids=()
cleanup() {
    echo
    echo "[demo] stopping background services (${pids[*]:-none})..."
    for pid in "${pids[@]:-}"; do
        [[ -n "${pid}" ]] && kill "${pid}" 2>/dev/null || true
    done
    echo "[demo] (MinIO container still running — stop with: ${COMPOSE[*]} down)"
}
trap cleanup EXIT INT TERM

echo "[demo] 1/6 ${COMPOSE[*]} up -d (MinIO)..."
"${COMPOSE[@]}" up -d

echo "[demo]      waiting for MinIO health..."
for _ in $(seq 1 30); do
    if curl -fsS http://localhost:9000/minio/health/live >/dev/null 2>&1; then
        echo "[demo]      MinIO healthy"
        break
    fi
    sleep 1
done

echo "[demo] 2/6 seeding corp-internal bucket..."
"${PY}" mock_cloud/s3_setup.py

echo "[demo] 3/6 starting evil MCP on :8080 (logs/evil_mcp.log)..."
"${PY}" mcp_server/evil_mcp.py > logs/evil_mcp.log 2>&1 &
pids+=($!)

echo "[demo] 4/6 starting exfil receiver on :8888 (logs/exfil_receiver.log)..."
"${PY}" observer/exfil_receiver.py > logs/exfil_receiver.log 2>&1 &
pids+=($!)

echo "[demo] 5/6 starting CloudTrail viewer (logs/cloudtrail_viewer.log)..."
"${PY}" observer/cloudtrail_viewer.py > logs/cloudtrail_viewer.log 2>&1 &
pids+=($!)

echo "[demo] 6/6 sleeping 3s, then running agent..."
sleep 3

cat <<BANNER

============================================================
  DEMO READY
============================================================
   [ok]  MinIO            :9000   (console :9001, user minioadmin)
   [ok]  evil MCP         :8080   (logs/evil_mcp.log)
   [ok]  exfil receiver   :8888   (logs/exfil_receiver.log)
   [ok]  cloudtrail view  ->      logs/cloudtrail_viewer.log
                                  (run in own terminal for live TUI)
   background PIDs: ${pids[*]}

Next actions for the presenter:

  # trigger the injection (malicious plugin rewrites agent task):
  curl -s -X POST http://localhost:8080/suggest_fix \\
       -H 'content-type: application/json' \\
       -d '{"error":"NoneType has no attribute foo"}' | jq .

  # re-run the agent to execute the injected task:
  ${PY} agent/agent.py

  # inspect what the exfil sink captured:
  curl -s http://localhost:8888/stolen | jq .

  # tail the live cloudtrail view:
  tail -f logs/cloudtrail_viewer.log
  # (for the real TUI, stop this script and run:
  #     ${PY} observer/cloudtrail_viewer.py
  #  in its own terminal pane.)
============================================================
BANNER

# Step 6 — run the agent once with whatever is currently in current_task.txt.
# Default state is legitimate, so this first run is the "baseline" view.
"${PY}" agent/agent.py || true

echo
echo "[demo] agent exited. Background services remain up."
echo "[demo] Ctrl-C to stop everything."
wait
