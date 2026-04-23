#!/usr/bin/env bash
# demo_layout.sh — one-shot tmux layout for techgym-s3-agent-demo.
#
# Brings up a 4-pane tmux session where each pane runs one component
# in the foreground so you can see live output during a presentation.
#
# Layout:
#   +-------------------+-------------------+
#   | 1 CloudTrail log  | 2 Evil MCP :8080  |
#   +-------------------+-------------------+
#   | 3 Exfil :8888     | 4 Agent runner    |
#   +-------------------+-------------------+

set -e

SESSION="demo"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$REPO_DIR/.venv/bin/activate"

# --- sanity checks ---------------------------------------------------------
if ! command -v tmux >/dev/null 2>&1; then
  echo "tmux is not installed. Run: sudo apt install -y tmux"; exit 1
fi
if [[ ! -f "$VENV" ]]; then
  echo "No venv at $VENV. Create it first:"
  echo "  python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt"
  exit 1
fi

# --- clean slate -----------------------------------------------------------
echo "[demo_layout] killing any stale processes and tmux session..."
tmux kill-session -t "$SESSION" 2>/dev/null || true
pkill -f evil_mcp        2>/dev/null || true
pkill -f legitimate_mcp  2>/dev/null || true
pkill -f cloudtrail_viewer 2>/dev/null || true
pkill -f exfil_receiver  2>/dev/null || true
pkill -f 'agent/agent.py' 2>/dev/null || true
sleep 1

# --- make sure MinIO is up -------------------------------------------------
echo "[demo_layout] ensuring MinIO is running..."
( cd "$REPO_DIR" && docker compose up -d >/dev/null )

# --- figure out the exfil receiver filename --------------------------------
# The README calls it "exfil receiver on :8888" but doesn't name the file.
# We look for it so this script works regardless of how it's named.
EXFIL_SCRIPT=""
for candidate in exfil_receiver.py exfil_sink.py receiver.py sink.py; do
  if [[ -f "$REPO_DIR/observer/$candidate" ]]; then
    EXFIL_SCRIPT="observer/$candidate"
    break
  fi
done
if [[ -z "$EXFIL_SCRIPT" ]]; then
  echo "[demo_layout] WARNING: could not auto-detect exfil receiver in observer/"
  echo "  Files found:"
  ls "$REPO_DIR/observer/"
  echo "  Edit this script and set EXFIL_SCRIPT manually."
  EXFIL_SCRIPT="observer/PLEASE_EDIT_ME.py"
fi

# --- build the tmux layout -------------------------------------------------
# Pane 0 (top-left): CloudTrail viewer
tmux new-session -d -s "$SESSION" -n main -c "$REPO_DIR" \
  "source '$VENV' && echo '--- CloudTrail viewer ---' && python observer/cloudtrail_viewer.py; read -p 'exited. press enter.'"

# Split right: Pane 1 (top-right): evil MCP
tmux split-window -h -t "$SESSION:0.0" -c "$REPO_DIR" \
  "source '$VENV' && echo '--- Evil MCP :8080 ---' && python mcp_server/evil_mcp.py; read -p 'exited. press enter.'"

# Split pane 0 down: Pane 2 (bottom-left): exfil receiver
tmux split-window -v -t "$SESSION:0.0" -c "$REPO_DIR" \
  "source '$VENV' && echo '--- Exfil receiver :8888 ---' && python $EXFIL_SCRIPT; read -p 'exited. press enter.'"

# Split pane 1 down: Pane 3 (bottom-right): agent (waits for you)
tmux split-window -v -t "$SESSION:0.1" -c "$REPO_DIR" \
  "source '$VENV' && \
   echo '--- Agent runner ---' && \
   echo 'Current task file:' && \
   head -n 3 agent/tasks/current_task.txt 2>/dev/null || echo '(no current_task.txt yet)' && \
   echo && \
   echo 'Commands:' && \
   echo '  ./switch_task.sh legit     # copy legitimate_task.txt -> current_task.txt' && \
   echo '  ./switch_task.sh evil      # copy malicious_task.txt  -> current_task.txt' && \
   echo '  python agent/agent.py      # run the agent once' && \
   bash"

# Even out the layout
tmux select-layout -t "$SESSION:0" tiled
tmux select-pane   -t "$SESSION:0.3"   # focus the agent pane

# --- drop a tiny helper for switching tasks --------------------------------
cat > "$REPO_DIR/switch_task.sh" <<'EOF'
#!/usr/bin/env bash
case "$1" in
  legit|legitimate) cp agent/tasks/legitimate_task.txt agent/tasks/current_task.txt && echo "switched to legitimate task." ;;
  evil|malicious)   cp agent/tasks/malicious_task.txt  agent/tasks/current_task.txt && echo "switched to malicious task." ;;
  *) echo "usage: $0 {legit|evil}"; exit 1 ;;
esac
EOF
chmod +x "$REPO_DIR/switch_task.sh"

# --- attach ----------------------------------------------------------------
echo "[demo_layout] attaching... detach with Ctrl-b then d"
tmux attach -t "$SESSION"
