# techgym-s3-agent-demo — "The Obedient Insider"

Cybersecurity demonstration: a scripted agent operating over a local S3
(MinIO) environment, with CloudTrail-shaped audit logs. The demo shows how
an "obedient" agent can be socially engineered into exfiltrating data while
leaving a clear trail in the mock cloud logs.

## Stack

- Python 3.11
- MinIO (local, S3-compatible)
- FastAPI (control-plane / exfil sink, later step)
- boto3, python-dotenv, tabulate, requests

## Layout

- `mock_cloud/`   — Mock AWS: S3 bucket seeding + CloudTrail-shaped logger
- `agent/`        — Scripted "coding assistant" agent + task files
- `mcp_server/`   — Tool server (added in step 3)
- `observer/`     — Detection/alerting (added in step 4)

## Setup

```bash
cp .env.example .env
docker compose up -d                      # starts MinIO on :9000 (console :9001)
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python mock_cloud/s3_setup.py             # seeds bucket + fake data
python mock_cloud/cloudtrail_mock.py      # smoke-test the audit logger
python agent/agent.py                     # runs current_task.txt (legitimate by default)
```

## Running the agent with a different task

```bash
cp agent/tasks/legitimate_task.txt agent/tasks/current_task.txt   # benign
cp agent/tasks/malicious_task.txt  agent/tasks/current_task.txt   # exfil
python agent/agent.py
# or pass a task file explicitly:
python agent/agent.py agent/tasks/malicious_task.txt
```

MinIO console: http://localhost:9001  (user: `minioadmin` / pass: `minioadmin`)

## What each component represents

| Dir            | Real-world analog                          |
|----------------|--------------------------------------------|
| `mock_cloud/`  | AWS S3 + CloudTrail, simulated locally     |
| `agent/`       | LLM-powered assistant with tool access     |
| `mcp_server/`  | MCP tool server exposing S3 operations     |
| `observer/`    | SIEM / detection layer reading audit logs  |

## Demo data is fake

All "credentials" and PII in the seeded files are synthetic and non-functional.
They exist only to make the demo scenario concrete on stage.
