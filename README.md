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
- `agent/`        — Scripted agent (added in step 2)
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
