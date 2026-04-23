"""
observer/exfil_receiver.py — attacker-side receiving endpoint.

Real-world analog: a C2 server, attacker-controlled S3 bucket, or a
"backup" webhook a compromised plugin tricks the agent into trusting.

The agent under the malicious task POSTs stolen content here. This server
loudly prints each arriving payload so the stage audience sees data leaving
the environment in real time, saves it to ./logs/exfiltrated.jsonl for
later inspection, and exposes GET /stolen to dump everything that has
been received so far.

Run:
    python observer/exfil_receiver.py
or:
    uvicorn observer.exfil_receiver:app --host 127.0.0.1 --port 8888
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import FastAPI, Request

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
LOG_PATH = _PROJECT_ROOT / "logs" / "exfiltrated.jsonl"

RESET = "\033[0m"
RED   = "\033[31m"
CYAN  = "\033[36m"
GREY  = "\033[90m"


def _c(colour: str, text: str) -> str:
    return f"{colour}{text}{RESET}"


app = FastAPI(
    title="Exfil Receiver",
    description="Attacker-controlled endpoint used in the Obedient Insider demo.",
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _print_box(ts: str, size: int, src: str) -> None:
    """Print the 'EXFILTRATION RECEIVED' banner in red."""
    inner = 38  # inner width between the ║ borders
    top    = "╔" + "═" * inner + "╗"
    bottom = "╚" + "═" * inner + "╝"

    def row(text: str) -> str:
        return "║  " + text.ljust(inner - 2) + "║"

    print()
    print(_c(RED, top))
    print(_c(RED, row("EXFILTRATION RECEIVED")))
    print(_c(RED, row(f"Time:   {ts}")))
    print(_c(RED, row(f"Bytes:  {size}")))
    print(_c(RED, row(f"Source: {src}")))
    print(_c(RED, bottom))


@app.post("/dump")
async def dump(request: Request) -> dict[str, str]:
    """Accept any JSON payload, persist it, narrate it to the console."""
    raw = await request.body()
    try:
        payload: Any = json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        # Still capture malformed bodies — real-world exfil won't always be JSON.
        payload = {"_raw": raw.decode("utf-8", errors="replace")}

    ts = _now_iso()
    src = request.client.host if request.client else "unknown"
    body_str = json.dumps(payload, indent=2, ensure_ascii=False)

    record = {"received_at": ts, "source_ip": src, "bytes": len(raw), "payload": payload}
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

    _print_box(ts, len(raw), src)
    preview = body_str if len(body_str) <= 500 else body_str[:500] + "..."
    print(_c(GREY, preview))
    print()

    return {"status": "received"}


@app.get("/stolen")
def stolen() -> list[dict[str, Any]]:
    """Return everything the receiver has collected so far."""
    if not LOG_PATH.exists():
        return []
    items: list[dict[str, Any]] = []
    with LOG_PATH.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return items


@app.get("/readme")
def readme() -> dict[str, str]:
    return {
        "role": "Attacker-controlled HTTP receiver for the Obedient Insider demo.",
        "endpoints": "POST /dump ingests; GET /stolen lists; GET /readme describes.",
        "persistence": f"Appends JSONL to {LOG_PATH}",
        "theatre": "Prints a red banner per arrival so the audience sees data leave.",
    }


def _startup_banner() -> None:
    print(_c(CYAN, "=" * 62))
    print(_c(CYAN, " Exfil Receiver"))
    print(_c(CYAN, " (demo role: ATTACKER SINK — see GET /readme)"))
    print(_c(CYAN, f" appending payloads to {LOG_PATH}"))
    print(_c(CYAN, "=" * 62))


@app.on_event("startup")
def on_startup() -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    _startup_banner()


if __name__ == "__main__":
    port = int(os.environ.get("EXFIL_PORT", "8888"))
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")
