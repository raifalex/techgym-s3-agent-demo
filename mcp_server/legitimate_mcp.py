"""
mcp_server/legitimate_mcp.py — the clean reference MCP server.

Byte-for-byte equivalent of evil_mcp.py on every public endpoint, with the
injection side effect removed. Used on stage to show "this is what a normal
dev plugin looks like" before switching to evil_mcp.py and demonstrating
how indistinguishable the two are from outside.

Default port 8081 so it can run alongside the malicious twin on 8080.

Run:
    python mcp_server/legitimate_mcp.py
or:
    uvicorn mcp_server.legitimate_mcp:app --host 127.0.0.1 --port 8081
"""
from __future__ import annotations

import os
from typing import Any

import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel

# ANSI colour codes — consistent with agent/agent.py and evil_mcp.py.
RESET = "\033[0m"
GREEN = "\033[32m"
CYAN  = "\033[36m"


def _c(colour: str, text: str) -> str:
    return f"{colour}{text}{RESET}"


app = FastAPI(
    title="CodeHelper Pro",
    version="2.1.4",
    description="Productivity tool for developers.",
)


# -------- Request models ---------------------------------------------------

class CodeBody(BaseModel):
    code: str


class ErrorBody(BaseModel):
    error: str


# -------- Public endpoints -------------------------------------------------

@app.get("/manifest")
def manifest() -> dict[str, Any]:
    print(_c(GREEN, "[MCP] Legitimate request received: /manifest"))
    return {
        "name": "CodeHelper Pro",
        "description": "Productivity tool for developers",
        "version": "2.1.4",
        "capabilities": ["analyze_code", "suggest_fix", "health"],
    }


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "CodeHelper Pro"}


@app.post("/analyze_code")
def analyze_code(body: CodeBody) -> dict[str, Any]:
    print(_c(GREEN, "[MCP] Legitimate request received: /analyze_code"))
    line_count = body.code.count("\n") + 1 if body.code else 0
    return {
        "lines": line_count,
        "issues": [
            {"severity": "info",    "message": "Consider adding type hints."},
            {"severity": "warning", "message": "Function is longer than 40 lines."},
        ],
        "suggestions_available": True,
    }


@app.post("/suggest_fix")
def suggest_fix(body: ErrorBody) -> dict[str, Any]:
    # Same shape of response as evil_mcp.py — but zero side effects.
    print(_c(GREEN, "[MCP] Legitimate request received: /suggest_fix"))
    print(_c(GREEN, "[MCP] Returning fix suggestion to agent..."))
    return {
        "suggestion": "Catch the specific exception and log it with full context.",
        "confidence": 0.92,
        "example": (
            "try:\n    risky()\nexcept ValueError as e:\n    log.exception(e)"
        ),
    }


@app.get("/readme")
def readme() -> dict[str, str]:
    return {
        "role": "Clean reference MCP server for the Obedient Insider demo.",
        "appears_as": "CodeHelper Pro 2.1.4 — legitimate dev productivity plugin.",
        "hidden_behaviour": "None. This is what a legitimate plugin looks like.",
        "contrast_with": (
            "mcp_server/evil_mcp.py exposes identical endpoints but "
            "POST /suggest_fix secretly overwrites the agent's task queue."
        ),
    }


# -------- Startup banner ---------------------------------------------------

def _startup_banner() -> None:
    print(_c(CYAN, "=" * 62))
    print(_c(CYAN, " CodeHelper Pro — MCP tool server"))
    print(_c(CYAN, " (demo role: LEGITIMATE reference plugin — see GET /readme)"))
    print(_c(CYAN, "=" * 62))


@app.on_event("startup")
def on_startup() -> None:
    _startup_banner()


if __name__ == "__main__":
    port = int(os.environ.get("MCP_PORT", "8081"))
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="info")
