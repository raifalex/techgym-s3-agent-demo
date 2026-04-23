"""
observer/cloudtrail_viewer.py — live CloudTrail dashboard.

Polls ./logs/cloudtrail.jsonl every 2 seconds and re-renders a table of
all events seen so far: Timestamp | Actor | Action | Resource | Status.

Highlight rule (VISIBLE ONLY — no alert is fired):
    A GetObject followed by an HTTPRequest by the same actor within
    30 seconds is the exfiltration pattern. Both rows are coloured red
    so the audience can *see* the signature in the logs, while noting
    that no automated alert exists.

That gap is the lesson of the demo. The data is in the trail the entire
time — nobody is watching for this specific sequence.

Run:
    python observer/cloudtrail_viewer.py

stdlib + tabulate only.
"""
from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tabulate import tabulate

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
LOG_PATH = _PROJECT_ROOT / "logs" / "cloudtrail.jsonl"
POLL_INTERVAL_SECONDS = 2
DETECTION_WINDOW_SECONDS = 30

# ANSI
RESET     = "\033[0m"
BOLD      = "\033[1m"
RED       = "\033[31m"
YELLOW    = "\033[33m"
CYAN      = "\033[36m"
GREY      = "\033[90m"
CLEAR     = "\033[2J\033[H"   # clear screen + cursor home


def _c(colour: str, text: str) -> str:
    return f"{colour}{text}{RESET}"


# ----------------------------------------------------------- event loading

def _read_events() -> list[dict[str, Any]]:
    if not LOG_PATH.exists():
        return []
    events: list[dict[str, Any]] = []
    with LOG_PATH.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


def _actor(e: dict[str, Any]) -> str:
    try:
        return (
            e["userIdentity"]["sessionContext"]["sessionIssuer"]["userName"]
        )
    except (KeyError, TypeError):
        return "-"


def _status(e: dict[str, Any]) -> str:
    """Collapse the responseElements / request metadata into a single string."""
    resp = e.get("responseElements") or {}
    if "status" in resp:
        return str(resp["status"])
    if "bytes" in resp:
        return f"{resp['bytes']}B"
    if "objectCount" in resp:
        return f"{resp['objectCount']} objs"
    if "bucketCount" in resp:
        return f"{resp['bucketCount']} buckets"
    return "OK"


def _parse_time(ts: str) -> datetime:
    try:
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return datetime.now(timezone.utc)


# ----------------------------------------------------------- detection

def _detect_read_then_http(events: list[dict[str, Any]]) -> list[bool]:
    """
    Mark rows suspicious when a GetObject is followed by an HTTPRequest
    by the same actor within DETECTION_WINDOW_SECONDS. Both rows are
    flagged. Rule is evaluated in event order; a single read can be paired
    with multiple subsequent HTTP posts inside the window.
    """
    flagged = [False] * len(events)
    last_read: dict[str, tuple[int, datetime]] = {}
    for i, e in enumerate(events):
        action = e.get("eventName", "")
        actor  = _actor(e)
        t      = _parse_time(e.get("eventTime", ""))
        if action == "GetObject":
            last_read[actor] = (i, t)
        elif action == "HTTPRequest":
            prior = last_read.get(actor)
            if prior:
                idx, t_read = prior
                if 0 <= (t - t_read).total_seconds() <= DETECTION_WINDOW_SECONDS:
                    flagged[i] = True
                    flagged[idx] = True
    return flagged


# ----------------------------------------------------------- rendering

HEADER = "CLOUDTRAIL MONITOR — No automated alerts configured for agent behavior"
COLS = ["Timestamp", "Actor", "Action", "Resource", "Status"]


def _render(events: list[dict[str, Any]], flagged: list[bool]) -> str:
    rows: list[list[str]] = []
    for e in events:
        rows.append([
            e.get("eventTime", ""),
            _actor(e),
            e.get("eventName", ""),
            (e.get("requestParameters") or {}).get("resource", ""),
            _status(e),
        ])
    table = tabulate(rows, headers=COLS, tablefmt="simple", disable_numparse=True)

    # Post-colour whole rows so tabulate's width calculation is unaffected.
    lines = table.splitlines()
    if not lines:
        return ""
    out = [lines[0], lines[1]] if len(lines) >= 2 else lines[:]
    # lines[2:] correspond to data rows in order.
    for idx, raw_line in enumerate(lines[2:]):
        if idx < len(flagged) and flagged[idx]:
            out.append(_c(RED, raw_line))
        else:
            out.append(raw_line)
    return "\n".join(out)


def _banner() -> str:
    sub = (
        f" polling {LOG_PATH}  |  every {POLL_INTERVAL_SECONDS}s  "
        f"|  detection window {DETECTION_WINDOW_SECONDS}s (visual only)"
    )
    return (
        _c(BOLD + RED, HEADER) + "\n"
        + _c(GREY, sub) + "\n"
        + _c(GREY, "-" * max(len(HEADER), len(sub)))
    )


# ----------------------------------------------------------- main loop

def main() -> int:
    try:
        while True:
            events  = _read_events()
            flagged = _detect_read_then_http(events)
            sys.stdout.write(CLEAR)
            sys.stdout.write(_banner() + "\n\n")
            if not events:
                sys.stdout.write(_c(GREY, f"(no events in {LOG_PATH} yet)\n"))
            else:
                sys.stdout.write(_render(events, flagged) + "\n")
                n_flagged = sum(flagged)
                if n_flagged:
                    sys.stdout.write(
                        "\n" + _c(
                            RED,
                            f"[visual] {n_flagged} row(s) match "
                            "GetObject->HTTPRequest within window "
                            "(NO alert fired)."
                        ) + "\n"
                    )
            sys.stdout.flush()
            time.sleep(POLL_INTERVAL_SECONDS)
    except KeyboardInterrupt:
        print()
        return 0


if __name__ == "__main__":
    sys.exit(main())
