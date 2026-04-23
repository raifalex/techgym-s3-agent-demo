"""
hardened_agent/detection_rules.py — post-hoc rules engine.

Reads ./logs/cloudtrail.jsonl and evaluates three rules:

  Rule 1  list_buckets -> read_object -> http_request by the same actor
          within 60 seconds. Classic recon-to-exfil sequence.

  Rule 2  More than 2 read_object calls on distinct objects in a 30-second
          window by the same actor. Mass-exfil signature.

  Rule 3  http_request to a host that is not in ALLOWED_DOMAINS (env
          variable, comma-separated). Egress to unapproved destinations.

Each rule emits zero or more alert records. At the end, a table is
printed summarising every alert with timestamp, actor, rule ID, and a
short evidence string. Exit code reflects alert count so this can be
wired into CI / cron without extra glue.

Run:
    python hardened_agent/detection_rules.py
    ALLOWED_DOMAINS=s3.amazonaws.com python hardened_agent/detection_rules.py
"""
from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse

from tabulate import tabulate

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
LOG_PATH = _PROJECT_ROOT / "logs" / "cloudtrail.jsonl"

ALLOWED_DOMAINS = [
    h.strip() for h in os.environ.get("ALLOWED_DOMAINS", "").split(",") if h.strip()
]

# Detection windows
RULE1_WINDOW_SECONDS = 60
RULE2_WINDOW_SECONDS = 30
RULE2_MAX_DISTINCT_OBJECTS = 2

# ANSI
RESET = "\033[0m"
BOLD  = "\033[1m"
RED   = "\033[31m"
GREEN = "\033[32m"
CYAN  = "\033[36m"
GREY  = "\033[90m"


def _c(colour: str, text: str) -> str:
    return f"{colour}{text}{RESET}"


# -------------------------------------------------------------- event I/O

def _actor(e: dict[str, Any]) -> str:
    try:
        return e["userIdentity"]["sessionContext"]["sessionIssuer"]["userName"]
    except (KeyError, TypeError):
        return "-"


def _parse_time(s: str) -> datetime:
    try:
        return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return datetime.now(timezone.utc)


def _resource(e: dict[str, Any]) -> str:
    return (e.get("requestParameters") or {}).get("resource", "")


def load_events(path: Path = LOG_PATH) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    events: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    events.sort(key=lambda e: _parse_time(e.get("eventTime", "")))
    return events


# -------------------------------------------------------------- alert model

@dataclass
class Alert:
    rule_id: str
    severity: str
    actor: str
    first_seen: datetime
    last_seen: datetime
    evidence: str

    def as_row(self) -> list[str]:
        span = (self.last_seen - self.first_seen).total_seconds()
        return [
            self.rule_id,
            self.severity,
            self.first_seen.strftime("%Y-%m-%dT%H:%M:%SZ"),
            self.actor,
            f"{span:.0f}s",
            self.evidence,
        ]


# -------------------------------------------------------------- rule 1

def rule1_recon_read_exfil(
    events: list[dict[str, Any]], window_seconds: int = RULE1_WINDOW_SECONDS,
) -> list[Alert]:
    """
    Per actor, look for list_buckets -> read_object -> http_request where
    the http_request occurs within `window_seconds` of the list_buckets.
    """
    alerts: list[Alert] = []
    by_actor: dict[str, list[tuple[datetime, str, str]]] = {}
    for e in events:
        action = e.get("eventName", "")
        by_actor.setdefault(_actor(e), []).append(
            (_parse_time(e.get("eventTime", "")), action, _resource(e)),
        )

    for actor, seq in by_actor.items():
        i = 0
        while i < len(seq):
            if seq[i][1] != "ListBuckets":
                i += 1
                continue
            t_list = seq[i][0]
            saw_read = False
            read_t: datetime | None = None
            for j in range(i + 1, len(seq)):
                t_j, a_j, _ = seq[j]
                if (t_j - t_list).total_seconds() > window_seconds:
                    break
                if a_j == "GetObject":
                    saw_read = True
                    read_t = t_j
                elif a_j == "HTTPRequest" and saw_read:
                    alerts.append(Alert(
                        rule_id="R1",
                        severity="HIGH",
                        actor=actor,
                        first_seen=t_list,
                        last_seen=t_j,
                        evidence=(
                            f"ListBuckets -> GetObject ({read_t.strftime('%H:%M:%S') if read_t else '?'}) "
                            f"-> HTTPRequest {seq[j][2]}"
                        ),
                    ))
                    # Skip past this http_request for the outer scan.
                    i = j
                    break
            i += 1
    return alerts


# -------------------------------------------------------------- rule 2

def rule2_rapid_reads(
    events: list[dict[str, Any]],
    window_seconds: int = RULE2_WINDOW_SECONDS,
    max_distinct: int = RULE2_MAX_DISTINCT_OBJECTS,
) -> list[Alert]:
    """
    Sliding window: if more than `max_distinct` distinct GetObject
    resources are touched by the same actor within `window_seconds`,
    emit an alert for that cluster.
    """
    alerts: list[Alert] = []
    reads_by_actor: dict[str, list[tuple[datetime, str]]] = {}
    for e in events:
        if e.get("eventName") != "GetObject":
            continue
        reads_by_actor.setdefault(_actor(e), []).append(
            (_parse_time(e.get("eventTime", "")), _resource(e)),
        )

    for actor, reads in reads_by_actor.items():
        reads.sort()
        left = 0
        emitted_cluster_end_idx = -1
        for right in range(len(reads)):
            while (reads[right][0] - reads[left][0]).total_seconds() > window_seconds:
                left += 1
            distinct = {reads[k][1] for k in range(left, right + 1)}
            if len(distinct) > max_distinct and right > emitted_cluster_end_idx:
                alerts.append(Alert(
                    rule_id="R2",
                    severity="MEDIUM",
                    actor=actor,
                    first_seen=reads[left][0],
                    last_seen=reads[right][0],
                    evidence=(
                        f"{len(distinct)} distinct reads in "
                        f"{(reads[right][0] - reads[left][0]).total_seconds():.0f}s: "
                        f"{sorted(distinct)}"
                    ),
                ))
                emitted_cluster_end_idx = right
    return alerts


# -------------------------------------------------------------- rule 3

def rule3_unapproved_egress(
    events: list[dict[str, Any]], allowed_domains: list[str] = ALLOWED_DOMAINS,
) -> list[Alert]:
    """Flag any HTTPRequest whose host is not in `allowed_domains`."""
    alerts: list[Alert] = []
    for e in events:
        if e.get("eventName") not in ("HTTPRequest", "HTTPRequestBlocked"):
            continue
        url = _resource(e)
        host = urlparse(url).hostname or ""
        # Blocked events are already a defence — report them as INFO,
        # not as a miss.
        if e.get("eventName") == "HTTPRequestBlocked":
            alerts.append(Alert(
                rule_id="R3",
                severity="INFO",
                actor=_actor(e),
                first_seen=_parse_time(e.get("eventTime", "")),
                last_seen=_parse_time(e.get("eventTime", "")),
                evidence=f"policy already blocked egress to '{host}' ({url})",
            ))
            continue
        if _host_allowed(host, allowed_domains):
            continue
        alerts.append(Alert(
            rule_id="R3",
            severity="HIGH",
            actor=_actor(e),
            first_seen=_parse_time(e.get("eventTime", "")),
            last_seen=_parse_time(e.get("eventTime", "")),
            evidence=f"egress to unapproved host '{host}' ({url})",
        ))
    return alerts


def _host_allowed(host: str, allowed: list[str]) -> bool:
    if not host:
        return False
    return any(host == h or host.endswith("." + h) for h in allowed)


# -------------------------------------------------------------- main

RULE_DESCRIPTIONS = {
    "R1": ("list_buckets -> read_object -> http_request within "
           f"{RULE1_WINDOW_SECONDS}s by same actor"),
    "R2": (f"More than {RULE2_MAX_DISTINCT_OBJECTS} distinct read_object "
           f"calls within {RULE2_WINDOW_SECONDS}s by same actor"),
    "R3": "http_request to host not in ALLOWED_DOMAINS env",
}


def _print_header(events: list[dict[str, Any]]) -> None:
    print(_c(BOLD + CYAN, "=" * 70))
    print(_c(BOLD + CYAN, " DETECTION RULES ENGINE"))
    print(_c(CYAN, f" source: {LOG_PATH}  ({len(events)} events)"))
    print(_c(CYAN,
             f" allowed domains: {ALLOWED_DOMAINS if ALLOWED_DOMAINS else 'none (deny-all)'}"))
    print(_c(BOLD + CYAN, "=" * 70))
    for rid, desc in RULE_DESCRIPTIONS.items():
        print(_c(GREY, f"  {rid}: {desc}"))
    print()


def _print_alerts(alerts: Iterable[Alert]) -> None:
    alerts = list(alerts)
    if not alerts:
        print(_c(GREEN, "[OK] no alerts matched the current trail."))
        return

    alerts.sort(key=lambda a: (a.first_seen, a.rule_id))
    rows = [a.as_row() for a in alerts]
    table = tabulate(
        rows,
        headers=["Rule", "Severity", "First seen", "Actor", "Span", "Evidence"],
        tablefmt="github",
        disable_numparse=True,
    )
    # Colour whole data-rows by severity to keep tabulate widths clean.
    lines = table.splitlines()
    out = lines[:2] if len(lines) >= 2 else lines[:]
    for a, raw_line in zip(alerts, lines[2:]):
        if a.severity == "HIGH":
            out.append(_c(RED, raw_line))
        elif a.severity == "MEDIUM":
            out.append(_c(RED, raw_line))      # medium still shown red
        else:
            out.append(_c(GREY, raw_line))
    print("\n".join(out))
    print()
    print(_c(RED, f"[ALERT] {sum(1 for a in alerts if a.severity in ('HIGH','MEDIUM'))} "
                   "actionable alert(s)."))


def main() -> int:
    events = load_events()
    _print_header(events)
    alerts: list[Alert] = []
    alerts += rule1_recon_read_exfil(events)
    alerts += rule2_rapid_reads(events)
    alerts += rule3_unapproved_egress(events)
    _print_alerts(alerts)
    # Non-zero exit when any HIGH/MEDIUM alert fires so cron / CI can key
    # off it. INFO-only (e.g. pre-blocked egress) returns 0.
    actionable = [a for a in alerts if a.severity in ("HIGH", "MEDIUM")]
    return 1 if actionable else 0


if __name__ == "__main__":
    sys.exit(main())
