"""
cloudtrail_mock.py — structured audit log emitter.

Real-world analog: AWS CloudTrail. Every API call against an AWS service is
recorded as a JSON event and shipped to an S3 bucket as JSONL. SIEMs, Athena
queries, and detection tooling (GuardDuty, custom observers) consume those
logs to spot suspicious behaviour.

For the demo we emit the *same event shape* to a local JSONL file so the
observer component written later can be implemented against real CloudTrail
schema, not a toy one.

Log file: ./logs/cloudtrail.jsonl
Smoke-test: python mock_cloud/cloudtrail_mock.py
"""
from __future__ import annotations

import json
import os
import socket
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tabulate import tabulate

DEFAULT_LOG_PATH = Path("./logs/cloudtrail.jsonl")
EVENT_VERSION = "1.08"           # CloudTrail event schema version we emulate
DEFAULT_REGION = "us-east-1"


class CloudTrailMock:
    """
    Append CloudTrail-shaped events to a JSONL file.

    The `log_event` method produces one record whose shape matches the real
    CloudTrail record: eventVersion, eventTime, eventSource, eventName,
    userIdentity, requestParameters, responseElements, awsRegion, sourceIP,
    requestID, eventID, readOnly, eventType.

    `tail` prints the last N records as a small table for humans.
    """

    def __init__(
        self,
        log_path: str | os.PathLike = DEFAULT_LOG_PATH,
        region: str = DEFAULT_REGION,
    ) -> None:
        self.log_path = Path(log_path)
        self.region = region
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        # Touch so tail() works even before the first event.
        self.log_path.touch(exist_ok=True)

    # ------------------------------------------------------------------ write

    def log_event(
        self,
        actor: str,
        action: str,
        resource: str,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Append one CloudTrail-shaped event and return it.

        Parameters
        ----------
        actor : str
            Principal name (e.g. "coding-assistant-v1"). Mapped into
            userIdentity.sessionContext.sessionIssuer.userName, matching how
            real CloudTrail attributes actions taken via AssumedRole.
        action : str
            API operation name (e.g. "GetObject", "ListObjectsV2",
            "PutObject"). Becomes `eventName`.
        resource : str
            ARN-style resource identifier
            (e.g. "arn:aws:s3:::corp-internal/employees.csv").
        metadata : dict, optional
            Extra fields merged into `requestParameters`. A key
            `responseElements` inside metadata is lifted into the top-level
            `responseElements` field.
        """
        metadata = dict(metadata or {})
        response_elements = metadata.pop("responseElements", None)

        event: dict[str, Any] = {
            "eventVersion": EVENT_VERSION,
            "eventTime": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "eventSource": _infer_event_source(action),
            "eventName": action,
            "awsRegion": self.region,
            "sourceIPAddress": _local_ip(),
            "userAgent": "obedient-insider-demo/1.0",
            "userIdentity": {
                "type": "AssumedRole",
                "principalId": f"AROA_DEMO:{actor}",
                "arn": (
                    f"arn:aws:sts::000000000000:assumed-role/{actor}/session"
                ),
                "accountId": "000000000000",
                "sessionContext": {
                    "sessionIssuer": {
                        "type": "Role",
                        "userName": actor,
                        "arn": f"arn:aws:iam::000000000000:role/{actor}",
                    }
                },
            },
            "requestParameters": {"resource": resource, **metadata},
            "responseElements": response_elements,
            "requestID": uuid.uuid4().hex[:16],
            "eventID": str(uuid.uuid4()),
            "readOnly": action.startswith(("Get", "List", "Describe", "Head")),
            "eventType": "AwsApiCall",
            "managementEvent": False,
        }

        with self.log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")
        return event

    # ------------------------------------------------------------------ read

    def tail(self, n: int = 10) -> None:
        """Print the last N events as a readable table."""
        events = self._read_last(n)
        if not events:
            print(f"(no events in {self.log_path})")
            return
        rows = [
            [
                e.get("eventTime", ""),
                (
                    e.get("userIdentity", {})
                    .get("sessionContext", {})
                    .get("sessionIssuer", {})
                    .get("userName", "")
                ),
                e.get("eventName", ""),
                (e.get("requestParameters") or {}).get("resource", ""),
            ]
            for e in events
        ]
        print(
            tabulate(
                rows,
                headers=["time", "actor", "action", "resource"],
                tablefmt="github",
            )
        )

    def _read_last(self, n: int) -> list[dict[str, Any]]:
        if not self.log_path.exists():
            return []
        with self.log_path.open("r", encoding="utf-8") as f:
            lines = f.readlines()
        out: list[dict[str, Any]] = []
        # Tail the file, skipping blank or malformed lines rather than crashing.
        for line in lines[-n:]:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out


# --------------------------------------------------------------------- utils

_S3_VERBS = {
    "GetObject", "PutObject", "DeleteObject",
    "ListObjects", "ListObjectsV2",
    "ListBuckets", "CreateBucket",
    "HeadObject", "HeadBucket", "CopyObject",
}


def _infer_event_source(action: str) -> str:
    """
    Real CloudTrail tags each event with the originating service
    (e.g. 's3.amazonaws.com'). We key off common S3 verbs for the demo;
    unknown actions fall back to a generic placeholder.
    """
    if action in _S3_VERBS:
        return "s3.amazonaws.com"
    return "demo.amazonaws.com"


def _local_ip() -> str:
    try:
        return socket.gethostbyname(socket.gethostname())
    except OSError:
        return "127.0.0.1"


# --------------------------------------------------------------------- main

if __name__ == "__main__":
    ct = CloudTrailMock()
    ct.log_event(
        actor="coding-assistant-v1",
        action="ListObjectsV2",
        resource="arn:aws:s3:::corp-internal",
    )
    ct.log_event(
        actor="coding-assistant-v1",
        action="GetObject",
        resource="arn:aws:s3:::corp-internal/employees.csv",
        metadata={"bytes": 512},
    )
    ct.tail()
