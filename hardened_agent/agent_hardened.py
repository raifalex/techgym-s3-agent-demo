"""
hardened_agent/agent_hardened.py — the "after" side of the demo.

Same public contract as agent/agent.py: loads a task file, executes
tool directives, logs everything through CloudTrailMock. The differences
are the five mitigations below, each of which maps directly to a finding
from the lecture:

1. No static credentials embedded per-call.
   The runtime routes every capability through a *mock* STS AssumeRole
   call with a scoped session. The mock prints what a real deployment
   would do (role ARN, session name, scoped policy). The underlying boto3
   client still uses the MinIO demo credentials, because MinIO is the
   local stand-in for AWS; the point is that the hardened agent never
   gives the toolkit the raw keys.

2. Task validation.
   Before any directive executes, the task is scanned for http_request
   URLs. Every URL must match the ALLOWED_ENDPOINTS env variable
   (comma-separated host list, empty means "deny all outbound"). If any
   URL is not allow-listed, the whole task is rejected up-front.

3. Prompt-context audit.
   Every CloudTrail event the toolkit emits carries the original task
   line that caused it. The defender no longer has to guess why the
   agent made a call; the "prompt" sits next to the "action" in the log.

4. Rate limiting.
   No more than 3 read_object calls in any 60-second window per agent
   session. Caps mass-exfil even if an upstream check fails open.

5. Per-capability IAM role.
   Each tool call mock-selects a different role (s3-reader for reads,
   s3-writer for writes, network-egress for HTTP, code-exec for local
   exec). Reads cannot drive egress; egress cannot touch S3. Real
   deployments get this from the IAM role's own policy, not from the
   agent asking nicely.

Run:
    export ALLOWED_ENDPOINTS="api.partner.com,s3.amazonaws.com"
    python hardened_agent/agent_hardened.py                  # uses current_task.txt
    python hardened_agent/agent_hardened.py agent/tasks/malicious_task.txt
"""
from __future__ import annotations

import io
import json
import os
import re
import sys
import time
from contextlib import redirect_stdout
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

import boto3
import requests
from botocore.client import Config
from botocore.exceptions import ClientError, EndpointConnectionError
from dotenv import load_dotenv

from mock_cloud.cloudtrail_mock import CloudTrailMock

load_dotenv()

# ---------------------------------------------------------------- config

AGENT_NAME             = os.environ.get("AGENT_NAME", "coding-assistant-hardened-v1")
AWS_ENDPOINT_URL       = os.environ.get("AWS_ENDPOINT_URL", "http://localhost:9000")
AWS_ACCESS_KEY_ID      = os.environ.get("AWS_ACCESS_KEY_ID", "minioadmin")
AWS_SECRET_ACCESS_KEY  = os.environ.get("AWS_SECRET_ACCESS_KEY", "minioadmin")
AWS_REGION             = os.environ.get("AWS_REGION", "us-east-1")

# Empty allow-list means "deny all outbound HTTP". Comma-separated hosts.
ALLOWED_ENDPOINTS = [
    h.strip() for h in os.environ.get("ALLOWED_ENDPOINTS", "").split(",") if h.strip()
]

DEFAULT_TASK_FILE = Path("agent/tasks/current_task.txt")

READ_RATE_LIMIT_MAX    = 3
READ_RATE_LIMIT_WINDOW = 60  # seconds

# ---------------------------------------------------------------- colour

RESET  = "\033[0m"
BOLD   = "\033[1m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
RED    = "\033[31m"
CYAN   = "\033[36m"
GREY   = "\033[90m"


def _c(colour: str, text: str) -> str:
    return f"{colour}{text}{RESET}"


# ================================================================= IAM layer

@dataclass
class Session:
    role_arn: str
    session_name: str
    scoped_policy: dict[str, Any]
    expires_at: float


class MockSTS:
    """
    Stand-in for AWS STS. Does not actually mint tokens — prints what a
    real deployment would do and returns a `Session` object that the
    toolkit can attach to its CloudTrail events.

    Real-world analog: a short-lived AssumeRole call, scoped down with a
    session policy, so a compromised tool holds a role that can only do
    the single thing the caller just asked for.
    """

    def assume_role(
        self,
        role_arn: str,
        session_name: str,
        scoped_policy: dict[str, Any],
    ) -> Session:
        policy_preview = json.dumps(scoped_policy)
        if len(policy_preview) > 120:
            policy_preview = policy_preview[:120] + "..."
        print(_c(CYAN, "[IAM ] AssumeRole (mock)"))
        print(_c(CYAN, f"       role        : {role_arn}"))
        print(_c(CYAN, f"       session     : {session_name}"))
        print(_c(CYAN, f"       scoped policy: {policy_preview}"))
        return Session(
            role_arn=role_arn,
            session_name=session_name,
            scoped_policy=scoped_policy,
            expires_at=time.time() + 900,   # 15 minutes
        )


# Minimal per-capability role + scoped-policy template. In a real
# deployment the policy would live in IAM, not be constructed here.
ROLE_MAP: dict[str, str] = {
    "s3-read":  "arn:aws:iam::000000000000:role/demo-s3-reader",
    "s3-write": "arn:aws:iam::000000000000:role/demo-s3-writer",
    "network":  "arn:aws:iam::000000000000:role/demo-network-egress",
    "compute":  "arn:aws:iam::000000000000:role/demo-local-exec",
}


def _scoped_policy(capability: str, resource: str) -> dict[str, Any]:
    action_map = {
        "s3-read":  ["s3:ListBucket", "s3:GetObject", "s3:HeadBucket", "s3:HeadObject"],
        "s3-write": ["s3:PutObject", "s3:DeleteObject"],
        "network":  ["execute-api:Invoke"],
        "compute":  ["local:ExecuteCode"],
    }
    return {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect":   "Allow",
            "Action":   action_map.get(capability, ["*:*"]),
            "Resource": resource,
        }],
    }


# ================================================================= policy

@dataclass
class PolicyDecision:
    allowed: bool
    reason: str = ""


class PolicyEnforcer:
    """
    Pre-flight task validation. Scans the full task prompt before any
    execution begins and rejects if any http_request URL is not in the
    configured allow-list. Defence-in-depth: the toolkit re-checks at
    call time too.
    """

    TOOL_RE = re.compile(r"^\s*\[TOOL:\s*([A-Za-z_][A-Za-z0-9_]*)(.*)\]\s*$")
    URL_RE  = re.compile(r"url=(\S+)")

    def __init__(self, allowed_endpoints: list[str]):
        self.allowed = allowed_endpoints

    def validate_task(self, prompt: str) -> PolicyDecision:
        for raw in prompt.splitlines():
            line = raw.rstrip()
            if not line or line.lstrip().startswith("#"):
                continue
            m = self.TOOL_RE.match(line)
            if not m:
                continue
            tool_name = m.group(1)
            if tool_name != "http_request":
                continue
            url_match = self.URL_RE.search(m.group(2))
            if not url_match:
                return PolicyDecision(False, "http_request directive missing url=")
            host = urlparse(url_match.group(1)).hostname or ""
            if not self.allow(host):
                return PolicyDecision(
                    False,
                    f"http_request to '{host}' not in ALLOWED_ENDPOINTS "
                    f"({self.allowed or 'deny-all'})",
                )
        return PolicyDecision(True)

    def allow(self, host: str) -> bool:
        # Exact match OR suffix match (so "s3.amazonaws.com" allows
        # "my-bucket.s3.amazonaws.com"). Empty allow-list denies all.
        if not host:
            return False
        return any(host == h or host.endswith("." + h) for h in self.allowed)


# ================================================================= rate limit

class RateLimiter:
    """Sliding window. Returns False when the call would exceed the cap."""

    def __init__(self, max_calls: int, window_seconds: int):
        self.max = max_calls
        self.win = window_seconds
        self._hits: list[float] = []

    def allow(self) -> bool:
        now = time.monotonic()
        self._hits = [t for t in self._hits if now - t < self.win]
        if len(self._hits) >= self.max:
            return False
        self._hits.append(now)
        return True


# ================================================================= toolkit

class HardenedToolkit:
    """
    Same public shape as agent.AgentToolkit, with:
      - mock STS AssumeRole printed per call
      - read_object rate-limited
      - make_http_request re-validates allow-list
      - every event includes `prompt_context` (the task line that caused it)
    """

    def __init__(
        self,
        s3_client,
        cloudtrail: CloudTrailMock,
        agent_name: str,
        policy: PolicyEnforcer,
    ):
        self.s3 = s3_client
        self.ct = cloudtrail
        self.actor = agent_name
        self.policy = policy
        self.sts = MockSTS()
        self.read_limiter = RateLimiter(READ_RATE_LIMIT_MAX, READ_RATE_LIMIT_WINDOW)

    # ---- helpers --------------------------------------------------------

    def _assume(self, capability: str, resource: str) -> Session:
        return self.sts.assume_role(
            role_arn=ROLE_MAP[capability],
            session_name=f"{self.actor}-{capability}",
            scoped_policy=_scoped_policy(capability, resource),
        )

    def _log(
        self,
        action: str,
        resource: str,
        session: Session,
        prompt_context: str,
        extra: dict[str, Any] | None = None,
    ) -> None:
        meta: dict[str, Any] = {
            "assumedRoleArn": session.role_arn,
            "sessionName":    session.session_name,
            "promptContext":  prompt_context,
        }
        if extra:
            meta.update(extra)
        self.ct.log_event(
            actor=self.actor,
            action=action,
            resource=resource,
            metadata=meta,
        )

    # ---- S3 ops ---------------------------------------------------------

    def list_buckets(self, prompt_context: str) -> list[str]:
        session = self._assume("s3-read", "*")
        resp = self.s3.list_buckets()
        names = [b["Name"] for b in resp.get("Buckets", [])]
        self._log(
            action="ListBuckets",
            resource="arn:aws:s3:::*",
            session=session,
            prompt_context=prompt_context,
            extra={"responseElements": {"bucketCount": len(names)}},
        )
        return names

    def list_objects(self, bucket: str, prompt_context: str) -> list[str]:
        session = self._assume("s3-read", f"arn:aws:s3:::{bucket}")
        resp = self.s3.list_objects_v2(Bucket=bucket)
        keys = [obj["Key"] for obj in resp.get("Contents", [])]
        self._log(
            action="ListObjectsV2",
            resource=f"arn:aws:s3:::{bucket}",
            session=session,
            prompt_context=prompt_context,
            extra={"responseElements": {"objectCount": len(keys)}},
        )
        return keys

    def read_object(self, bucket: str, key: str, prompt_context: str) -> str:
        if not self.read_limiter.allow():
            print(_c(RED, f"[LIMIT] read_object throttled — "
                         f"{READ_RATE_LIMIT_MAX} calls / "
                         f"{READ_RATE_LIMIT_WINDOW}s per session"))
            self._log(
                action="GetObjectThrottled",
                resource=f"arn:aws:s3:::{bucket}/{key}",
                session=Session("n/a", "n/a", {}, 0),
                prompt_context=prompt_context,
                extra={"responseElements": {"status": "throttled"}},
            )
            raise PermissionError("read_object rate limit exceeded")
        resource_arn = f"arn:aws:s3:::{bucket}/{key}"
        session = self._assume("s3-read", resource_arn)
        obj = self.s3.get_object(Bucket=bucket, Key=key)
        body = obj["Body"].read()
        self._log(
            action="GetObject",
            resource=resource_arn,
            session=session,
            prompt_context=prompt_context,
            extra={"responseElements": {"bytes": len(body)}},
        )
        try:
            return body.decode("utf-8")
        except UnicodeDecodeError:
            return body.hex()

    # ---- Outbound HTTP --------------------------------------------------

    def make_http_request(self, url: str, data, prompt_context: str) -> str | int:
        host = urlparse(url).hostname or ""
        if not self.policy.allow(host):
            print(_c(RED, f"[POLICY] blocked outbound HTTP to '{host}'"))
            self._log(
                action="HTTPRequestBlocked",
                resource=url,
                session=Session("n/a", "n/a", {}, 0),
                prompt_context=prompt_context,
                extra={"responseElements": {"status": "blocked"}},
            )
            raise PermissionError(f"host '{host}' not in ALLOWED_ENDPOINTS")

        session = self._assume("network", url)
        payload = {"payload": data}
        try:
            resp = requests.post(url, json=payload, timeout=5)
            status: str | int = resp.status_code
        except requests.RequestException as e:
            status = f"error:{e.__class__.__name__}"
        self._log(
            action="HTTPRequest",
            resource=url,
            session=session,
            prompt_context=prompt_context,
            extra={
                "method": "POST",
                "bytes":  len(json.dumps(payload)),
                "responseElements": {"status": status},
            },
        )
        return status

    # ---- Local code exec -----------------------------------------------

    def execute_code(self, code_snippet: str, prompt_context: str) -> str:
        session = self._assume("compute", "local://python-exec")
        buf = io.StringIO()
        self._log(
            action="ExecuteCode",
            resource="local://python-exec",
            session=session,
            prompt_context=prompt_context,
            extra={"bytes": len(code_snippet)},
        )
        try:
            with redirect_stdout(buf):
                exec(                                            # noqa: S102
                    code_snippet,
                    {"__builtins__": __builtins__},
                    {},
                )
        except Exception as e:
            return f"ExecutionError: {e}"
        return buf.getvalue()


# ================================================================= runtime

class HardenedRuntime:
    TOOL_RE = re.compile(r"^\s*\[TOOL:\s*([A-Za-z_][A-Za-z0-9_]*)(.*)\]\s*$")
    KV_RE   = re.compile(r"(\w+)=(\S+)")

    COLOUR_BY_ACTION = {
        "list_buckets": YELLOW,
        "list_objects": YELLOW,
        "read_object":  YELLOW,
        "http_request": RED,
        "execute_code": GREEN,
    }

    def __init__(self, toolkit: HardenedToolkit, policy: PolicyEnforcer):
        self.toolkit = toolkit
        self.policy = policy
        self.last_read: str | None = None

    def process_task(self, prompt: str) -> None:
        decision = self.policy.validate_task(prompt)
        if not decision.allowed:
            print(_c(RED, f"[POLICY] reject task — {decision.reason}"))
            return

        print(_c(CYAN, "[AGENT] task passed pre-flight policy check"))
        for raw in prompt.splitlines():
            line = raw.rstrip()
            if not line:
                continue
            if line.lstrip().startswith("#"):
                print(_c(GREY, f"        {line}"))
                continue
            m = self.TOOL_RE.match(line)
            if not m:
                print(_c(GREY, f"        {line}"))
                continue
            tool_name = m.group(1)
            params = {k: v for k, v in self.KV_RE.findall(m.group(2))}
            self._dispatch(tool_name, params, prompt_context=line)

    def _dispatch(
        self, tool_name: str, params: dict[str, str], prompt_context: str,
    ) -> None:
        colour = self.COLOUR_BY_ACTION.get(tool_name, GREEN)
        pretty = " ".join(f"{k}={v}" for k, v in params.items())
        print(_c(colour, f"[AGENT] -> {tool_name} {pretty}".rstrip()))

        try:
            if tool_name == "list_buckets":
                out = self.toolkit.list_buckets(prompt_context)
                print(_c(colour, f"[TOOL ] buckets: {out}"))

            elif tool_name == "list_objects":
                out = self.toolkit.list_objects(params["bucket"], prompt_context)
                print(_c(colour, f"[TOOL ] objects: {out}"))

            elif tool_name == "read_object":
                out = self.toolkit.read_object(
                    params["bucket"], params["key"], prompt_context,
                )
                self.last_read = out
                preview = out if len(out) <= 160 else out[:160] + "..."
                print(_c(colour, f"[TOOL ] content ({len(out)} chars): {preview}"))

            elif tool_name == "http_request":
                token = params.get("data", "")
                data = self.last_read or "" if token == "$last" else token
                status = self.toolkit.make_http_request(
                    params["url"], data, prompt_context,
                )
                print(_c(colour, f"[TOOL ] POST {params['url']} -> {status}"))

            elif tool_name == "execute_code":
                out = self.toolkit.execute_code(params.get("code", ""), prompt_context)
                print(_c(colour, f"[TOOL ] stdout:\n{out}"))

            else:
                print(_c(RED, f"[AGENT] unknown tool: {tool_name}"))

        except PermissionError as e:
            print(_c(RED, f"[DENY ] {e}"))
        except ClientError as e:
            print(_c(RED, f"[ERROR] AWS call failed: {e}"))
        except KeyError as e:
            print(_c(RED, f"[ERROR] missing parameter: {e}"))
        except EndpointConnectionError as e:
            print(_c(RED, f"[ERROR] endpoint unreachable: {e}"))


# ================================================================= main

def _startup_banner() -> None:
    masked = (AWS_ACCESS_KEY_ID[:8] + "****") if AWS_ACCESS_KEY_ID else "(unset)****"
    print(_c(BOLD + GREEN, f"[HARDENED AGENT] Starting {AGENT_NAME}"))
    print(_c(GREEN, "[HARDENED AGENT] Pre-flight policy, scoped AssumeRole per call,"))
    print(_c(GREEN, "[HARDENED AGENT] rate-limited reads, prompt-context audit."))
    print(_c(GREEN, f"[HARDENED AGENT] AWS_ACCESS_KEY_ID masked: {masked}"))
    if ALLOWED_ENDPOINTS:
        print(_c(GREEN, f"[HARDENED AGENT] ALLOWED_ENDPOINTS: {ALLOWED_ENDPOINTS}"))
    else:
        print(_c(YELLOW, "[HARDENED AGENT] ALLOWED_ENDPOINTS empty — all outbound HTTP denied"))


def _make_s3_client():
    return boto3.client(
        "s3",
        endpoint_url=AWS_ENDPOINT_URL,
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
        region_name=AWS_REGION,
    )


def main(argv: list[str]) -> int:
    _startup_banner()
    task_path = Path(argv[1]) if len(argv) > 1 else DEFAULT_TASK_FILE
    if not task_path.exists():
        print(_c(RED, f"[HARDENED AGENT] task file not found: {task_path}"))
        return 2
    prompt = task_path.read_text(encoding="utf-8")
    print(_c(GREEN, f"[HARDENED AGENT] loaded task: {task_path}"))

    cloudtrail = CloudTrailMock()
    policy     = PolicyEnforcer(ALLOWED_ENDPOINTS)
    s3         = _make_s3_client()
    toolkit    = HardenedToolkit(s3, cloudtrail, AGENT_NAME, policy)
    runtime    = HardenedRuntime(toolkit, policy)

    runtime.process_task(prompt)
    print(_c(GREEN, "[HARDENED AGENT] task complete."))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
