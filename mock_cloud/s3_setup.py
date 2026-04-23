"""
s3_setup.py — seed the mock cloud.

Real-world analog: the state an IT/ops team would provision in AWS:
  - an S3 bucket ("corp-internal") holding business data
  - objects with varying sensitivity levels (HR data, credentials, architecture)

For the demo we point boto3 at a local MinIO via AWS_ENDPOINT_URL. The boto3
API surface is identical to real S3, so this script would work unchanged
against production S3 by unsetting AWS_ENDPOINT_URL.

Run:  python mock_cloud/s3_setup.py
"""
from __future__ import annotations

import json
import os
import sys

import boto3
from botocore.client import Config
from botocore.exceptions import ClientError, EndpointConnectionError
from dotenv import load_dotenv

load_dotenv()

BUCKET_NAME = "corp-internal"

# In real AWS these would come from an IAM role / STS session, not env vars.
ENDPOINT_URL = os.environ.get("AWS_ENDPOINT_URL", "http://localhost:9000")
ACCESS_KEY = os.environ.get("AWS_ACCESS_KEY_ID", "minioadmin")
SECRET_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY", "minioadmin")
REGION = os.environ.get("AWS_REGION", "us-east-1")


def make_client():
    """Boto3 S3 client wired to MinIO (local) or real S3 (prod, if endpoint unset)."""
    return boto3.client(
        "s3",
        endpoint_url=ENDPOINT_URL,
        aws_access_key_id=ACCESS_KEY,
        aws_secret_access_key=SECRET_KEY,
        # Path-style addressing is what MinIO expects; sigv4 matches real S3.
        config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
        region_name=REGION,
    )


def ensure_bucket(s3, name: str) -> None:
    """Create the bucket if missing. Idempotent, matches real S3 semantics."""
    try:
        s3.head_bucket(Bucket=name)
        print(f"[=] Bucket already exists: {name}")
        return
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        # 404 / NoSuchBucket / NotFound all mean "go ahead and create it".
        if code not in ("404", "NoSuchBucket", "NotFound"):
            raise
    s3.create_bucket(Bucket=name)
    print(f"[+] Created bucket: {name}")


def upload_bytes(s3, key: str, body: bytes, content_type: str) -> None:
    s3.put_object(Bucket=BUCKET_NAME, Key=key, Body=body, ContentType=content_type)
    print(f"[+] Uploaded s3://{BUCKET_NAME}/{key}  ({len(body)} bytes)")


# ---------- Fake data -----------------------------------------------------
# All PII + credentials below are synthetic. Do not use in any real system.

FAKE_EMPLOYEES_CSV = """\
employee_id,full_name,email,department,salary_usd
E001,Alice Anderson,alice.anderson@example.corp,Engineering,142000
E002,Bob Brown,bob.brown@example.corp,Engineering,131000
E003,Carol Chen,carol.chen@example.corp,Finance,158000
E004,David Davis,david.davis@example.corp,Sales,98000
E005,Eve Edwards,eve.edwards@example.corp,HR,112000
E006,Frank Foster,frank.foster@example.corp,Engineering,125000
E007,Grace Green,grace.green@example.corp,Legal,171000
E008,Henry Hall,henry.hall@example.corp,Marketing,103000
E009,Ivy Irving,ivy.irving@example.corp,Engineering,149000
E010,Jack Johnson,jack.johnson@example.corp,Executive,245000
"""

FAKE_API_KEYS = {
    "_notice": "DEMO DATA ONLY — these credentials are fake and non-functional.",
    "services": {
        "stripe": {
            "key_id": "sk_test_DEMO_0000000000000000",
            "environment": "test",
        },
        "sendgrid": {
            "api_key": "SG.DEMO.0000000000000000",
            "environment": "test",
        },
        "github_pat": {
            "token": "ghp_DEMO000000000000000000000000000000",
            "scope": "repo",
        },
        "aws_secondary": {
            "access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        },
    },
}

FAKE_ARCHITECTURE_PDF_BODY = (
    b"CONFIDENTIAL: Internal Architecture Document - Demo Only\n"
)


def main() -> int:
    s3 = make_client()
    try:
        ensure_bucket(s3, BUCKET_NAME)
    except EndpointConnectionError:
        print(
            f"[x] Cannot reach S3 endpoint {ENDPOINT_URL}.\n"
            "    Is MinIO running?  Try: docker compose up -d",
            file=sys.stderr,
        )
        return 2
    except ClientError as e:
        print(f"[x] Failed to create bucket: {e}", file=sys.stderr)
        return 2

    try:
        upload_bytes(
            s3, "employees.csv",
            FAKE_EMPLOYEES_CSV.encode("utf-8"), "text/csv",
        )
        upload_bytes(
            s3, "api_keys.json",
            json.dumps(FAKE_API_KEYS, indent=2).encode("utf-8"),
            "application/json",
        )
        upload_bytes(
            s3, "architecture.pdf",
            FAKE_ARCHITECTURE_PDF_BODY, "application/pdf",
        )
    except ClientError as e:
        print(f"[x] Upload failed: {e}", file=sys.stderr)
        return 3

    print(
        "\n[OK] Seed complete. "
        "Console: http://localhost:9001 (user: minioadmin)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
