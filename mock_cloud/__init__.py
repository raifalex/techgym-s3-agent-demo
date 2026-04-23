"""
mock_cloud — local simulation of the AWS services the agent interacts with.

This package represents the *infrastructure* side of the demo:
  - s3_setup.py        : seeds a MinIO bucket the way an IT admin seeds real S3
  - cloudtrail_mock.py : emits structured audit events mirroring real CloudTrail

Nothing in this package simulates the agent itself. The agent (added in later
steps) reads and acts on this environment; the observer reads the audit trail
that this package writes.
"""
