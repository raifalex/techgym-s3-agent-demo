"""
hardened_agent — "what stops the attack" counterpart to ./agent/.

Two modules:
  - agent_hardened.py  : same toolkit as the base agent, with mitigations
                         layered in (scoped assume-role per capability,
                         allow-list validation, rate limiting, prompt-context
                         audit).
  - detection_rules.py : post-hoc rules engine over logs/cloudtrail.jsonl.

Both ride on the same CloudTrailMock emitter as the base agent so the
dashboard and rules see the hardened runs the same way they see the
vulnerable ones.
"""
