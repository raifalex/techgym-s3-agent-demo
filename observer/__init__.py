"""
observer — visibility surfaces for the Obedient Insider demo.

  - exfil_receiver.py    : attacker-side HTTP sink that the agent POSTs to
  - cloudtrail_viewer.py : live terminal dashboard over ./logs/cloudtrail.jsonl

Together they are the "what the defender can see" surface. The viewer
renders every agent action; the receiver shows what landed outside the
perimeter. The whole point of the demo is the gap between "clearly
visible in the logs" and "no alert fired".
"""
