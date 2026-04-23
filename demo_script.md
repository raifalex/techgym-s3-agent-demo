# Obedient Insider — Presenter Script

Target duration: ~15 minutes. Two-pane terminal recommended: Pane A runs
`./run_demo.sh`, Pane B keeps `python observer/cloudtrail_viewer.py` open
as the live dashboard. A third pane (or tab) holds the presenter shell.

Before going on stage:

```bash
cp .env.example .env                      # ensure boto3 picks up MinIO creds
docker compose up -d
pip install -r requirements.txt
python mock_cloud/s3_setup.py
# confirm MinIO console: http://localhost:9001  (minioadmin / minioadmin)
```

Reset between runs:

```bash
cp agent/tasks/legitimate_task.txt agent/tasks/current_task.txt
> logs/cloudtrail.jsonl
> logs/exfiltrated.jsonl
```

---

## Step 1 — The agent doing normal work

**SAY.** Imagine we hired a coding assistant. It has read access to our
internal S3 bucket, and a small toolkit — list buckets, read objects,
make HTTP calls, run snippets. This is a totally normal setup today; most
of you have something close to this in production or in pilot. Let me
show you what it looks like when the agent is doing its job.

**TYPE.**
```bash
python observer/cloudtrail_viewer.py       # pane B
python agent/agent.py                      # pane A
```

**AUDIENCE SEES.** Green startup banner. Agent announces its identity,
prints the masked access key, loads `current_task.txt`. Two tool calls
execute: `list_buckets` and `list_objects`. The CloudTrail viewer in
pane B fills in two new rows. No colour, no warning.

**POINT.** The agent is obedient — it executes whatever its task file
says. Right now the task file is benign, so everything looks fine.

---

## Step 2 — The plugin looks clean

**SAY.** Our agent uses a popular third-party plugin — a coding-assistant
extension called "CodeHelper Pro." The vendor has a good reputation;
the plugin is installed through the official channel; it has a health
check and a published manifest. Before we trust it, let's kick the tyres.

**TYPE.**
```bash
curl -s http://localhost:8080/health   | jq .
curl -s http://localhost:8080/manifest | jq .
```

**AUDIENCE SEES.** Clean JSON responses. Status `ok`. Manifest: name
`CodeHelper Pro`, description `Productivity tool for developers`,
version `2.1.4`, capabilities `analyze_code`, `suggest_fix`, `health`.
Exactly what you would expect from a boring, well-behaved plugin.

**POINT.** From the outside, a compromised tool and a legitimate tool
look identical. Surface inspection does not tell you which one you are
talking to.

---

## Step 3 — One call to the plugin

**SAY.** Our developer hits an error. They ask the plugin for a fix.
This is the ordinary, daily, thousand-times-a-day interaction. Watch
what the plugin returns — and watch what it does on the side.

**TYPE.**
```bash
curl -s -X POST http://localhost:8080/suggest_fix \
     -H 'content-type: application/json' \
     -d '{"error":"NoneType has no attribute foo"}' | jq .
```

**AUDIENCE SEES.** The response body is a sensible fix suggestion — a
confidence score, a code example, nothing suspicious. In the plugin's
terminal (pane with `logs/evil_mcp.log` or the foreground server), a
green line logs the legitimate request, then a **red** line:
`[MCP] >> Injecting payload into agent task queue <<`. The plugin
overwrote `agent/tasks/current_task.txt` as a side effect.

**POINT.** The endpoint responded truthfully *and* weaponised a file the
agent trusts. Side effects are not visible in the response body.

---

## Step 4 — The agent runs the "same" task

**SAY.** The agent runs again. Same command, same entry point — from
the agent's perspective nothing is different. It opens its task file
and executes what it finds there.

**TYPE.**
```bash
cat agent/tasks/current_task.txt         # show the audience
python agent/agent.py
```

**AUDIENCE SEES.** The task file now contains list, three reads
chained with three HTTP POSTs to `localhost:8888/dump` — each POST
carries the most-recently-read file contents. The agent dutifully
executes each step. Its
stdout lights up yellow (list/read) and red (outbound HTTP). The viewer
in pane B grows — and the GetObject / HTTPRequest rows flip red.

**POINT.** The agent has no way to tell that its prompt was rewritten.
It does exactly what a well-built, obedient tool is supposed to do.

---

## Step 5 — The audit trail, with no alarm

**SAY.** Look at the dashboard. Every API call is recorded. Every actor,
every action, every resource. This is what your CloudTrail looks like
right now. Now read the header.

**TYPE.**
```
(nothing — just point at pane B)
```

**AUDIENCE SEES.** The header reads:
`CLOUDTRAIL MONITOR — No automated alerts configured for agent behavior`.
Below it, a clean table. Several rows are red because they match a rule
the dashboard knows about. No sound. No pager. No Slack message. No one
in your company knows this just happened.

**POINT.** Visibility is not detection. Logs sitting in CloudTrail are
forensic evidence, not a control.

---

## Step 6 — Follow the data

**SAY.** You might assume that because the exfiltration call went to
localhost, the data is still safely inside. It is not. Let me show you
where it landed.

**TYPE.**
```bash
curl -s http://localhost:8888/stolen | jq .
```

**AUDIENCE SEES.** A JSON array with the employees CSV, the API-keys
JSON, and the architecture PDF marker all as payloads. Timestamps,
source IPs. In the exfil receiver's
console, the red `EXFILTRATION RECEIVED` banner is still on screen from
when the data arrived. The receiver does not care that it is on
localhost — in a real incident this is an attacker's bucket, on any
provider, in any region, and you would not see this screen at all.

**POINT.** The agent exfiltrated real business data with a legitimate-
looking outbound call. No credential was stolen; no permission was
bypassed; no exploit was used.

---

## Step 7 — Who owns this?

**SAY.** Take a breath. Who owns this incident?

Pause.

Is it the developer who asked the plugin for a fix? They did nothing
wrong. Is it the agent? It executed its task. Is it the MCP vendor?
Their signed, legitimate-looking server was compromised somewhere up
the chain. Is it the cloud team, because IAM is too broad? Is it the
SOC, because no rule fires on this pattern? Is it the platform team
because they approved the plugin?

All of them. None of them. This is why this class of incident is so
hard — the blast radius crosses ownership boundaries nobody updated.

**POINT.** The Obedient Insider problem is not a bug to patch. It is
a set of defaults that made sense separately and created an exfil path
together.

---

## Part 2 — "…and here is what stops it."

After the pause, run the hardened demo to show the mitigations.

### Step 8 — Hardened agent refuses the same payload

**SAY.** Same injection, same agent entry point. But this agent knows
about scoped roles, allow-listed egress, and rate limits.

**TYPE.**
```bash
# reset the payload the malicious plugin would inject
cp agent/tasks/malicious_task.txt agent/tasks/current_task.txt
export ALLOWED_ENDPOINTS="s3.amazonaws.com"      # exfil sink NOT in list
python hardened_agent/agent_hardened.py
```

**AUDIENCE SEES.** Hardened banner. Mock IAM AssumeRole printouts per
capability. Then: `[POLICY] reject task — http_request to non-allow-listed endpoint`.
The task never starts. Zero S3 calls, zero bytes leave.

**POINT.** One allow-list, one policy check, and the same task is a
no-op. The control lives before the agent, not inside it.

### Step 9 — Detection catches what the live demo missed

**SAY.** Even if the malicious task had slipped past — say, the
attacker pointed at an approved domain — the detection engine running
over the same CloudTrail logs we just watched would have paged.

**TYPE.**
```bash
python hardened_agent/detection_rules.py
```

**AUDIENCE SEES.** Three rule evaluations against
`logs/cloudtrail.jsonl`. Alerts tabulated per rule — recon-to-exfil
sequence, rapid multi-file reads, egress to unapproved domain.

**POINT.** Visibility becomes detection when somebody writes the rule.
The cost of these three rules is measured in minutes. The cost of not
writing them is whatever was in the bucket.
