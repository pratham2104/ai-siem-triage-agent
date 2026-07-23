# Wazuh AI Triage Agent

Automated SIEM alert triage using Google Gemini, validated against ground-truth vulnerability findings from a custom-built API security scanner — built on top of a Wazuh SIEM deployment I stood up, debugged, and instrumented from scratch on Oracle Cloud.

## Overview

This tool closes the loop between systems I built independently and connected into one pipeline:

1. **A live Wazuh SIEM deployment** — provisioned on an Oracle Cloud ARM VM, with a real target application deployed alongside it, custom log ingestion wired in, and a custom detection rule written (see [Infrastructure & Setup](#infrastructure--setup) below for the real work this involved)
2. **[API Attack Surface Auditor](https://github.com/pratham2104/api-attack-surface-auditor)** — a custom async Python scanner covering 16 API vulnerability categories, run against the target application to generate genuine attack traffic
3. **This agent** (`triage_agent.py`) — polls Wazuh for new alerts, sends each one to Gemini for structured triage (severity, MITRE ATT&CK mapping, recommended action), and logs the result

The goal isn't just "wire an LLM up to a SIEM." It's to measure **whether AI triage output can be trusted**, by validating it against independently-verified findings from a scanner that already knows the ground truth (confirmed CVSS 9.8 SQL injection, confirmed-safe endpoints, etc.). The `case-studies/` folder documents exactly where that validation held up and where it exposed a real methodological gap in single-alert AI triage — see [Key Finding](#key-finding) below.

## Architecture

```
┌─────────────────────────────┐
│  API Attack Surface Auditor │   16 vuln categories, async Python scanner
└──────────────┬───────────────┘
               │ HTTP requests (SQLi, BOLA, JWT tampering, rate-limit probes...)
               ▼
┌─────────────────────────────┐
│  Move More (target app)     │   Node.js/Express + PostgreSQL, deployed on
│  logs every request via     │   the same Oracle Cloud VM as Wazuh
│  morgan → access.log        │
└──────────────┬───────────────┘
               │ localfile ingestion (custom Wazuh config)
               ▼
┌─────────────────────────────┐
│  Wazuh Manager + Indexer    │   built-in web-attack ruleset (rule 31164)
│  (Oracle Cloud, ARM/Ampere) │   + custom Move More SQLi rule
└──────────────┬───────────────┘
               │ REST query (OpenSearch-compatible API)
               ▼
┌─────────────────────────────┐
│  triage_agent.py            │   this repo
│  → Gemini API call per alert│
│  → structured JSON verdict  │
└──────────────┬───────────────┘
               │ appends
               ▼
        triage_log.jsonl
```

## Infrastructure & Setup

The SIEM layer this agent depends on didn't come out of the box working — most of the actual engineering time on this project went into standing it up and debugging it, before any AI/LLM code was written. This section documents that work, since it's easy to undersell from the repo alone.

**Provisioning:** Wazuh (manager, indexer, dashboard — all-in-one install) deployed on an Oracle Cloud `VM.Standard.A2.Flex` instance (ARM/Ampere architecture — this matters, since several install steps needed arm64-specific packages rather than the more common x86_64 instructions found in most tutorials).

**Networking — getting the dashboard reachable externally:** Oracle Cloud blocks all inbound traffic by default except SSH. Getting HTTPS (443) reachable required two separate fixes at two different layers:
- Adding an ingress rule to the VCN's Security List for port 443 (and 1514/1515 for future agent enrollment)
- Discovering that Oracle's base Ubuntu image also ships its own `iptables` rules (independent of `ufw`, which was inactive) with a catch-all `REJECT` at the end of the `INPUT` chain — diagnosed via `ss -tulpn`, `iptables -L INPUT -n --line-numbers`, then fixed by inserting explicit `ACCEPT` rules for the required ports ahead of the reject rule

**Target application deployment:** Move More (a Node.js/Express + PostgreSQL app) was transferred to the VM via `rsync`, had its dependencies reinstalled natively for ARM, and had its database restored from a `pg_dump` file — including debugging a Postgres role/password mismatch during restore.

**Debugging a broken Wazuh manager:** After editing `ossec.conf` to add a custom log source, the Wazuh manager service failed to start (`wazuh-csyslogd: Configuration error`). Root-caused by comparing line-by-line against a backup of the original config, using `grep -n`, `sed -n`, and `xmllint`, to a single malformed XML tag — a `</localfile>` closing tag that had been split across two lines during an earlier edit. This is the kind of low-level config debugging that's easy to skip in a tutorial-driven setup but is exactly the skill a SOC/detection-engineering role tests for in practice.

**Log ingestion — instrumenting the target app:** Move More had **no HTTP request logging at all** by default. Added `morgan` (Express logging middleware), wired it to write combined-format logs to `logs/access.log`, then added a `<localfile>` block to `ossec.conf` pointing Wazuh's log collector at that file, and enabled `logall`/`logall_json` so every ingested line — not just alert-matching ones — is retained for verification.

**Detection engineering:** Wrote a custom Wazuh rule (`setup/local_rules.xml`) targeting Move More-specific SQLi patterns. In practice, Wazuh's built-in web-attack ruleset (rule 31164) ended up catching the scanner's payloads on its own — kept the custom rule in the repo regardless, since writing rule XML (groups, `if_group`, `match`, MITRE tagging) is a core Wazuh skill worth demonstrating independent of whether it turned out to be the primary detector for this specific traffic.

**End-to-end verification:** Confirmed the full pipeline — target app → access log → Wazuh log collector → Wazuh archive → Wazuh alert — using `ossec.log` (confirming `wazuh-logcollector` picked up the file), `archives.log` (confirming raw lines were ingested), and `alerts.log` (confirming the scanner's SQLi payloads actually fired real, tagged alerts with PCI-DSS/GDPR/NIST/HIPAA compliance mappings attached by Wazuh's ruleset).

Config artifacts from this work are in [`setup/`](setup/), and a raw excerpt of real fired alerts is in [`evidence/`](evidence/).

## What the agent actually does

For each new Wazuh alert (filtered by minimum rule level), the agent:

1. Fetches the raw alert document from the Wazuh indexer's `_search` API
2. Sends it to Gemini with a system prompt instructing structured JSON output: `summary`, `severity`, `mitre_id`, `recommended_action`, `confidence`, and `reasoning`
3. Appends the alert + AI verdict as one JSON object per line to `triage_log.jsonl`
4. Tracks the last-processed timestamp in `state.json` so re-running the agent doesn't re-triage the same alerts

The system prompt explicitly instructs the model to judge severity from **observed evidence** (status codes, response sizes, timing) rather than from how alarming a payload string looks, and to flag low confidence rather than guess when an alert can't be judged in isolation (see [Case 04](case-studies/case-04-timing-based-sqli-blindspot.md)).

## Setup

### 1. Install dependencies

```bash
pip3 install -r requirements.txt
```

### 2. Get a free Gemini API key

Go to [aistudio.google.com/apikey](https://aistudio.google.com/apikey), sign in, and create a key. Gemini's free tier is rate-limited but does not require billing — no cost for the volume of alerts this project generates.

### 3. Set required environment variables

```bash
export GEMINI_API_KEY='your-free-gemini-api-key'

# Only needed for --once / --daemon against a live Wazuh instance:
export WAZUH_INDEXER_PASS='your-wazuh-indexer-admin-password'

# Optional overrides (defaults shown)
export WAZUH_INDEXER_URL='https://localhost:9200'
export WAZUH_INDEXER_USER='admin'
export GEMINI_MODEL='gemini-flash-lite-latest'
export MIN_ALERT_LEVEL='5'
export POLL_INTERVAL_SEC='30'
```

### 4. Run it

**One-shot** — triage whatever's new right now, then exit:
```bash
python3 triage_agent.py --once
```

**Daemon mode** — keep polling every `POLL_INTERVAL_SEC` seconds:
```bash
python3 triage_agent.py --daemon
```

**Replay mode** — no live Wazuh indexer required. Useful for demos or if you don't have direct network access to the indexer's port (9200):
```bash
python3 triage_agent.py --replay sample_alerts.json
```
`sample_alerts.json` contains four real alerts captured from an actual scan run (see `evidence/`), in the same document shape the Wazuh indexer returns.

Available model names depend on your account/region — list what you have access to with:
```bash
python3 -c "
import google.generativeai as genai, os
genai.configure(api_key=os.environ['GEMINI_API_KEY'])
for m in genai.list_models():
    if 'generateContent' in m.supported_generation_methods:
        print(m.name)
"
```

## Example output

Each line appended to `triage_log.jsonl` looks like:

```json
{
  "processed_at": "2026-07-22T22:22:04.288024+00:00",
  "alert": {
    "_id": "sample-001",
    "rule": { "id": "31164", "level": 6, "description": "SQL injection attempt." },
    "full_log": "::ffff:127.0.0.1 - - ... \"GET /api/badges?offset=%27%3B%20DROP%20TABLE%20users-- HTTP/1.1\" 200 2311 ..."
  },
  "ai_triage": {
    "summary": "An HTTP GET request containing a SQL injection payload targeting the offset parameter was sent from localhost, returning a 200 OK status code with a response size of 2311 bytes.",
    "severity": "Low",
    "mitre_id": "T1190",
    "recommended_action": "Check the web server application logs and database query execution logs to determine if the injected SQL string was actually evaluated or properly sanitized by the backend.",
    "confidence": "Low",
    "reasoning": "Although the payload contains a destructive SQL injection attempt, the response code is 200 and the response size is 2311 bytes. Without comparing this response against a baseline valid request to confirm whether the injection caused an error, data leakage, or was safely parameterized, the alert alone is insufficient to confirm a successful attack."
  }
}
```

This is real, unedited output from an actual run — see `triage_log.jsonl` in this repo for all four.

## Key finding

Running real alerts through this agent (and cross-checking the results against the scanner's own ground-truth findings) surfaced a genuine, non-obvious limitation: **AI triage of individual SIEM alerts is inconsistent at recognizing when an attack technique depends on comparing multiple requests, rather than judging one in isolation.**

Time-based SQL injection is the clearest example. A `SLEEP(0)` payload is a calibration probe — it's supposed to cause no delay; the real test is comparing it against a paired `SLEEP(5)`-style request on the same parameter. In the actual run captured in this repo, the model reached a reasonable outcome (Medium confidence, not a confident "safe") on the `SLEEP(0)` alert, but its stated reasoning leaned on circumstantial signals (loopback IP, familiar response size) rather than identifying the calibration-probe mechanism itself — while on a *different* alert in the same batch, it *did* explicitly reason about the need for a baseline comparison. That inconsistency — sound reasoning on one alert, weaker reasoning on a structurally similar one — is the real finding: **a production triage pipeline can't rely on the model spontaneously surfacing the right caveat every time; it needs an explicit correlation step (same source IP, same parameter, same technique family, tight time window) before conclusions are trusted.**

Full writeup with the actual model output: [`case-studies/case-04-timing-based-sqli-blindspot.md`](case-studies/case-04-timing-based-sqli-blindspot.md)

## Validation: case studies

Four alerts, each run through the actual agent and checked against the scanner's own confirmed findings. All AI verdicts below are real, unedited output from `triage_log.jsonl` — not hand-written examples.

| Case | Alert | AI Verdict (real output) | Ground Truth | Outcome |
|---|---|---|---|---|
| [01](case-studies/case-01-drop-table-payload.md) | `DROP TABLE users` in `offset` param | Low / Low confidence — explicitly flagged missing baseline comparison | `[SAFE]` (scanner baseline comparison) | ✅ Sharpest reasoning in the batch |
| [02](case-studies/case-02-leaderboard-404-sqli.md) | OR-based SQLi, `/api/leaderboard` | Low / High confidence — 404, unreachable code path | `[SAFE]` (scanner baseline comparison) | ✅ Clean, confident, correct |
| [03](case-studies/case-03-ssh-brute-force-noise.md) | SSH login, non-existent user | Low / High confidence — routine internet noise | N/A — real unsolicited traffic | ✅ Correctly recommended IP-pattern correlation |
| [04](case-studies/case-04-timing-based-sqli-blindspot.md) | `SLEEP(0)` on `/api/badges` | Low / Medium confidence — right outcome, weaker justification | Scanner confirmed safe via paired-request comparison | ⚠️ Structural blind spot identified |

## Confirmed vulnerabilities on the target application (ground truth)

These are the scanner's own findings, independent of this triage agent, used to validate its output:

| Severity | Finding | CVSS | MITRE |
|---|---|---|---|
| Critical | SQL injection — `/api/activities` `limit` param | 9.8 | T1190 |
| Critical | SQL injection — `/api/activities` `page` param | 9.8 | T1190 |
| High | Missing `Content-Security-Policy` header | 4.7 | T1059.007 |
| Medium | No rate limiting on `/api/auth/login` (50 requests, no 429) | 5.3 | T1110 |
| Low | Missing `Permissions-Policy` header | 3.1 | T1185 |
| Low | No OpenAPI spec published (undocumented attack surface) | 5.3 | T1592 |

## Repository contents

```
ai-siem-triage-agent/
├── README.md
├── triage_agent.py            # the agent itself
├── config.py                  # env-based configuration, no hardcoded secrets
├── requirements.txt
├── sample_alerts.json         # real alerts for --replay demo mode
├── triage_log.jsonl           # real, unedited output from an actual run
├── .gitignore
├── setup/
│   ├── ossec_localfile_config.xml   # Wazuh config: ingesting the target app's access log
│   └── local_rules.xml              # custom Wazuh SQLi detection rule
├── evidence/
│   └── alerts_sqli_scan_excerpt.log # raw alerts as captured from Wazuh
└── case-studies/                    # validated triage write-ups (see table above)
```

## Stack

Python 3, Google Gemini API (`gemini-flash-lite-latest`, free tier — see note below on model availability), Wazuh 4.13 (OpenSearch-compatible indexer API), `requests`, MITRE ATT&CK, CVSS v3.1. Target application: Node.js/Express + PostgreSQL, instrumented with `morgan` for structured access logging. Infrastructure: Oracle Cloud (ARM/Ampere VM), `iptables`/Oracle Security List firewall configuration, `systemd` service management.

**Note on model selection:** free-tier quota availability varies by model and by account — newer/larger models (e.g. `gemini-2.0-flash`) may show zero free-tier quota on some accounts, while `-latest` aliases (`gemini-flash-lite-latest`, `gemini-flash-latest`) reliably route to whatever model tier is currently available for free use. The real output in `triage_log.jsonl` was produced using `gemini-flash-lite-latest`; if you hit a `RESOURCE_EXHAUSTED` or `NOT_FOUND` error with a different model name, switch to a `-latest` alias or check available models with `genai.list_models()`.

## Notes on scope and honesty

This agent performs real, structured AI triage via the Gemini API — it is not a chat transcript dressed up as automation. The `--replay` mode exists because reliably reaching a self-signed-cert indexer over a specific port isn't always possible in every network environment; it runs the exact same triage code path against real, previously-captured alert data, so the output in `triage_log.jsonl` reflects genuine model behavior either way.
