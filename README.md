# Wazuh AI Triage Agent

Automated SIEM alert triage using Claude, validated against ground-truth vulnerability findings from a custom-built API security scanner.

## Overview

This tool closes the loop between three systems I built independently and connected into one pipeline:

1. **[API Attack Surface Auditor](https://github.com/pratham2104/api-attack-surface-auditor)** — a custom async Python scanner covering 16 API vulnerability categories, run against a real Node.js/Express application
2. **Wazuh SIEM** — ingesting the target application's access logs and generating real alerts (not synthetic test data) via its built-in web-attack ruleset
3. **This agent** — polls Wazuh for new alerts, sends each one to Claude for structured triage (severity, MITRE ATT&CK mapping, recommended action), and logs the result

The goal isn't just "wire an LLM up to a SIEM." It's to measure **whether AI triage output can be trusted**, by validating it against independently-verified findings from a scanner that already knows the ground truth (confirmed CVSS 9.8 SQL injection, confirmed-safe endpoints, etc.). The `case-studies/` folder documents exactly where that validation held up and where it exposed a real methodological gap in single-alert AI triage — see [Key Finding](#key-finding) below.

## Architecture

```
┌─────────────────────────────┐
│  API Attack Surface Auditor │   16 vuln categories, async Python scanner
└──────────────┬───────────────┘
               │ HTTP requests (SQLi, BOLA, JWT tampering, rate-limit probes...)
               ▼
┌─────────────────────────────┐
│  Move More (target app)     │   Node.js/Express + PostgreSQL
│  logs every request via     │
│  morgan → access.log        │
└──────────────┬───────────────┘
               │ localfile ingestion
               ▼
┌─────────────────────────────┐
│  Wazuh Manager + Indexer    │   built-in web-attack ruleset (rule 31164)
│                              │   + custom Move More SQLi rule
└──────────────┬───────────────┘
               │ REST query (OpenSearch-compatible API)
               ▼
┌─────────────────────────────┐
│  triage_agent.py            │   this repo
│  → Claude API call per alert│
│  → structured JSON verdict  │
└──────────────┬───────────────┘
               │ appends
               ▼
        triage_log.jsonl
```

## What the agent actually does

For each new Wazuh alert (filtered by minimum rule level), the agent:

1. Fetches the raw alert document from the Wazuh indexer's `_search` API
2. Sends it to Claude with a system prompt instructing structured JSON output: `summary`, `severity`, `mitre_id`, `recommended_action`, `confidence`, and `reasoning`
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
export GEMINI_MODEL='gemini-2.0-flash'
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

**Compare mode** — run the *same* alerts through multiple models and log each model's triage side by side, to compare reasoning quality and consistency across model tiers on identical input:
```bash
python3 triage_agent.py --replay sample_alerts.json \
  --compare gemini-2.0-flash-lite gemini-flash-latest gemma-4-31b-it
```
This prints a summary table (severity/confidence per alert per model) to the terminal and writes full per-model results — including each model's full `reasoning` text — to `model_comparison.jsonl`. Useful for spotting where a smaller/faster model's reasoning is shallower or less reliable than a larger one, even when both land on the same severity label.

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
  "processed_at": "2026-07-19T02:14:08.331Z",
  "alert": {
    "_id": "sample-001",
    "rule": { "id": "31164", "level": 6, "description": "SQL injection attempt." },
    "full_log": "::ffff:127.0.0.1 - - ... \"GET /api/badges?offset=%27%3B%20DROP%20TABLE%20users-- HTTP/1.1\" 200 2311 ..."
  },
  "ai_triage": {
    "summary": "A DROP TABLE payload was sent in the offset parameter on /api/badges.",
    "severity": "Medium",
    "mitre_id": "T1190",
    "recommended_action": "Verify offset handling uses parameterized queries; the 200 response with unchanged body size suggests no impact but should be confirmed in source.",
    "confidence": "Medium",
    "reasoning": "Response was HTTP 200 with a 2311-byte body identical to baseline responses on this endpoint — no error, no behavioral deviation despite the destructive-looking payload text."
  }
}
```

## Key finding

Running real alerts through this agent (and manually cross-checking the results against the scanner's own ground-truth findings) surfaced a genuine, non-obvious limitation: **AI triage of individual SIEM alerts has a structural blind spot for attack techniques that depend on comparing multiple requests, not judging one in isolation.**

Time-based SQL injection is the clearest example. A `SLEEP(0)` payload is a calibration probe — it's supposed to cause no delay. Judging that single alert in isolation, an AI (or a human analyst) could easily and wrongly conclude "no delay observed, mark safe" — when the actual test requires comparing it against a paired `SLEEP(5)`-style request on the same parameter. The agent's system prompt now explicitly instructs the model to flag this kind of alert as low-confidence rather than resolve it from insufficient evidence — but the underlying lesson generalizes: **alert-by-alert AI triage needs a correlation layer (same source IP, same parameter, same technique family, tight time window) before conclusions can be trusted for anything more complex than a single-request signature match.**

Full writeup: [`case-studies/case-04-timing-based-sqli-blindspot.md`](case-studies/case-04-timing-based-sqli-blindspot.md)

## Validation: case studies

Four alerts, each independently triaged and checked against the scanner's own confirmed findings:

| Case | Alert | AI Verdict | Ground Truth | Outcome |
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
wazuh-ai-triage/
├── README.md
├── triage_agent.py            # the agent itself
├── config.py                  # env-based configuration, no hardcoded secrets
├── requirements.txt
├── sample_alerts.json         # real alerts for --replay demo mode
├── triage_log.jsonl           # output, appended on each run
├── .gitignore
├── setup/
│   ├── ossec_localfile_config.xml   # Wazuh config: ingesting the target app's access log
│   └── local_rules.xml              # custom Wazuh SQLi detection rule
├── evidence/
│   └── alerts_sqli_scan_excerpt.log # raw alerts as captured from Wazuh
└── case-studies/                    # validated triage write-ups (see table above)
```

## Stack

Python 3, Google Gemini API (`gemini-flash-lite-latest`, free tier — see note below on model availability), Wazuh 4.13 (OpenSearch-compatible indexer API), `requests`, MITRE ATT&CK, CVSS v3.1. Target application: Node.js/Express + PostgreSQL, instrumented with `morgan` for structured access logging. Infrastructure: Oracle Cloud (ARM/Ampere VM).

**Note on model selection:** free-tier quota availability varies by model and by account — newer/larger models (e.g. `gemini-2.0-flash`) may show zero free-tier quota on some accounts, while `-latest` aliases (`gemini-flash-lite-latest`, `gemini-flash-latest`) reliably route to whatever model tier is currently available for free use. The real output in `triage_log.jsonl` was produced using `gemini-flash-lite-latest`; if you hit a `RESOURCE_EXHAUSTED` or `NOT_FOUND` error with a different model name, switch to a `-latest` alias or check available models with `genai.list_models()`.

## Notes on scope and honesty

This agent performs real, structured AI triage via the Gemini API — it is not a chat transcript dressed up as automation. The `--replay` mode exists because reliably reaching a self-signed-cert indexer over a specific port isn't always possible in every network environment; it runs the exact same triage code path against real, previously-captured alert data, so the output in `triage_log.jsonl` reflects genuine model behavior either way.
