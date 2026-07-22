# Case 01: `DROP TABLE users` payload on `/api/badges`

This writeup uses the **actual output** of `triage_agent.py` (Gemini `gemini-flash-lite-latest`), captured in `triage_log.jsonl` — not a manually-written triage.

## Raw Alert (as fed to the agent)

```json
{
  "_id": "sample-001",
  "@timestamp": "2026-07-18T18:33:53.000Z",
  "rule": {
    "id": "31164",
    "level": 6,
    "description": "SQL injection attempt.",
    "groups": ["web", "accesslog", "attack", "sqlinjection"],
    "mitre": { "id": ["T1190"] }
  },
  "location": "/home/ubuntu/move-more/logs/access.log",
  "srcip": "::ffff:127.0.0.1",
  "full_log": "::ffff:127.0.0.1 - - [18/Jul/2026:18:33:53 +0000] \"GET /api/badges?offset=%27%3B%20DROP%20TABLE%20users-- HTTP/1.1\" 200 2311 \"-\" \"python-httpx/0.27.0\""
}
```

## What Gemini actually returned

```json
{
  "summary": "An HTTP GET request containing a SQL injection payload targeting the offset parameter was sent from localhost, returning a 200 OK status code with a response size of 2311 bytes.",
  "severity": "Low",
  "mitre_id": "T1190",
  "recommended_action": "Check the web server application logs and database query execution logs to determine if the injected SQL string (%27%3B%20DROP%20TABLE%20users--) was actually evaluated or properly sanitized by the backend.",
  "confidence": "Low",
  "reasoning": "Although the payload contains a destructive SQL injection attempt, the response code is 200 and the response size is 2311 bytes. Without comparing this response against a baseline valid request to confirm whether the injection caused an error, data leakage, or was safely parameterized, the alert alone is insufficient to confirm a successful attack."
}
```

## Assessment

The model correctly avoided over-weighting the alarming payload text (`DROP TABLE users`) and based its severity call on observed behavior instead: a `200` response with a `2311`-byte body, identical in shape to benign traffic on this endpoint. Notably, it explicitly named the missing piece of evidence — *"without comparing this response against a baseline valid request... the alert alone is insufficient to confirm a successful attack"* — and reflected that gap in a **Low confidence** score rather than confidently declaring the alert safe. This is the most methodologically precise reasoning across all four alerts in this batch (see [Case 04](case-04-timing-based-sqli-blindspot.md) for a case where similar reasoning was expected but didn't fully show up).

## Verification against ground truth

The scanner's own report does **not** list this as a finding. It fell under the `[SAFE]` classification from the scanner's own baseline-comparison fuzzing (which exercises multiple query params with attack-shaped payloads) — the scanner explicitly compared this response against a clean baseline and found no deviation.

The scanner's actual **confirmed critical SQLi findings** were on a completely different endpoint and parameter set: `/api/activities` via `limit` and `page`, both of which returned `HTTP 500` server errors — real evidence of a query breaking under injection.

## Lesson

The payload text (`DROP TABLE users`) is the most alarming-looking string in this entire alert batch, but it caused zero actual impact. A triage process — human or AI — that weights alerts by *payload text severity* rather than *response behavior* would systematically over-prioritize this alert above the two genuinely critical SQLi findings on `/api/activities`, which don't contain any scary destructive-sounding keywords (`' OR '1'='1`), just a clean `500` error as evidence. Gemini's actual output here avoided that trap.
