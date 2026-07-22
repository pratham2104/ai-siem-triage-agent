# Case 02: OR-based SQLi payload on `/api/leaderboard`

This writeup uses the **actual output** of `triage_agent.py` (Gemini `gemini-flash-lite-latest`), captured in `triage_log.jsonl`.

## Raw Alert (as fed to the agent)

```json
{
  "_id": "sample-002",
  "@timestamp": "2026-07-18T18:33:53.500Z",
  "rule": {
    "id": "31164",
    "level": 6,
    "description": "SQL injection attempt.",
    "groups": ["web", "accesslog", "attack", "sqlinjection"],
    "mitre": { "id": ["T1190"] }
  },
  "location": "/home/ubuntu/move-more/logs/access.log",
  "srcip": "::ffff:127.0.0.1",
  "full_log": "::ffff:127.0.0.1 - - [18/Jul/2026:18:33:53 +0000] \"GET /api/leaderboard?href=%27%20OR%201%3D1-- HTTP/1.1\" 404 154 \"-\" \"python-httpx/0.27.0\""
}
```

## What Gemini actually returned

```json
{
  "summary": "An HTTP GET request containing a potential SQL injection payload was sent to the /api/leaderboard endpoint from localhost, resulting in a 404 Not Found response.",
  "severity": "Low",
  "mitre_id": "T1190",
  "recommended_action": "Verify if the /api/leaderboard endpoint exists and check application logs for surrounding requests from 127.0.0.1 to determine if this was an active scan or a misrouted request.",
  "confidence": "High",
  "reasoning": "Although the payload contains a classic SQL injection string (' OR 1=1--), the server responded with a 404 status code and a small response size (154 bytes), indicating the requested resource does not exist and the injection attempt likely failed or was a harmless probe against an invalid endpoint. Severity is Low based on the 404 status code and local source IP (::ffff:127.0.0.1)."
}
```

## Assessment

Clean, confident, correct call. The `404` response is a fast, unambiguous signal that the route/parameter never reached application logic capable of executing a query — the model correctly used that to justify both Low severity and High confidence, and its recommended action (check for a scan pattern from the same source) is a reasonable next step rather than a dead end.

## Verification against ground truth

Matches the scanner's own `[SAFE]` classification for this fuzzing pass — no behavioral deviation from baseline was recorded for this endpoint/parameter combination.

## Lesson

A `404` in response to an injection attempt is one of the more reliable low-severity signals available: it means the attack surface being probed doesn't exist in the form the request assumed. Both the model's severity and confidence tracked that correctly, which is a useful contrast to [Case 04](case-04-timing-based-sqli-blindspot.md), where a `200` response left genuine ambiguity the model only partially resolved.
