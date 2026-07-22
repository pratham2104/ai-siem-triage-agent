# Case 04: `SLEEP(0)` payload on `/api/badges` — the structural blind spot

This is the key finding of the lab: a case where alert-by-alert AI triage has a genuine methodology gap, not just a severity miscall. Unlike the earlier draft of this writeup, everything below is the **actual output** of `triage_agent.py` running against Gemini (`gemini-flash-lite-latest`), captured in `triage_log.jsonl`, not a hypothetical.

## Raw Alert (as fed to the agent)

```json
{
  "_id": "sample-004",
  "@timestamp": "2026-07-18T18:33:53.750Z",
  "rule": {
    "id": "31164",
    "level": 6,
    "description": "SQL injection attempt.",
    "groups": ["web", "accesslog", "attack", "sqlinjection"],
    "mitre": { "id": ["T1190"] }
  },
  "location": "/home/ubuntu/move-more/logs/access.log",
  "srcip": "::ffff:127.0.0.1",
  "full_log": "::ffff:127.0.0.1 - - [18/Jul/2026:18:33:53 +0000] \"GET /api/badges?image=%27%20AND%20SLEEP%280%29-- HTTP/1.1\" 200 2311 \"-\" \"python-httpx/0.27.0\""
}
```

## What Gemini actually returned

```json
{
  "summary": "An HTTP GET request containing a time-based blind SQL injection payload (SLEEP(0)) was sent to the /api/badges endpoint from the local address.",
  "severity": "Low",
  "mitre_id": "T1190",
  "recommended_action": "Check the web server application logs and database query execution times for anomalies, and verify if the request originated from an internal testing tool or scanner since the source IP is localhost.",
  "confidence": "Medium",
  "reasoning": "The alert rule level is 6 and the payload 'SLEEP(0)' uses a conditional delay of zero, indicating a potential probe or scanner activity rather than a confirmed impactful exploit. Furthermore, the HTTP response status code is 200 with a response size of 2311 bytes, and the source IP is loopback (::ffff:127.0.0.1), suggesting benign internal testing or a non-malicious scan without definitive evidence of successful exploitation."
}
```

## Assessment: partial credit, not a clean pass

**What the model got right:** it correctly recognized `SLEEP(0)` as "a conditional delay of zero, indicating a potential probe... rather than a confirmed impactful exploit" — it wasn't fooled into treating this as a real, executed attack, and it downgraded confidence to Medium (not High) rather than confidently declaring the alert safe.

**What the model did not do:** it never identified the actual mechanism that makes this alert hard to judge — that `SLEEP(0)` is specifically a **calibration probe**, meaningless without a paired `SLEEP(5)`-style request on the *same parameter* to compare against. Instead, its reasoning leaned on loopback IP and response size/status as its basis for lowered confidence — a reasonable but different, less precise justification than the one this case study originally predicted.

For comparison, on a different alert in the same batch ([Case 01](case-01-drop-table-payload.md), the `DROP TABLE` payload), the model's reasoning **did** explicitly say: *"Without comparing this response against a baseline valid request... the alert alone is insufficient to confirm a successful attack."* That is the sharper, correlation-aware reasoning — it just showed up on the wrong alert relative to what this case study expected.

## Why this still supports the underlying finding

Even though the model's stated reasoning wasn't textbook-precise on this specific alert, the practical result — Medium confidence rather than a confident "safe" verdict — is exactly the outcome you want from a triage system handling this class of alert. The genuinely interesting finding is that the model's *justification* for caution was inconsistent across two structurally similar alerts (Case 01 and Case 04) in the same run: sound correlation-based reasoning on one, weaker circumstantial reasoning (loopback IP, familiar response size) on the other. That inconsistency — not a single wrong answer — is the real, defensible evidence for why alert-by-alert AI triage needs an explicit correlation step (grouping alerts by source IP, parameter, and technique family) rather than trusting each model response to reliably surface the right caveat on its own.

## Verification against ground truth

My own API Attack Surface Auditor performs the correct paired-request comparison internally — its SQL injection module tests both zero-delay and nonzero-delay variants and explicitly measures the timing delta before flagging a finding. The scan report shows no positive time-based SQLi finding for `/api/badges`, confirming the scanner's structured methodology already ruled this out correctly. The gap is specifically in triaging **Wazuh's alerts directly**, one at a time, without access to that scanner's internal baseline-comparison logic — which is exactly the situation this agent (and the real transcript above) is testing.

## Lesson

**This is the central finding of the lab, refined by real data rather than assumption.** AI triage of individual SIEM alerts can reach a reasonable severity/confidence outcome for correlation-dependent techniques like timing-based SQLi, but the *reasoning it uses to get there* is not reliably the correct one — and isn't guaranteed to generalize to a case where the circumstantial signals (loopback IP, familiar response size) aren't available to lean on instead. A production triage pipeline should not depend on the model spontaneously identifying which alerts need cross-referencing; it needs an explicit correlation step (grouping alerts by source IP, parameter, and technique family within a time window) before handing anything to an LLM for a final judgment call.

