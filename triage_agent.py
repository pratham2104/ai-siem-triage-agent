#!/usr/bin/env python3
"""
Wazuh AI Triage Agent
=====================

Polls the Wazuh indexer (OpenSearch) for new alerts, sends each one to
Gemini for structured triage (summary, severity, MITRE ATT&CK ID,
recommended action), and appends the result to triage_log.jsonl.

Uses Google's Gemini API, which has a genuinely free tier (rate-limited,
not credit-limited) — get a key at https://aistudio.google.com/apikey.

This is a real integration, not a chat-based simulation: it makes an
actual authenticated HTTP call to Wazuh's alert store and an actual
API call to Gemini for every alert it processes.

Usage
-----
Run once, triage whatever's new, then exit:
    python3 triage_agent.py --once

Run continuously, polling every POLL_INTERVAL_SEC seconds:
    python3 triage_agent.py --daemon

Replay mode — triage alerts from a local exported JSON file instead of
querying a live Wazuh indexer (useful for demos, or if TLS/network
access to the indexer isn't available in your environment):
    python3 triage_agent.py --replay sample_alerts.json

The replay file should be a JSON array of Wazuh alert documents (the
same shape returned by the indexer's _search API — see
sample_alerts.json for the expected format).
"""

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
import urllib3
import google.generativeai as genai

import config

# Wazuh's indexer typically uses a self-signed cert out of the box.
# Suppressing the warning is acceptable for a local lab; in production,
# point requests at your real CA bundle instead of disabling verification.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


TRIAGE_SYSTEM_PROMPT = """You are a SOC (Security Operations Center) triage assistant. \
You will be given a single Wazuh SIEM alert as JSON. Respond with ONLY a JSON object \
(no markdown fences, no preamble, no trailing commentary) with exactly these fields:

{
  "summary": "one or two sentence plain-English description of what happened",
  "severity": "Low" | "Medium" | "High" | "Critical",
  "mitre_id": "a MITRE ATT&CK technique ID if applicable, else null",
  "recommended_action": "a concrete, specific next step for an analyst",
  "confidence": "High" | "Medium" | "Low",
  "reasoning": "brief explanation of why you assigned this severity — cite specific \
fields from the alert (status code, response size, payload, source IP, etc.), not just \
the alert's own description text"
}

Judge severity from the alert's actual evidence (response codes, response sizes, \
repeated patterns, timing) rather than from how alarming the payload text looks. \
If the alert alone is insufficient to draw a confident conclusion (for example, a \
timing-based SQL injection probe that would require comparing it against a paired \
request to judge), say so explicitly in "reasoning" and lower "confidence" accordingly \
rather than guessing."""


def load_state() -> dict:
    path = Path(config.STATE_FILE)
    if path.exists():
        return json.loads(path.read_text())
    return {"last_alert_timestamp": None, "processed_ids": []}


def save_state(state: dict) -> None:
    Path(config.STATE_FILE).write_text(json.dumps(state, indent=2))


def fetch_new_alerts_from_wazuh(state: dict) -> list:
    """
    Query the Wazuh indexer (OpenSearch-compatible API) for alerts at or
    above MIN_ALERT_LEVEL, newer than the last timestamp we processed.
    """
    if not config.WAZUH_INDEXER_PASS:
        raise RuntimeError(
            "WAZUH_INDEXER_PASS is not set — required for live mode. "
            "Use --replay sample_alerts.json to test without a live Wazuh connection."
        )

    url = f"{config.WAZUH_INDEXER_URL}/{config.WAZUH_ALERTS_INDEX_PATTERN}/_search"

    must_clauses = [{"range": {"rule.level": {"gte": config.MIN_ALERT_LEVEL}}}]
    if state.get("last_alert_timestamp"):
        must_clauses.append(
            {"range": {"@timestamp": {"gt": state["last_alert_timestamp"]}}}
        )

    query = {
        "size": config.BATCH_SIZE,
        "sort": [{"@timestamp": "asc"}],
        "query": {"bool": {"must": must_clauses}},
    }

    resp = requests.post(
        url,
        json=query,
        auth=(config.WAZUH_INDEXER_USER, config.WAZUH_INDEXER_PASS),
        verify=False,
        timeout=15,
    )
    resp.raise_for_status()
    hits = resp.json().get("hits", {}).get("hits", [])
    return [dict(hit["_source"], _id=hit["_id"]) for hit in hits]


def load_replay_alerts(replay_path: str) -> list:
    data = json.loads(Path(replay_path).read_text())
    if not isinstance(data, list):
        raise ValueError("Replay file must contain a JSON array of alert objects")
    return data


def triage_alert(model, alert: dict) -> dict:
    """Send one alert to Gemini and parse its structured triage response."""
    alert_json = json.dumps(alert, indent=2, default=str)

    response = model.generate_content(
        f"{TRIAGE_SYSTEM_PROMPT}\n\nAlert:\n{alert_json}",
        generation_config=genai.types.GenerationConfig(
            temperature=0.2,
            max_output_tokens=500,
        ),
    )

    raw_text = (response.text or "").strip()

    # Defensive parsing: strip markdown fences if the model adds them anyway.
    if raw_text.startswith("```"):
        raw_text = raw_text.strip("`")
        if raw_text.lower().startswith("json"):
            raw_text = raw_text[4:].strip()

    try:
        return json.loads(raw_text)
    except json.JSONDecodeError:
        return {
            "summary": "PARSE_ERROR",
            "severity": "Unknown",
            "mitre_id": None,
            "recommended_action": "Manual review required — AI response was not valid JSON.",
            "confidence": "Low",
            "reasoning": f"Raw model output: {raw_text[:500]}",
        }


def append_triage_result(alert: dict, triage: dict) -> None:
    record = {
        "processed_at": datetime.now(timezone.utc).isoformat(),
        "alert": alert,
        "ai_triage": triage,
    }
    with open(config.TRIAGE_LOG_FILE, "a") as f:
        f.write(json.dumps(record, default=str) + "\n")


def run_once(replay_path=None) -> int:
    config.validate()
    genai.configure(api_key=config.GEMINI_API_KEY)
    model = genai.GenerativeModel(config.GEMINI_MODEL)

    state = load_state()

    if replay_path:
        alerts = load_replay_alerts(replay_path)
        print(f"[replay] Loaded {len(alerts)} alerts from {replay_path}")
    else:
        alerts = fetch_new_alerts_from_wazuh(state)
        print(f"[live] Fetched {len(alerts)} new alert(s) from Wazuh indexer")

    if not alerts:
        print("No new alerts to triage.")
        return 0

    for i, alert in enumerate(alerts, 1):
        alert_id = alert.get("_id", alert.get("id", f"unknown-{i}"))
        if alert_id in state.get("processed_ids", []):
            continue

        rule_desc = alert.get("rule", {}).get("description", "unknown rule")
        print(f"  [{i}/{len(alerts)}] Triaging alert {alert_id}: {rule_desc}")

        triage = triage_alert(model, alert)
        append_triage_result(alert, triage)

        print(
            f"      -> severity={triage.get('severity')} "
            f"mitre={triage.get('mitre_id')} "
            f"confidence={triage.get('confidence')}"
        )

        state.setdefault("processed_ids", []).append(alert_id)
        ts = alert.get("@timestamp")
        if ts:
            state["last_alert_timestamp"] = ts

    save_state(state)
    print(f"\nDone. Results appended to {config.TRIAGE_LOG_FILE}")
    return 0


def run_daemon() -> int:
    print(
        f"Starting triage daemon — polling every {config.POLL_INTERVAL_SEC}s "
        f"(Ctrl+C to stop)"
    )
    try:
        while True:
            run_once()
            time.sleep(config.POLL_INTERVAL_SEC)
    except KeyboardInterrupt:
        print("\nStopped.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Wazuh AI Triage Agent (Gemini-powered)")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--once", action="store_true", help="Fetch and triage new alerts once, then exit"
    )
    group.add_argument(
        "--daemon", action="store_true", help="Continuously poll and triage new alerts"
    )
    group.add_argument(
        "--replay",
        metavar="FILE",
        help="Triage alerts from a local JSON file instead of a live Wazuh indexer",
    )
    args = parser.parse_args()

    if args.replay:
        return run_once(replay_path=args.replay)
    if args.daemon:
        return run_daemon()
    return run_once()


if __name__ == "__main__":
    sys.exit(main())
