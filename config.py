"""
Configuration for the Wazuh AI Triage agent.

All secrets are read from environment variables — never hardcode
credentials in this file or commit real values to git.

Required environment variables:
    GEMINI_API_KEY      your free Google AI Studio API key
                         (get one at https://aistudio.google.com/apikey —
                         no billing required for the free tier)

Required only for live mode (--once / --daemon against a real Wazuh instance):
    WAZUH_INDEXER_URL   e.g. "https://localhost:9200"
    WAZUH_INDEXER_USER  e.g. "admin"
    WAZUH_INDEXER_PASS  the Wazuh indexer admin password

Optional:
    GEMINI_MODEL          default: "gemini-2.0-flash"
    MIN_ALERT_LEVEL       minimum Wazuh rule level to triage (default: 5)
    POLL_INTERVAL_SEC     seconds between polls in daemon mode (default: 30)
    BATCH_SIZE            max alerts to fetch per poll (default: 20)
"""

import os

WAZUH_INDEXER_URL = os.environ.get("WAZUH_INDEXER_URL", "https://localhost:9200")
WAZUH_INDEXER_USER = os.environ.get("WAZUH_INDEXER_USER", "admin")
WAZUH_INDEXER_PASS = os.environ.get("WAZUH_INDEXER_PASS")

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.0-flash")

MIN_ALERT_LEVEL = int(os.environ.get("MIN_ALERT_LEVEL", "5"))
POLL_INTERVAL_SEC = int(os.environ.get("POLL_INTERVAL_SEC", "30"))
BATCH_SIZE = int(os.environ.get("BATCH_SIZE", "20"))

# Index pattern Wazuh writes alerts into (default naming as of Wazuh 4.x)
WAZUH_ALERTS_INDEX_PATTERN = os.environ.get(
    "WAZUH_ALERTS_INDEX_PATTERN", "wazuh-alerts-*"
)

# Where we persist "last seen alert timestamp" so re-running the agent
# doesn't re-triage alerts it already processed.
STATE_FILE = os.environ.get("STATE_FILE", "state.json")

# Where triage results are appended, one JSON object per line.
TRIAGE_LOG_FILE = os.environ.get("TRIAGE_LOG_FILE", "triage_log.jsonl")


def validate():
    """Raise a clear error early if required secrets are missing."""
    missing = []
    if not GEMINI_API_KEY:
        missing.append("GEMINI_API_KEY")
    if missing:
        raise RuntimeError(
            f"Missing required environment variable(s): {', '.join(missing)}. "
            "Set them before running triage_agent.py, e.g.:\n"
            "  export GEMINI_API_KEY='your-free-api-key-from-aistudio.google.com'\n\n"
            "Note: WAZUH_INDEXER_PASS is only required for --once/--daemon modes "
            "against a live Wazuh instance. --replay mode does not need it."
        )
