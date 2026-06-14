"""
Per-session request log. Every request the sender issues (baseline + attack) is
recorded here so the Critic can correlate baseline vs. attack outcomes, and so the
UI History tab can replay them.

Written to: backend/request_log.json  (git-ignored)
"""
import json
import os
from datetime import datetime, timezone
from typing import List, Optional

LOG_PATH = os.environ.get("GRAPHRAIDER_LOG") or os.path.join(os.path.dirname(__file__), "request_log.json")
_entries: List[dict] = []

# Header names whose values are secrets and must never be written to disk in full.
_SENSITIVE = {"authorization", "cookie", "x-api-key", "x-auth-token"}


def _redact(headers: dict) -> dict:
    out = {}
    for k, v in (headers or {}).items():
        if k.lower() in _SENSITIVE:
            out[k] = "…[redacted]"
        else:
            out[k] = v
    return out


def record(
    test_id: str,
    label: str,
    is_baseline: bool,
    method: str,
    url: str,
    req_headers: dict,
    req_body: str,
    status_code: Optional[int],
    resp_headers: dict,
    resp_body: str,
    latency_ms: float,
    error: Optional[str],
) -> None:
    _entries.append({
        "ts": datetime.now(timezone.utc).isoformat(),
        "test_id": test_id,
        "label": label,
        "is_baseline": is_baseline,
        "method": method,
        "url": url,
        "req_headers": _redact(req_headers),
        "req_body_preview": (req_body or "")[:600],
        "status_code": status_code,
        "resp_headers": dict(list((resp_headers or {}).items())[:12]),
        "resp_body_preview": (resp_body or "")[:1000],
        "latency_ms": round(latency_ms, 1),
        "error": error,
    })
    _flush()


def get_entries_for_test(test_id: str) -> List[dict]:
    return [e for e in _entries if e["test_id"] == test_id]


def clear_test(test_id: str) -> None:
    """Drop prior entries for a test before re-running it."""
    global _entries
    _entries = [e for e in _entries if e["test_id"] != test_id]
    _flush()


def _flush() -> None:
    try:
        with open(LOG_PATH, "w", encoding="utf-8") as f:
            json.dump(_entries, f, indent=2)
    except OSError:
        pass
