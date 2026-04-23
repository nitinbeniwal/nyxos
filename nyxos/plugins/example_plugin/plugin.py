"""
NyxOS Plugin: Slack Notifier
==============================
Sends findings and session summaries to a Slack webhook.

Installation
------------
1. Copy this folder to ``~/.nyxos/plugins/slack-notifier/``
2. Create ``config.json`` next to this file with::

       {"webhook_url": "https://hooks.slack.com/services/T.../B.../xxx"}

3. Restart NyxOS or run ``plugins reload`` in the NyxOS shell.

Demonstrates
------------
- ``PLUGIN_MANIFEST`` format
- ``on_finding`` hook
- ``on_session_end`` hook
- Plugin-specific configuration loading
- Graceful error handling (never crashes the host)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional

from loguru import logger

# Try importing requests; if not installed the hooks will degrade gracefully.
try:
    import requests  # noqa: F401

    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False


# ---------------------------------------------------------------------------
# Plugin Manifest (REQUIRED)
# ---------------------------------------------------------------------------

PLUGIN_MANIFEST: Dict[str, Any] = {
    "name": "slack-notifier",
    "version": "1.0.0",
    "author": "NyxOS Community",
    "description": "Send findings and session summaries to a Slack webhook.",
    "hooks": ["on_finding", "on_session_end"],
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_CONFIG_FILENAME = "config.json"


def _get_config() -> Optional[dict]:
    """
    Load plugin-specific config from ``config.json`` next to this file.

    Returns:
        Parsed dict or ``None`` if the file is missing / invalid.
    """
    config_path = Path(__file__).parent / _CONFIG_FILENAME
    if not config_path.exists():
        logger.warning("[slack-notifier] config.json not found at {}", config_path)
        return None
    try:
        return json.loads(config_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        logger.error("[slack-notifier] Failed to read config.json: {}", exc)
        return None


def _send_slack(webhook_url: str, message: dict) -> bool:
    """
    Post a Slack message payload to *webhook_url*.

    Args:
        webhook_url: Full Slack incoming-webhook URL.
        message: Slack message dict (must contain ``"text"`` or ``"blocks"``).

    Returns:
        ``True`` if the message was accepted (HTTP 200), ``False`` otherwise.
    """
    if not _HAS_REQUESTS:
        logger.warning("[slack-notifier] 'requests' library not installed — cannot send.")
        return False

    try:
        resp = requests.post(
            webhook_url,
            json=message,
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
        if resp.status_code == 200:
            logger.debug("[slack-notifier] Message sent successfully.")
            return True
        else:
            logger.warning("[slack-notifier] Slack returned HTTP {}: {}", resp.status_code, resp.text[:200])
            return False
    except requests.RequestException as exc:
        logger.error("[slack-notifier] Network error: {}", exc)
        return False


def _severity_emoji(severity: str) -> str:
    """Map a severity string to a Slack emoji."""
    mapping = {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🔵",
        "info": "⚪",
    }
    return mapping.get(severity.lower(), "❓")


# ---------------------------------------------------------------------------
# Hook Implementations
# ---------------------------------------------------------------------------

def on_finding(finding: dict, config: dict) -> None:
    """
    Called whenever a new finding is recorded in project memory.

    Posts a short Slack message with the finding title and severity.

    Args:
        finding: The finding dict (keys: title, severity, description, …).
        config: NyxOS config dict (injected by PluginManager.fire_event).
    """
    plugin_cfg = _get_config()
    if plugin_cfg is None:
        return

    webhook_url = plugin_cfg.get("webhook_url")
    if not webhook_url:
        logger.warning("[slack-notifier] No webhook_url in config.json.")
        return

    severity = finding.get("severity", "info")
    emoji = _severity_emoji(severity)
    title = finding.get("title", "Untitled finding")
    description = finding.get("description", "")

    text = (
        f"{emoji} *NyxOS Finding — {severity.upper()}*\n"
        f"*{title}*\n"
        f"{description[:300]}"
    )

    _send_slack(webhook_url, {"text": text})


def on_session_end(session_summary: dict, config: dict) -> None:
    """
    Called when the user exits NyxOS.

    Posts a summary of the session to Slack.

    Args:
        session_summary: Dict with keys like commands_run, findings_count,
                         duration_seconds, etc.
        config: NyxOS config dict.
    """
    plugin_cfg = _get_config()
    if plugin_cfg is None:
        return

    webhook_url = plugin_cfg.get("webhook_url")
    if not webhook_url:
        return

    commands = session_summary.get("commands_run", 0)
    findings = session_summary.get("findings_count", 0)
    duration = session_summary.get("duration_seconds", 0)
    minutes = int(duration // 60)
    seconds = int(duration % 60)

    text = (
        f"🖥️ *NyxOS Session Ended*\n"
        f"• Commands run: *{commands}*\n"
        f"• Findings discovered: *{findings}*\n"
        f"• Duration: *{minutes}m {seconds}s*"
    )

    _send_slack(webhook_url, {"text": text})
