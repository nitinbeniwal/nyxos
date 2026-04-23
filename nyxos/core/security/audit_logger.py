"""
NyxOS Audit Logger
Location: nyxos/core/security/audit_logger.py

Protects: ACCOUNTABILITY & NON-REPUDIATION
- Logs every command executed
- Logs every AI interaction
- Logs authentication events
- Tamper-evident logging (hash chain)

Critical for:
- Legal compliance during pentests
- Incident investigation
- Proving authorization and scope compliance
"""

import os
import json
import hashlib
from datetime import datetime
from typing import Optional
from pathlib import Path
from loguru import logger


class AuditLogger:
    """
    Tamper-evident audit logging.
    
    Each log entry includes a hash of the previous entry,
    creating a chain that detects any modification.
    Similar to a simple blockchain for integrity.
    """

    LOG_DIR = os.path.expanduser("~/.nyxos/logs/audit")

    def __init__(self):
        os.makedirs(self.LOG_DIR, mode=0o700, exist_ok=True)
        self._current_log_file = self._get_log_file()
        self._last_hash = self._get_last_hash()

    def _get_log_file(self) -> str:
        """Get current log file (one per day)"""
        date_str = datetime.now().strftime("%Y-%m-%d")
        return os.path.join(self.LOG_DIR, f"audit-{date_str}.jsonl")

    def _get_last_hash(self) -> str:
        """Get hash of last log entry for chain integrity"""
        if os.path.exists(self._current_log_file):
            with open(self._current_log_file, "r") as f:
                lines = f.readlines()
                if lines:
                    last_entry = json.loads(lines[-1])
                    return last_entry.get("entry_hash", "GENESIS")
        return "GENESIS"

    def _compute_hash(self, entry: dict) -> str:
        """Compute SHA-256 hash of a log entry"""
        entry_str = json.dumps(entry, sort_keys=True, default=str)
        return hashlib.sha256(entry_str.encode()).hexdigest()

    def log(
        self,
        event_type: str,
        action: str,
        username: str = "system",
        details: Optional[dict] = None,
        command: str = "",
        result: str = "",
        risk_level: str = "low",
        source: str = "shell"
    ):
        """
        Log an audit event.
        
        Event types:
        - AUTH: Authentication events
        - COMMAND: Command execution
        - AI: AI interactions
        - SCAN: Scan operations
        - SCOPE: Scope changes
        - CONFIG: Configuration changes
        - SECURITY: Security events (blocked commands, etc.)
        """
        entry = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "action": action,
            "username": username,
            "command": command,
            "result": result[:1000] if result else "",  # Truncate large results
            "risk_level": risk_level,
            "source": source,
            "details": details or {},
            "previous_hash": self._last_hash,
        }

        # Add hash chain
        entry["entry_hash"] = self._compute_hash(entry)
        self._last_hash = entry["entry_hash"]

        # Write to log file
        log_file = self._get_log_file()
        with open(log_file, "a") as f:
            f.write(json.dumps(entry, default=str) + "\n")

        # Set restrictive permissions
        os.chmod(log_file, 0o600)

    def verify_integrity(self, log_file: Optional[str] = None) -> bool:
        """
        Verify the hash chain integrity of a log file.
        Detects any tampering with log entries.
        """
        log_file = log_file or self._current_log_file

        if not os.path.exists(log_file):
            return True

        with open(log_file, "r") as f:
            lines = f.readlines()

        previous_hash = "GENESIS"

        for i, line in enumerate(lines):
            entry = json.loads(line)

            # Verify previous hash link
            if entry["previous_hash"] != previous_hash:
                logger.error(f"Hash chain broken at entry {i}")
                return False

            # Verify entry hash
            stored_hash = entry.pop("entry_hash")
            computed_hash = self._compute_hash(entry)
            entry["entry_hash"] = stored_hash

            if stored_hash != computed_hash:
                logger.error(f"Entry {i} has been tampered with")
                return False

            previous_hash = stored_hash

        logger.info(f"Log integrity verified: {len(lines)} entries OK")
        return True

    def get_recent_events(self, count: int = 50, event_type: Optional[str] = None) -> list:
        """Get recent audit events"""
        log_file = self._get_log_file()
        if not os.path.exists(log_file):
            return []

        with open(log_file, "r") as f:
            lines = f.readlines()

        events = [json.loads(line) for line in lines]

        if event_type:
            events = [e for e in events if e["event_type"] == event_type]

        return events[-count:]

