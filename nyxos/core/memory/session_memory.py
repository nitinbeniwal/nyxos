"""
NyxOS Session Memory (Short-term)
Location: nyxos/core/memory/session_memory.py

Lives only during current session.
Tracks what's happening RIGHT NOW.
"""

from typing import Dict, Any, List, Optional
from datetime import datetime
from dataclasses import dataclass, field


@dataclass
class CommandRecord:
    """Record of a single command execution"""
    command: str
    output: str
    timestamp: str
    exit_code: int = 0
    skill_used: str = ""
    ai_generated: bool = False


class SessionMemory:
    """
    Short-term memory for the current session.
    
    Contains:
    - Current target/scope
    - Commands run this session
    - Findings discovered this session
    - Active scans
    - Conversation context for AI
    
    Dies when session ends (unless saved to project).
    Only recent items are sent to AI (token optimization).
    """

    MAX_CONTEXT_COMMANDS = 10  # Only last 10 commands sent to AI
    MAX_CONTEXT_FINDINGS = 20  # Only last 20 findings sent to AI

    def __init__(self):
        self.session_id: str = ""
        self.started_at: str = datetime.now().isoformat()
        self.target: str = ""
        self.scope_name: str = ""
        self.commands: List[CommandRecord] = []
        self.findings: List[Dict[str, Any]] = []
        self.active_scans: List[Dict[str, Any]] = []
        self.notes: List[str] = []
        self.variables: Dict[str, Any] = {}  # User-set variables

    def add_command(self, command: str, output: str, exit_code: int = 0,
                    skill_used: str = "", ai_generated: bool = False):
        """Record a command execution"""
        self.commands.append(CommandRecord(
            command=command,
            output=output[:5000],  # Truncate large outputs
            timestamp=datetime.now().isoformat(),
            exit_code=exit_code,
            skill_used=skill_used,
            ai_generated=ai_generated
        ))

    def add_finding(self, finding: Dict[str, Any]):
        """Add a security finding"""
        finding["discovered_at"] = datetime.now().isoformat()
        self.findings.append(finding)

    def get_ai_context(self) -> str:
        """
        Build minimal context string for AI prompts.
        This is THE key to token optimization.
        Only sends what's relevant and recent.
        """
        parts = []

        if self.target:
            parts.append(f"Current target: {self.target}")

        if self.scope_name:
            parts.append(f"Scope: {self.scope_name}")

        # Last N commands (summarized)
        recent_cmds = self.commands[-self.MAX_CONTEXT_COMMANDS:]
        if recent_cmds:
            cmd_summary = []
            for cmd in recent_cmds:
                output_preview = cmd.output[:200] if cmd.output else "no output"
                cmd_summary.append(f"  $ {cmd.command} → {output_preview}")
            parts.append("Recent commands:\n" + "\n".join(cmd_summary))

        # Recent findings (summarized)
        recent_findings = self.findings[-self.MAX_CONTEXT_FINDINGS:]
        if recent_findings:
            finding_summary = []
            for f in recent_findings:
                finding_summary.append(
                    f"  - [{f.get('severity', 'info')}] {f.get('type', 'unknown')}: "
                    f"{f.get('description', str(f))}"
                )
            parts.append("Findings so far:\n" + "\n".join(finding_summary))

        return "\n\n".join(parts)

    def get_last_output(self) -> str:
        """Get output of last command"""
        if self.commands:
            return self.commands[-1].output
        return ""

    def set_variable(self, key: str, value: Any):
        """Set a session variable"""
        self.variables[key] = value

    def get_variable(self, key: str, default: Any = None) -> Any:
        """Get a session variable"""
        return self.variables.get(key, default)

    def clear(self):
        """Clear session memory"""
        self.commands.clear()
        self.findings.clear()
        self.active_scans.clear()
        self.notes.clear()
        self.variables.clear()

