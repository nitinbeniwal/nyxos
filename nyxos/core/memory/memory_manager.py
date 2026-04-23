"""
NyxOS Memory Manager
Location: nyxos/core/memory/memory_manager.py

Orchestrates all three memory layers.
Builds optimized AI context from combined memory.
"""

import os
import json
from typing import Dict, Any, Optional
from datetime import datetime
from loguru import logger

from .session_memory import SessionMemory
from .project_memory import ProjectMemory
from .user_memory import UserMemory


class MemoryManager:
    """
    Central memory orchestrator.

    Manages all three memory layers:
    1. Session (short-term) — current session context
    2. Project (medium-term) — engagement data
    3. User (long-term) — preferences and habits

    Key responsibility: Build the optimal AI context
    using minimal tokens from all three layers.
    """

    # Token budget for context injection
    MAX_CONTEXT_TOKENS_ESTIMATE = 1500  # ~1500 tokens for context

    def __init__(self, username: str = "default", project_name: str = "default"):
        self.session = SessionMemory()
        self.project = ProjectMemory(project_name)
        self.user = UserMemory(username)
        self.session.session_id = f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        logger.info(
            f"Memory Manager initialized — User: {username}, "
            f"Project: {project_name}, Session: {self.session.session_id}"
        )

    def build_ai_context(self) -> str:
        """
        Build the complete AI context from all memory layers.

        This is THE most important function for token optimization.
        It carefully selects what to include based on relevance.

        Approximate token allocation:
        - Session context: ~600 tokens (most important — what's happening now)
        - Project context: ~500 tokens (scope, findings summary)
        - User preferences: ~200 tokens (just hints, not raw data)
        - Buffer: ~200 tokens
        """
        parts = []

        # Layer 1: Session context (highest priority)
        session_ctx = self.session.get_ai_context()
        if session_ctx:
            parts.append(f"=== CURRENT SESSION ===\n{session_ctx}")

        # Layer 2: Project context (medium priority)
        project_ctx = self.project.get_ai_context()
        if project_ctx:
            parts.append(f"=== PROJECT INFO ===\n{project_ctx}")

        # Layer 3: User preferences (lowest priority, minimal tokens)
        user_hints = self.user.get_ai_preference_hints()
        if user_hints:
            parts.append(f"=== USER PREFERENCES ===\n{user_hints}")

        full_context = "\n\n".join(parts)

        # Rough token estimate (1 token ≈ 4 chars)
        estimated_tokens = len(full_context) // 4
        if estimated_tokens > self.MAX_CONTEXT_TOKENS_ESTIMATE:
            full_context = self._compress_context(full_context)

        return full_context

    def _compress_context(self, context: str) -> str:
        """Compress context if it exceeds token budget"""
        # Simple compression: truncate from the middle
        # Keep session (most recent) and user preferences (stable)
        max_chars = self.MAX_CONTEXT_TOKENS_ESTIMATE * 4

        if len(context) <= max_chars:
            return context

        # Split into sections and prioritize
        sections = context.split("===")
        compressed_parts = []
        remaining_chars = max_chars

        for section in sections:
            section = section.strip()
            if not section:
                continue
            if len(section) <= remaining_chars:
                compressed_parts.append(section)
                remaining_chars -= len(section)
            else:
                compressed_parts.append(section[:remaining_chars] + "...[truncated]")
                break

        return "\n".join(compressed_parts)

    def record_command(self, command: str, output: str, exit_code: int = 0,
                       skill_used: str = "", ai_generated: bool = False):
        """Record a command across all memory layers"""
        # Session — full detail
        self.session.add_command(
            command=command,
            output=output,
            exit_code=exit_code,
            skill_used=skill_used,
            ai_generated=ai_generated
        )

        # User — pattern learning only
        self.user.record_command(command, skill_used, ai_generated)

        # Project — timeline event
        self.project.add_timeline_event(f"Executed: {command[:100]}", "command")

    def record_finding(self, finding: Dict[str, Any]):
        """Record a finding across all memory layers"""
        # Session — immediate context
        self.session.add_finding(finding)

        # Project — persistent storage
        self.project.add_finding(finding)

        # User — stats only
        self.user.data["stats"]["total_findings"] += 1

    def record_ai_interaction(self, provider: str, tokens_used: int):
        """Record AI usage for tracking"""
        self.user.record_provider_usage(provider, tokens_used)

    def set_target(self, target: str):
        """Set the current target"""
        self.session.target = target
        logger.info(f"Target set: {target}")

    def set_scope(self, targets: list, excluded: list = None,
                  authorization: bool = False, roe: str = ""):
        """Set project scope"""
        self.project.set_scope(targets, excluded, authorization, roe)
        if targets:
            self.session.target = targets[0]
            self.session.scope_name = self.project.name

    def switch_project(self, project_name: str):
        """Switch to a different project"""
        # Save current session to current project
        self._save_session_to_project()

        # Load new project
        self.project = ProjectMemory(project_name)
        self.session = SessionMemory()  # Fresh session
        self.session.session_id = f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        # Restore target from project scope
        if self.project.data["scope"]["targets"]:
            self.session.target = self.project.data["scope"]["targets"][0]
            self.session.scope_name = project_name

        logger.info(f"Switched to project: {project_name}")

    def end_session(self):
        """End current session and persist data"""
        self._save_session_to_project()

        # Update user stats
        started = datetime.fromisoformat(self.session.started_at)
        duration = (datetime.now() - started).total_seconds() / 60

        self.user.record_session_end(
            duration_minutes=duration,
            commands_run=len(self.session.commands),
            findings=len(self.session.findings)
        )
        self.user.save()
        self.project.save()

        logger.info(
            f"Session ended — Duration: {duration:.1f}min, "
            f"Commands: {len(self.session.commands)}, "
            f"Findings: {len(self.session.findings)}"
        )

    def _save_session_to_project(self):
        """Save session summary to project"""
        if not self.session.commands:
            return

        started = datetime.fromisoformat(self.session.started_at)
        duration = (datetime.now() - started).total_seconds() / 60

        self.project.record_session({
            "session_id": self.session.session_id,
            "duration": f"{duration:.1f} minutes",
            "commands_run": len(self.session.commands),
            "findings_discovered": len(self.session.findings),
            "summary": f"Ran {len(self.session.commands)} commands, "
                       f"found {len(self.session.findings)} findings"
        })
