"""
NyxOS User Memory (Long-term)
Location: nyxos/core/memory/user_memory.py

Learns how the user works over time.
Adapts AI behavior to user preferences.
NEVER sent to AI APIs — stays local for privacy.
"""

import os
import json
from typing import Dict, Any, List, Optional
from datetime import datetime
from collections import Counter
from loguru import logger

MEMORY_DIR = os.path.expanduser("~/.nyxos/memory")


class UserMemory:
    """
    Long-term memory that learns user preferences and habits.

    Tracks:
    - Tool preferences (which tools user prefers)
    - Workflow patterns (how user typically works)
    - Skill level progression
    - Communication preferences
    - Common targets/domains
    - Frequently used commands

    Privacy:
    - All data stays LOCAL — never sent to AI API
    - Only derived preferences (not raw data) influence AI prompts
    - User can view, export, or delete at any time
    """

    def __init__(self, username: str = "default"):
        self.username = username
        self.memory_file = os.path.join(MEMORY_DIR, f"{username}_memory.json")
        self.data = self._load()

    def _load(self) -> dict:
        """Load user memory from disk"""
        if os.path.exists(self.memory_file):
            try:
                with open(self.memory_file, "r") as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                pass

        return {
            "username": self.username,
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat(),
            "preferences": {
                "scan_style": "balanced",      # stealth, balanced, aggressive
                "verbosity": "normal",          # minimal, normal, detailed
                "auto_confirm": False,
                "preferred_tools": {},          # tool_name: usage_count
                "preferred_scan_type": "",
                "report_format": "pdf",
                "color_scheme": "dark"
            },
            "stats": {
                "total_sessions": 0,
                "total_commands": 0,
                "total_findings": 0,
                "total_scans": 0,
                "skills_used": {},              # skill_name: count
                "providers_used": {},           # provider_name: count
                "tokens_lifetime": 0
            },
            "patterns": {
                "common_commands": {},          # command_prefix: count
                "work_hours": {},               # hour: count (when user is active)
                "session_durations": [],        # list of durations in minutes
                "target_types": {},             # web, network, wireless, etc.
                "workflow_sequences": []        # common command sequences
            },
            "knowledge": {
                "topics_explored": [],
                "tools_learned": [],
                "skill_progression": {}         # category: level
            },
            "corrections": []                   # times user corrected AI
        }

    def save(self):
        """Save user memory to disk"""
        os.makedirs(MEMORY_DIR, mode=0o700, exist_ok=True)
        self.data["updated_at"] = datetime.now().isoformat()

        with open(self.memory_file, "w") as f:
            json.dump(self.data, f, indent=2, default=str)
        os.chmod(self.memory_file, 0o600)

    def record_command(self, command: str, skill_used: str = "", ai_generated: bool = False):
        """Record a command execution to learn patterns"""
        self.data["stats"]["total_commands"] += 1

        # Track command prefix patterns
        prefix = command.split()[0] if command.strip() else ""
        if prefix:
            cmds = self.data["patterns"]["common_commands"]
            cmds[prefix] = cmds.get(prefix, 0) + 1

        # Track tool usage
        if skill_used:
            skills = self.data["stats"]["skills_used"]
            skills[skill_used] = skills.get(skill_used, 0) + 1

        # Track work hours
        hour = str(datetime.now().hour)
        hours = self.data["patterns"]["work_hours"]
        hours[hour] = hours.get(hour, 0) + 1

        # Track tool preferences
        tools = self.data["preferences"]["preferred_tools"]
        if prefix in ["nmap", "gobuster", "nikto", "sqlmap", "hydra", "john",
                       "hashcat", "metasploit", "burp", "ffuf", "dirb",
                       "enum4linux", "smbclient", "crackmapexec", "responder",
                       "wireshark", "tcpdump", "aircrack-ng"]:
            tools[prefix] = tools.get(prefix, 0) + 1

        # Periodic save (every 10 commands)
        if self.data["stats"]["total_commands"] % 10 == 0:
            self.save()

    def record_correction(self, ai_suggestion: str, user_correction: str):
        """Record when user corrects AI — this is how we improve"""
        self.data["corrections"].append({
            "timestamp": datetime.now().isoformat(),
            "ai_said": ai_suggestion[:500],
            "user_wanted": user_correction[:500]
        })

        # Keep only last 100 corrections
        self.data["corrections"] = self.data["corrections"][-100:]
        self.save()

    def record_session_end(self, duration_minutes: float, commands_run: int,
                           findings: int):
        """Record session statistics"""
        self.data["stats"]["total_sessions"] += 1
        self.data["stats"]["total_findings"] += findings

        durations = self.data["patterns"]["session_durations"]
        durations.append(round(duration_minutes, 1))
        # Keep last 50 sessions
        self.data["patterns"]["session_durations"] = durations[-50:]

        self.save()

    def record_provider_usage(self, provider: str, tokens: int):
        """Track AI provider usage"""
        providers = self.data["stats"]["providers_used"]
        providers[provider] = providers.get(provider, 0) + 1
        self.data["stats"]["tokens_lifetime"] += tokens

    def learn_scan_preference(self, scan_type: str):
        """Learn what type of scans user prefers"""
        target_types = self.data["patterns"]["target_types"]
        target_types[scan_type] = target_types.get(scan_type, 0) + 1

        # Determine preferred style based on history
        if target_types:
            most_common = max(target_types, key=target_types.get)
            self.data["preferences"]["preferred_scan_type"] = most_common

    def get_preferred_tool(self, category: str) -> Optional[str]:
        """Get user's preferred tool for a category"""
        tool_map = {
            "port_scan": ["rustscan", "nmap", "masscan"],
            "web_scan": ["ffuf", "gobuster", "dirb"],
            "vuln_scan": ["nuclei", "nikto", "nessus"],
            "password": ["hashcat", "john"],
            "brute_force": ["hydra", "medusa"],
        }

        candidates = tool_map.get(category, [])
        tools = self.data["preferences"]["preferred_tools"]

        # Return the most-used tool from the category
        best_tool = None
        best_count = 0
        for tool in candidates:
            count = tools.get(tool, 0)
            if count > best_count:
                best_count = count
                best_tool = tool

        return best_tool

    def get_ai_preference_hints(self) -> str:
        """
        Generate preference hints for AI prompts.
        These are DERIVED insights, not raw data.
        Minimal tokens used.
        """
        hints = []

        prefs = self.data["preferences"]

        if prefs.get("scan_style") and prefs["scan_style"] != "balanced":
            hints.append(f"User prefers {prefs['scan_style']} approach")

        if prefs.get("verbosity") and prefs["verbosity"] != "normal":
            hints.append(f"Verbosity: {prefs['verbosity']}")

        if prefs.get("auto_confirm"):
            hints.append("User prefers auto-confirm (skip confirmation prompts)")

        # Top 3 preferred tools
        top_tools = sorted(
            prefs.get("preferred_tools", {}).items(),
            key=lambda x: x[1],
            reverse=True
        )[:3]
        if top_tools:
            tool_names = [t[0] for t in top_tools]
            hints.append(f"Favorite tools: {', '.join(tool_names)}")

        # Recent corrections (last 3)
        recent_corrections = self.data.get("corrections", [])[-3:]
        if recent_corrections:
            correction_hints = []
            for c in recent_corrections:
                correction_hints.append(
                    f"User corrected: '{c['ai_said'][:50]}' → wanted: '{c['user_wanted'][:50]}'"
                )
            hints.append("Recent corrections:\n  " + "\n  ".join(correction_hints))

        if not hints:
            return ""

        return "User preferences:\n" + "\n".join(f"- {h}" for h in hints)

    def get_stats_display(self) -> Dict[str, Any]:
        """Get displayable statistics"""
        stats = self.data["stats"]
        patterns = self.data["patterns"]

        avg_session = 0
        if patterns["session_durations"]:
            avg_session = sum(patterns["session_durations"]) / len(patterns["session_durations"])

        top_commands = sorted(
            patterns["common_commands"].items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]

        return {
            "total_sessions": stats["total_sessions"],
            "total_commands": stats["total_commands"],
            "total_findings": stats["total_findings"],
            "avg_session_minutes": round(avg_session, 1),
            "top_commands": top_commands,
            "tokens_lifetime": stats["tokens_lifetime"],
            "favorite_tools": sorted(
                self.data["preferences"]["preferred_tools"].items(),
                key=lambda x: x[1],
                reverse=True
            )[:5]
        }

    def export_data(self) -> dict:
        """Export all user memory data (for user to download)"""
        return self.data.copy()

    def delete_all(self):
        """Delete all user memory — user's right to be forgotten"""
        if os.path.exists(self.memory_file):
            os.remove(self.memory_file)
            logger.info(f"Deleted all memory for user: {self.username}")
        self.data = self._load()
