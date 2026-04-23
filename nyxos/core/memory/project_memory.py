"""
NyxOS Project Memory (Medium-term)
Location: nyxos/core/memory/project_memory.py

Persists across sessions for a specific engagement/project.
"""

import os
import json
from typing import Dict, Any, List, Optional
from datetime import datetime
from loguru import logger

PROJECTS_DIR = os.path.expanduser("~/.nyxos/projects")


class ProjectMemory:
    """
    Medium-term memory tied to a specific project/engagement.

    A project might be:
    - A penetration test for a client
    - A bug bounty program
    - A CTF competition
    - A learning exercise

    Contains:
    - Target information
    - All findings from all sessions
    - Scope definition
    - Notes and screenshots references
    - Timeline of activities
    """

    def __init__(self, project_name: str = "default"):
        self.name = project_name
        self.project_dir = os.path.join(PROJECTS_DIR, project_name)
        self.data_file = os.path.join(self.project_dir, "project.json")
        self.data = self._load()

    def _load(self) -> dict:
        """Load project data from disk"""
        if os.path.exists(self.data_file):
            try:
                with open(self.data_file, "r") as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError) as e:
                logger.warning(f"Failed to load project {self.name}: {e}")

        return {
            "name": self.name,
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat(),
            "status": "active",
            "scope": {
                "targets": [],
                "excluded": [],
                "authorization": False,
                "rules_of_engagement": ""
            },
            "findings": [],
            "timeline": [],
            "notes": [],
            "sessions": [],
            "tags": [],
            "metadata": {
                "client": "",
                "assessor": "",
                "methodology": "",
                "start_date": "",
                "end_date": ""
            }
        }

    def save(self):
        """Save project data to disk with secure permissions"""
        os.makedirs(self.project_dir, mode=0o700, exist_ok=True)

        for subdir in ["scans", "reports", "evidence", "notes", "scripts", "loot"]:
            os.makedirs(os.path.join(self.project_dir, subdir), mode=0o700, exist_ok=True)

        self.data["updated_at"] = datetime.now().isoformat()

        with open(self.data_file, "w") as f:
            json.dump(self.data, f, indent=2, default=str)
        os.chmod(self.data_file, 0o600)

    def set_scope(self, targets: List[str], excluded: List[str] = None,
                  authorization: bool = False, roe: str = ""):
        """Set project scope"""
        self.data["scope"]["targets"] = targets
        self.data["scope"]["excluded"] = excluded or []
        self.data["scope"]["authorization"] = authorization
        self.data["scope"]["rules_of_engagement"] = roe
        self.add_timeline_event("Scope defined", "config")
        self.save()
        logger.info(f"Project scope set: {len(targets)} targets")

    def add_finding(self, finding: Dict[str, Any]):
        """Add a finding to the project"""
        finding["id"] = len(self.data["findings"]) + 1
        finding["discovered_at"] = datetime.now().isoformat()
        finding["status"] = finding.get("status", "new")
        self.data["findings"].append(finding)
        self.add_timeline_event(
            f"Finding #{finding['id']}: {finding.get('title', finding.get('type', 'unknown'))}",
            "finding"
        )
        self.save()

    def update_finding(self, finding_id: int, updates: Dict[str, Any]):
        """Update an existing finding"""
        for finding in self.data["findings"]:
            if finding.get("id") == finding_id:
                finding.update(updates)
                finding["updated_at"] = datetime.now().isoformat()
                self.save()
                return True
        return False

    def add_timeline_event(self, event: str, event_type: str = "action"):
        """Add event to project timeline"""
        self.data["timeline"].append({
            "timestamp": datetime.now().isoformat(),
            "event": event,
            "type": event_type
        })

    def add_note(self, note: str, category: str = "general"):
        """Add a note to the project"""
        self.data["notes"].append({
            "timestamp": datetime.now().isoformat(),
            "content": note,
            "category": category
        })
        self.save()

    def record_session(self, session_summary: Dict[str, Any]):
        """Record a session summary when session ends"""
        self.data["sessions"].append({
            "timestamp": datetime.now().isoformat(),
            "duration": session_summary.get("duration", "unknown"),
            "commands_run": session_summary.get("commands_run", 0),
            "findings_discovered": session_summary.get("findings_discovered", 0),
            "summary": session_summary.get("summary", "")
        })
        self.save()

    def get_findings_summary(self) -> Dict[str, int]:
        """Get findings count by severity"""
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in self.data["findings"]:
            severity = finding.get("severity", "info").lower()
            if severity in summary:
                summary[severity] += 1
        return summary

    def get_ai_context(self) -> str:
        """
        Build project context for AI prompts.
        Summarized to minimize tokens.
        """
        parts = []

        parts.append(f"Project: {self.name}")
        parts.append(f"Status: {self.data['status']}")

        scope = self.data["scope"]
        if scope["targets"]:
            parts.append(f"Targets in scope: {', '.join(scope['targets'][:10])}")
        if scope["excluded"]:
            parts.append(f"Excluded: {', '.join(scope['excluded'][:5])}")

        findings_summary = self.get_findings_summary()
        total = sum(findings_summary.values())
        if total > 0:
            parts.append(
                f"Findings: {total} total "
                f"(C:{findings_summary['critical']} H:{findings_summary['high']} "
                f"M:{findings_summary['medium']} L:{findings_summary['low']})"
            )

        # Last 5 timeline events
        recent_events = self.data["timeline"][-5:]
        if recent_events:
            events_str = "; ".join([e["event"] for e in recent_events])
            parts.append(f"Recent activity: {events_str}")

        return "\n".join(parts)

    def export_report_data(self) -> Dict[str, Any]:
        """Export all project data for report generation"""
        return {
            "project_name": self.name,
            "metadata": self.data["metadata"],
            "scope": self.data["scope"],
            "findings": sorted(
                self.data["findings"],
                key=lambda f: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
                    f.get("severity", "info").lower(), 5
                )
            ),
            "timeline": self.data["timeline"],
            "sessions": self.data["sessions"],
            "summary": self.get_findings_summary()
        }

    @staticmethod
    def list_projects() -> List[Dict[str, str]]:
        """List all projects"""
        projects = []
        if not os.path.exists(PROJECTS_DIR):
            return projects

        for name in os.listdir(PROJECTS_DIR):
            project_file = os.path.join(PROJECTS_DIR, name, "project.json")
            if os.path.exists(project_file):
                try:
                    with open(project_file, "r") as f:
                        data = json.load(f)
                    projects.append({
                        "name": name,
                        "status": data.get("status", "unknown"),
                        "created_at": data.get("created_at", ""),
                        "updated_at": data.get("updated_at", ""),
                        "findings_count": len(data.get("findings", []))
                    })
                except (json.JSONDecodeError, IOError):
                    pass

        return sorted(projects, key=lambda p: p.get("updated_at", ""), reverse=True)

    @staticmethod
    def create_project(name: str, metadata: Dict[str, str] = None) -> "ProjectMemory":
        """Create a new project"""
        project = ProjectMemory(name)
        if metadata:
            project.data["metadata"].update(metadata)
        project.save()
        logger.info(f"Created project: {name}")
        return project
