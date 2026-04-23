"""
NyxOS Memory System Tests.
Tests for session, project, and user memory persistence and aggregation.
"""

import json
import pytest
from pathlib import Path
from datetime import datetime


# ─── Lightweight memory implementations for testing ──────────

class SessionMemory:
    """In-RAM session memory (not persisted)."""

    def __init__(self):
        self.commands: list = []
        self.findings: list = []
        self.targets: list = []
        self.started_at: str = datetime.utcnow().isoformat()

    def record_command(self, cmd: dict) -> None:
        self.commands.append({**cmd, "ts": datetime.utcnow().isoformat()})

    def record_finding(self, finding: dict) -> None:
        self.findings.append({**finding, "ts": datetime.utcnow().isoformat()})

    def add_target(self, target: str) -> None:
        if target not in self.targets:
            self.targets.append(target)

    def get_context(self) -> dict:
        return {
            "commands": self.commands[-10:],
            "findings": self.findings,
            "targets": self.targets,
            "started_at": self.started_at,
        }


class ProjectMemory:
    """Disk-persisted project memory."""

    def __init__(self, name: str, base_dir: Path):
        self.name = name
        self.targets: list = []
        self.findings: list = []
        self.notes: list = []
        self.scope: dict = {}
        self._path = base_dir / name / "project.json"

    def add_finding(self, finding: dict) -> None:
        finding = {**finding, "id": f"F-{len(self.findings)+1:04d}"}
        self.findings.append(finding)

    def set_scope(self, scope: dict) -> None:
        self.scope = scope

    def get_summary(self) -> dict:
        sev = {}
        for f in self.findings:
            s = f.get("severity", "info")
            sev[s] = sev.get(s, 0) + 1
        return {"name": self.name, "findings": len(self.findings), "severity": sev}

    def save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps({
            "name": self.name, "targets": self.targets,
            "findings": self.findings, "notes": self.notes, "scope": self.scope,
        }, indent=2))

    def load(self) -> None:
        if self._path.exists():
            d = json.loads(self._path.read_text())
            self.name = d["name"]
            self.targets = d["targets"]
            self.findings = d["findings"]
            self.notes = d["notes"]
            self.scope = d["scope"]


class UserMemory:
    """Disk-persisted user learning memory."""

    def __init__(self, username: str, base_dir: Path):
        self.username = username
        self._path = base_dir / f"{username}.json"
        self.preferences: dict = {"preferred_tools": {}, "verbosity": "normal"}
        self.corrections: list = []
        self.stats: dict = {"total_commands": 0, "total_sessions": 0, "total_findings": 0}

    def record_command(self, tool: str = "") -> None:
        self.stats["total_commands"] += 1
        if tool:
            pt = self.preferences["preferred_tools"]
            pt[tool] = pt.get(tool, 0) + 1

    def record_correction(self, original: str, corrected: str) -> None:
        self.corrections.append({"original": original, "corrected": corrected})

    def record_session_end(self) -> None:
        self.stats["total_sessions"] += 1

    def save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps({
            "username": self.username, "preferences": self.preferences,
            "corrections": self.corrections, "stats": self.stats,
        }, indent=2))

    def load(self) -> None:
        if self._path.exists():
            d = json.loads(self._path.read_text())
            self.preferences = d["preferences"]
            self.corrections = d["corrections"]
            self.stats = d["stats"]


class MemoryManager:
    """Aggregates all three memory layers."""

    def __init__(self, username: str, project_name: str, base_dir: Path):
        self.session = SessionMemory()
        self.project = ProjectMemory(project_name, base_dir / "projects")
        self.user = UserMemory(username, base_dir / "memory")

    def get_full_context(self) -> dict:
        return {
            "session": self.session.get_context(),
            "project": self.project.get_summary(),
            "user_prefs": self.user.preferences,
        }

    def end_session(self) -> None:
        self.user.record_session_end()
        self.user.save()
        self.project.save()


# ═══════════════════════════════════════════════════════════════
# TestSessionMemory
# ═══════════════════════════════════════════════════════════════

class TestSessionMemory:
    """Session memory lives in RAM only."""

    @pytest.fixture
    def session(self):
        return SessionMemory()

    def test_record_command(self, session):
        session.record_command({"command": "nmap -sV 127.0.0.1"})
        assert len(session.commands) == 1
        assert session.commands[0]["command"] == "nmap -sV 127.0.0.1"
        assert "ts" in session.commands[0]

    def test_record_finding(self, session):
        session.record_finding({"title": "Port 80 open", "severity": "info"})
        assert len(session.findings) == 1
        assert session.findings[0]["severity"] == "info"

    def test_add_target_deduplicates(self, session):
        session.add_target("10.0.0.1")
        session.add_target("10.0.0.1")
        assert session.targets == ["10.0.0.1"]

    def test_get_context_limits(self, session):
        for i in range(20):
            session.record_command({"command": f"cmd_{i}"})
        ctx = session.get_context()
        assert len(ctx["commands"]) == 10

    def test_session_is_ram_only(self, tmp_path):
        """No files should be created by session memory."""
        import os
        before = set(os.listdir(tmp_path))
        s = SessionMemory()
        s.record_command({"command": "test"})
        s.record_finding({"title": "test"})
        s.add_target("1.2.3.4")
        after = set(os.listdir(tmp_path))
        assert before == after


# ═══════════════════════════════════════════════════════════════
# TestProjectMemory
# ═══════════════════════════════════════════════════════════════

class TestProjectMemory:
    """Project memory persists to disk."""

    @pytest.fixture
    def project(self, tmp_path):
        return ProjectMemory("engagement_alpha", tmp_path)

    def test_save_and_load(self, project):
        project.targets = ["192.168.1.0/24"]
        project.add_finding({"title": "Open SSH", "severity": "info"})
        project.set_scope({"targets": ["192.168.1.0/24"]})
        project.save()

        loaded = ProjectMemory("engagement_alpha", project._path.parent.parent)
        loaded.load()
        assert loaded.name == "engagement_alpha"
        assert loaded.targets == ["192.168.1.0/24"]
        assert len(loaded.findings) == 1
        assert loaded.scope["targets"] == ["192.168.1.0/24"]

    def test_add_finding_persists(self, project):
        project.add_finding({"title": "SQLi", "severity": "critical"})
        project.add_finding({"title": "XSS", "severity": "high"})
        project.save()

        loaded = ProjectMemory("engagement_alpha", project._path.parent.parent)
        loaded.load()
        assert len(loaded.findings) == 2
        assert loaded.findings[0]["id"] == "F-0001"
        assert loaded.findings[1]["id"] == "F-0002"

    def test_get_summary(self, project):
        project.add_finding({"title": "A", "severity": "critical"})
        project.add_finding({"title": "B", "severity": "critical"})
        project.add_finding({"title": "C", "severity": "low"})
        summary = project.get_summary()
        assert summary["findings"] == 3
        assert summary["severity"]["critical"] == 2
        assert summary["severity"]["low"] == 1

    def test_project_directory_created(self, project):
        project.save()
        assert project._path.exists()
        assert project._path.parent.is_dir()


# ═══════════════════════════════════════════════════════════════
# TestUserMemory
# ═══════════════════════════════════════════════════════════════

class TestUserMemory:
    """User memory learns preferences over time."""

    @pytest.fixture
    def user(self, tmp_path):
        return UserMemory("testuser", tmp_path)

    def test_record_updates_stats(self, user):
        user.record_command("nmap")
        user.record_command("nmap")
        user.record_command("gobuster")
        assert user.stats["total_commands"] == 3
        assert user.preferences["preferred_tools"]["nmap"] == 2
        assert user.preferences["preferred_tools"]["gobuster"] == 1

    def test_corrections_stored(self, user):
        user.record_correction("nmap -sV", "nmap -sCV")
        assert len(user.corrections) == 1
        assert user.corrections[0]["corrected"] == "nmap -sCV"

    def test_persistence(self, user):
        user.record_command("nmap")
        user.stats["total_sessions"] = 5
        user.save()

        loaded = UserMemory("testuser", user._path.parent)
        loaded.load()
        assert loaded.stats["total_commands"] == 1
        assert loaded.stats["total_sessions"] == 5
        assert loaded.preferences["preferred_tools"]["nmap"] == 1

    def test_session_end(self, user):
        user.record_session_end()
        assert user.stats["total_sessions"] == 1


# ═══════════════════════════════════════════════════════════════
# TestMemoryManager
# ═══════════════════════════════════════════════════════════════

class TestMemoryManager:
    """MemoryManager aggregates all three memory layers."""

    @pytest.fixture
    def manager(self, tmp_path):
        return MemoryManager("testuser", "test_project", tmp_path)

    def test_full_context_aggregates(self, manager):
        manager.session.record_command({"command": "nmap"})
        manager.session.record_finding({"title": "port 80"})
        manager.session.add_target("10.0.0.1")
        manager.project.add_finding({"title": "port 80", "severity": "info"})

        ctx = manager.get_full_context()
        assert "session" in ctx
        assert "project" in ctx
        assert "user_prefs" in ctx
        assert len(ctx["session"]["commands"]) == 1
        assert ctx["project"]["findings"] == 1

    def test_end_session_saves(self, manager):
        manager.session.record_command({"command": "test"})
        manager.project.add_finding({"title": "X", "severity": "high"})
        manager.end_session()

        assert manager.user.stats["total_sessions"] == 1
        assert manager.user._path.exists()
        assert manager.project._path.exists()

    def test_different_projects(self, tmp_path):
        m1 = MemoryManager("testuser", "project_a", tmp_path)
        m2 = MemoryManager("testuser", "project_b", tmp_path)
        m1.project.add_finding({"title": "A", "severity": "info"})
        m2.project.add_finding({"title": "B", "severity": "high"})
        m1.project.save()
        m2.project.save()

        assert m1.project.get_summary()["findings"] == 1
        assert m2.project.get_summary()["findings"] == 1
        assert m1.project._path != m2.project._path
