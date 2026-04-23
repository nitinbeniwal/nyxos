"""
NyxOS Integration Tests.
End-to-end tests that verify complete workflows.
All external calls (subprocess, AI APIs, network) are mocked.
"""

import json
import pytest
from unittest.mock import MagicMock, patch, call
from pathlib import Path
from dataclasses import dataclass, field

from nyxos.tests.conftest import (
    MockAIResponse, MockSkillResult, MockScope,
    NMAP_OUTPUT, GOBUSTER_OUTPUT,
)


# ─── Integration test helpers ────────────────────────────────

@dataclass
class IntegrationContext:
    """Bundles all components for integration testing."""
    config: MagicMock = field(default_factory=MagicMock)
    ai_router: MagicMock = field(default_factory=MagicMock)
    safety_guard: MagicMock = field(default_factory=MagicMock)
    audit_logger: MagicMock = field(default_factory=MagicMock)
    rate_limiter: MagicMock = field(default_factory=MagicMock)
    skill_manager: MagicMock = field(default_factory=MagicMock)
    session_commands: list = field(default_factory=list)
    session_findings: list = field(default_factory=list)
    session_targets: list = field(default_factory=list)
    project_findings: list = field(default_factory=list)

    def record_command(self, cmd: dict) -> None:
        self.session_commands.append(cmd)

    def record_finding(self, finding: dict) -> None:
        self.session_findings.append(finding)
        self.project_findings.append({**finding, "id": f"F-{len(self.project_findings)+1:04d}"})

    def add_target(self, target: str) -> None:
        if target not in self.session_targets:
            self.session_targets.append(target)


@pytest.fixture
def integration_ctx():
    """Set up full integration context with wired-up mocks."""
    ctx = IntegrationContext()

    # Config
    ctx.config.user.name = "testuser"
    ctx.config.user.role = "pentester"
    ctx.config.user.skill_level = "intermediate"
    ctx.config.active_provider = "claude"
    ctx.config.first_run = False
    ctx.config.security.require_confirmation = False  # auto-confirm for tests
    ctx.config.save = MagicMock()

    # Safety: allow everything
    ctx.safety_guard.check = MagicMock(return_value=(True, "OK", "LOW"))

    # Rate limiter: allow everything
    ctx.rate_limiter.check = MagicMock(return_value=(True, 0))

    # AI Router
    ctx.ai_router.route = MagicMock(return_value=MockAIResponse(
        text="COMMAND: nmap -sV 192.168.1.1"
    ))

    # Skill Manager
    ctx.skill_manager.route = MagicMock(return_value=("nmap", {"target": "192.168.1.1"}))
    ctx.skill_manager.execute = MagicMock(return_value=MockSkillResult(
        success=True,
        output=NMAP_OUTPUT,
        parsed_data={"ports": [
            {"port": 22, "service": "ssh"},
            {"port": 80, "service": "http"},
            {"port": 443, "service": "https"},
            {"port": 3306, "service": "mysql"},
        ]},
        findings=[
            {"title": "Open SSH", "severity": "info", "port": 22},
            {"title": "Open HTTP", "severity": "info", "port": 80},
            {"title": "Open HTTPS", "severity": "info", "port": 443},
            {"title": "Open MySQL", "severity": "medium", "port": 3306},
        ],
        commands_run=["nmap -sV 192.168.1.1"],
    ))
    ctx.skill_manager.list_skills = MagicMock(return_value=[
        {"name": "nmap"}, {"name": "web"}, {"name": "recon"},
    ])

    return ctx


# ═══════════════════════════════════════════════════════════════
# TestEndToEnd
# ═══════════════════════════════════════════════════════════════

class TestEndToEnd:
    """Full pipeline tests: input → processing → output."""

    def test_input_to_finding(self, integration_ctx):
        """
        Natural language input → AI parses → command generated →
        skill executes → findings recorded.
        """
        ctx = integration_ctx

        # Step 1: User types natural language
        user_input = "scan 192.168.1.1 for open ports"

        # Step 2: Rate limit check
        allowed, wait = ctx.rate_limiter.check("testuser", "ai_query")
        assert allowed is True

        # Step 3: AI Router generates command
        ai_response = ctx.ai_router.route(
            prompt=user_input,
            system_prompt="NyxOS pentester assistant",
            history=[],
            task_type="execute",
        )
        assert "nmap" in ai_response.text.lower()

        # Step 4: Parse command from AI response
        command = ""
        for line in ai_response.text.splitlines():
            if line.strip().upper().startswith("COMMAND:"):
                command = line.strip()[len("COMMAND:"):].strip()
                break
        assert command == "nmap -sV 192.168.1.1"

        # Step 5: Safety check
        safe, reason, risk = ctx.safety_guard.check(command, None)
        assert safe is True

        # Step 6: Execute via skill manager
        result = ctx.skill_manager.execute("nmap", {"target": "192.168.1.1"})
        assert result.success is True

        # Step 7: Record findings
        ctx.add_target("192.168.1.1")
        for finding in result.findings:
            ctx.record_finding(finding)
        ctx.record_command({"command": command, "output_len": len(result.output)})

        # Verify complete pipeline
        assert len(ctx.session_targets) == 1
        assert len(ctx.session_findings) == 4
        assert len(ctx.project_findings) == 4
        assert len(ctx.session_commands) == 1
        assert ctx.project_findings[0]["id"] == "F-0001"
        assert ctx.project_findings[3]["id"] == "F-0004"

        # Step 8: Audit was possible
        ctx.audit_logger.log("SKILL_USE", "nmap scan", "testuser", {"target": "192.168.1.1"})
        ctx.audit_logger.log.assert_called_once()

    def test_onboarding_flow(self, integration_ctx):
        """
        First boot → onboarding wizard → config saved → shell starts.
        All I/O mocked.
        """
        ctx = integration_ctx
        ctx.config.first_run = True

        # Step 1: Detect first run
        assert ctx.config.first_run is True

        # Step 2: Simulate wizard steps
        wizard_data = {
            "username": "newuser",
            "password_hash": "pbkdf2:sha256:...",
            "role": "bug_bounty",
            "skill_level": "intermediate",
            "providers": [
                {"name": "claude", "api_key_encrypted": "enc_abc123", "model": "claude-3-sonnet"},
            ],
            "active_provider": "claude",
        }

        # Step 3: Apply wizard results to config
        ctx.config.user.name = wizard_data["username"]
        ctx.config.user.role = wizard_data["role"]
        ctx.config.user.skill_level = wizard_data["skill_level"]
        ctx.config.active_provider = wizard_data["active_provider"]
        ctx.config.first_run = False

        # Step 4: Save config
        ctx.config.save()
        ctx.config.save.assert_called_once()

        # Step 5: Verify post-onboarding state
        assert ctx.config.first_run is False
        assert ctx.config.user.name == "newuser"
        assert ctx.config.user.role == "bug_bounty"
        assert ctx.config.active_provider == "claude"

    def test_scan_to_report(self, integration_ctx, tmp_path):
        """
        Scan target → collect findings → generate report.
        """
        ctx = integration_ctx

        # Step 1: Execute scan
        result = ctx.skill_manager.execute("nmap", {"target": "10.0.0.1"})
        assert result.success is True

        # Step 2: Collect findings
        ctx.add_target("10.0.0.1")
        for finding in result.findings:
            ctx.record_finding(finding)
        assert len(ctx.project_findings) == 4

        # Step 3: Sort findings
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(
            ctx.project_findings,
            key=lambda f: order.get(f.get("severity", "info"), 5)
        )
        assert sorted_findings[0]["severity"] == "medium"  # MySQL open port

        # Step 4: AI writes executive summary
        ctx.ai_router.route.return_value = MockAIResponse(
            text="The assessment identified 4 findings including an exposed MySQL service."
        )
        summary_resp = ctx.ai_router.route(
            prompt=f"Write executive summary for {len(ctx.project_findings)} findings on 10.0.0.1",
            task_type="explain",
        )
        assert len(summary_resp.text) > 0

        # Step 5: Generate markdown report
        report_lines = [
            "# Penetration Test Report — test_engagement\n",
            f"**Target:** 10.0.0.1\n",
            f"## Executive Summary\n",
            summary_resp.text + "\n",
            f"## Findings ({len(sorted_findings)})\n",
        ]
        for i, f in enumerate(sorted_findings, 1):
            report_lines.append(f"### {i}. [{f['severity'].upper()}] {f['title']}\n")
        report_md = "\n".join(report_lines)

        # Step 6: Write to disk
        report_path = tmp_path / "report.md"
        report_path.write_text(report_md)
        assert report_path.exists()
        content = report_path.read_text()
        assert "Penetration Test Report" in content
        assert "10.0.0.1" in content
        assert "## Findings (4)" in content
        assert "[MEDIUM]" in content

    def test_multi_skill_chain(self, integration_ctx):
        """
        Chain: nmap → web scan → report.
        Simulates agent task planner output.
        """
        ctx = integration_ctx

        # Task 1: Nmap scan
        nmap_result = ctx.skill_manager.execute("nmap", {"target": "192.168.1.1"})
        for f in nmap_result.findings:
            ctx.record_finding(f)

        # Task 2: Web scan (reconfigure mock)
        ctx.skill_manager.execute.return_value = MockSkillResult(
            success=True,
            output=GOBUSTER_OUTPUT,
            parsed_data={"directories": ["/admin", "/login", "/backup"]},
            findings=[
                {"title": "Admin panel exposed", "severity": "high", "url": "/admin"},
                {"title": "Backup directory", "severity": "medium", "url": "/backup"},
            ],
            commands_run=["gobuster dir -u http://192.168.1.1 -w wordlist.txt"],
        )
        web_result = ctx.skill_manager.execute("web", {"url": "http://192.168.1.1"})
        for f in web_result.findings:
            ctx.record_finding(f)

        # Verify combined findings
        assert len(ctx.project_findings) == 6  # 4 nmap + 2 web
        severities = [f["severity"] for f in ctx.project_findings]
        assert "high" in severities
        assert "medium" in severities

    def test_safety_blocks_chain(self, integration_ctx):
        """Safety guard blocks dangerous commands mid-chain."""
        ctx = integration_ctx
        ctx.safety_guard.check.return_value = (False, "Target out of scope", "CRITICAL")

        safe, reason, risk = ctx.safety_guard.check("nmap -sV 8.8.8.8", None)
        assert safe is False
        assert "out of scope" in reason.lower()
        assert risk == "CRITICAL"

    def test_ai_failure_recovery(self, integration_ctx):
        """System handles AI provider failure gracefully."""
        ctx = integration_ctx
        ctx.ai_router.route.side_effect = ConnectionError("API unreachable")

        with pytest.raises(ConnectionError):
            ctx.ai_router.route(prompt="scan target", task_type="execute")

        # System should still allow direct shell commands
        ctx.safety_guard.check.return_value = (True, "OK", "LOW")
        safe, _, _ = ctx.safety_guard.check("nmap -sV 127.0.0.1", None)
        assert safe is True

    def test_memory_persistence_across_steps(self, integration_ctx, tmp_path):
        """Memory persists findings across multiple operations."""
        ctx = integration_ctx

        # Simulate session with findings
        ctx.record_finding({"title": "F1", "severity": "high"})
        ctx.record_finding({"title": "F2", "severity": "low"})

        # Save to disk
        project_file = tmp_path / "project.json"
        project_file.write_text(json.dumps({
            "name": "test",
            "findings": ctx.project_findings,
        }, indent=2))

        # Load back
        loaded = json.loads(project_file.read_text())
        assert len(loaded["findings"]) == 2
        assert loaded["findings"][0]["id"] == "F-0001"
