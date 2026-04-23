"""
NyxOS Test Configuration
Shared fixtures for all test modules.
"""

import json
import pytest
from unittest.mock import MagicMock
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional


# ─── Mock dataclasses that mirror real ones ──────────────────────

@dataclass
class MockAIResponse:
    """Mirrors nyxos.core.ai_engine.adapter.AIResponse."""
    text: str = ""
    tokens_used: int = 50
    provider: str = "mock"
    model: str = "mock-model"
    cached: bool = False


@dataclass
class MockSkillResult:
    """Mirrors nyxos.skills.base_skill.SkillResult."""
    success: bool = True
    output: str = ""
    parsed_data: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)
    commands_run: list = field(default_factory=list)
    duration_seconds: float = 0.0


@dataclass
class MockScope:
    """Mirrors nyxos.core.security.safety_guard.Scope."""
    targets: list = field(default_factory=lambda: ["127.0.0.1", "192.168.1.0/24"])
    excluded_ranges: list = field(default_factory=list)
    allowed_tools: list = field(default_factory=lambda: ["nmap", "gobuster", "nikto"])


# ─── Shared Fixtures ─────────────────────────────────────────────

@pytest.fixture
def mock_config():
    """Fully mocked NyxConfig."""
    config = MagicMock()
    config.user.name = "testuser"
    config.user.role = "pentester"
    config.user.skill_level = "intermediate"
    config.active_provider = "mock_provider"
    config.first_run = False
    config.security.safety_level = "medium"
    config.security.allowed_commands = []
    config.security.blocked_commands = []
    config.security.require_confirmation = True
    config.tokens.daily_budget = 100000
    config.tokens.monthly_budget = 3000000
    config.ai_providers = {
        "mock_provider": MagicMock(
            provider="mock", model="mock-1", api_key_encrypted="enc_key"
        )
    }
    config.save = MagicMock()
    return config


@pytest.fixture
def mock_ai_router():
    """Mocked AIRouter that returns predictable responses."""
    router = MagicMock()
    router.route = MagicMock(
        return_value=MockAIResponse(text="COMMAND: nmap -sV 127.0.0.1")
    )
    router.get_usage_stats = MagicMock(return_value={"today": 500, "month": 5000})
    return router


@pytest.fixture
def mock_safety_guard():
    """Mocked SafetyGuard — allows everything by default."""
    guard = MagicMock()
    guard.check = MagicMock(return_value=(True, "OK", "LOW"))
    return guard


@pytest.fixture
def mock_audit_logger():
    """Mocked AuditLogger."""
    logger = MagicMock()
    logger.log = MagicMock()
    return logger


@pytest.fixture
def mock_rate_limiter():
    """Mocked RateLimiter — allows everything by default."""
    limiter = MagicMock()
    limiter.check = MagicMock(return_value=(True, 0))
    return limiter


@pytest.fixture
def mock_skill_manager():
    """Mocked SkillManager."""
    manager = MagicMock()
    manager.route = MagicMock(return_value=("nmap", {"target": "127.0.0.1"}))
    manager.execute = MagicMock(return_value=MockSkillResult(
        success=True,
        output="PORT   STATE SERVICE\n80/tcp open  http",
        parsed_data={"ports": [{"port": 80, "state": "open", "service": "http"}]},
        findings=[{"title": "Open HTTP port", "severity": "info", "port": 80}],
        commands_run=["nmap -sV 127.0.0.1"],
    ))
    manager.list_skills = MagicMock(return_value=[
        {"name": "nmap", "description": "Network port scanner"},
        {"name": "web", "description": "Web vulnerability scanner"},
        {"name": "recon", "description": "OSINT and reconnaissance"},
        {"name": "forensics", "description": "Digital forensics"},
        {"name": "ctf", "description": "CTF challenge helper"},
        {"name": "password", "description": "Password cracking"},
    ])
    return manager


@pytest.fixture
def mock_memory_manager():
    """Mocked MemoryManager with all three sub-memories."""
    mm = MagicMock()
    # Session
    mm.session.commands = []
    mm.session.findings = []
    mm.session.targets = []
    mm.session.get_context = MagicMock(return_value={
        "commands": [], "findings": [], "targets": [], "started_at": "2024-01-15T10:00:00"
    })
    mm.session.record_command = MagicMock()
    mm.session.record_finding = MagicMock()
    mm.session.add_target = MagicMock()
    # Project
    mm.project.name = "default"
    mm.project.findings = []
    mm.project.targets = []
    mm.project.get_summary = MagicMock(return_value={
        "name": "default", "total_findings": 0, "severity_counts": {}
    })
    mm.project.add_finding = MagicMock()
    mm.project.save = MagicMock()
    # User
    mm.user.preferences = {"preferred_tools": {}, "verbosity": "normal"}
    mm.user.stats = {"total_commands": 0, "total_sessions": 0}
    mm.user.save = MagicMock()
    mm.user.record_session_end = MagicMock()
    # Manager
    mm.get_full_context = MagicMock(return_value={
        "session": {"commands": [], "findings": [], "targets": []},
        "project": {"name": "default", "total_findings": 0},
        "user": {"preferences": {}, "hints": ""},
    })
    mm.end_session = MagicMock()
    return mm


# ─── Sample Tool Outputs ─────────────────────────────────────────

NMAP_OUTPUT = """Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for 192.168.1.1
Host is up (0.0012s latency).

PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.9p1
80/tcp   open  http     Apache httpd 2.4.52
443/tcp  open  ssl/http Apache httpd 2.4.52
3306/tcp open  mysql    MySQL 8.0.33

Nmap done: 1 IP address (1 host up) scanned in 12.34 seconds
"""

GOBUSTER_OUTPUT = """===============================================================
Gobuster v3.6
===============================================================
/admin                (Status: 200) [Size: 1234]
/login                (Status: 200) [Size: 5678]
/backup               (Status: 403) [Size: 278]
/api                  (Status: 301) [Size: 310]
/robots.txt           (Status: 200) [Size: 42]
===============================================================
"""

NIKTO_OUTPUT = """- Nikto v2.5.0
+ Target IP:          192.168.1.1
+ Target Port:        80
+ Server: Apache/2.4.52
+ /: The anti-clickjacking X-Frame-Options header is not present.
+ /admin/: Directory indexing found.
+ OSVDB-3092: /admin/: This might be interesting.
"""

CURL_HEADERS = """HTTP/1.1 200 OK
Server: Apache/2.4.52 (Ubuntu)
X-Powered-By: PHP/8.1
Content-Type: text/html; charset=UTF-8
"""

EXIFTOOL_OUTPUT = """File Name                       : document.pdf
File Size                       : 2.4 MB
File Type                       : PDF
Creator                         : John Doe
Create Date                     : 2024:01:10 14:30:00
Producer                        : LibreOffice 7.5
"""

WHOIS_OUTPUT = """Domain Name: EXAMPLE.COM
Registrar: Example Registrar Inc.
Creation Date: 1995-08-14T04:00:00Z
Registrant Organization: Example Inc.
Registrant Email: admin@example.com
Name Server: NS1.EXAMPLE.COM
Name Server: NS2.EXAMPLE.COM
"""

JOHN_OUTPUT = """Loaded 1 password hash (Raw-MD5)
password123      (admin)
1g 0:00:00:02 DONE
Session completed.
"""
