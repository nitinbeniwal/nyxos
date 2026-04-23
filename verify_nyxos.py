#!/usr/bin/env python3
"""
NyxOS Master Verification Script
==================================
Checks ALL work from Agents 1-10.
Run: python3 verify_nyxos.py
"""

import sys
import os
import importlib
import subprocess
from pathlib import Path

# ---- Setup ----
PASS = "\033[92m✅ PASS\033[0m"
FAIL = "\033[91m❌ FAIL\033[0m"
WARN = "\033[93m⚠️  WARN\033[0m"
HEADER = "\033[96m"
RESET = "\033[0m"

total_pass = 0
total_fail = 0
total_warn = 0
results = []


def check(description: str, condition: bool, warn_only: bool = False):
    global total_pass, total_fail, total_warn
    if condition:
        total_pass += 1
        results.append(f"  {PASS} {description}")
    elif warn_only:
        total_warn += 1
        results.append(f"  {WARN} {description}")
    else:
        total_fail += 1
        results.append(f"  {FAIL} {description}")


def section(title: str):
    results.append(f"\n{HEADER}{'='*60}")
    results.append(f"  {title}")
    results.append(f"{'='*60}{RESET}")


def try_import(module_path: str):
    try:
        return importlib.import_module(module_path), None
    except Exception as e:
        return None, str(e)


def file_exists(path: str) -> bool:
    return Path(path).exists()


def file_has_content(path: str, min_lines: int = 5) -> bool:
    p = Path(path)
    if not p.exists():
        return False
    try:
        lines = p.read_text(encoding="utf-8").strip().split("\n")
        return len(lines) >= min_lines
    except Exception:
        return False


def bash_syntax_ok(path: str) -> bool:
    try:
        result = subprocess.run(
            ["bash", "-n", path],
            capture_output=True, text=True, timeout=10
        )
        return result.returncode == 0
    except Exception:
        return False


def python_syntax_ok(path: str) -> bool:
    try:
        import py_compile
        py_compile.compile(path, doraise=True)
        return True
    except Exception:
        return False


# ============================================================
# PRE-FLIGHT
# ============================================================
section("PRE-FLIGHT CHECKS")

check("Python >= 3.10", sys.version_info >= (3, 10))
check("Running from project root", file_exists("nyxos/__init__.py") or file_exists("nyxos/core/__init__.py") or file_exists("nyxos/core/config/settings.py"))

# ============================================================
# COMPLETED CORE FILES (Pre-Agent work)
# ============================================================
section("CORE — Pre-built Files (Must Exist)")

core_files = {
    "nyxos/core/__init__.py": 0,
    "nyxos/core/config/settings.py": 20,
    "nyxos/core/security/encryption.py": 10,
    "nyxos/core/security/auth.py": 10,
    "nyxos/core/security/safety_guard.py": 10,
    "nyxos/core/security/audit_logger.py": 10,
    "nyxos/core/security/rate_limiter.py": 10,
    "nyxos/core/ai_engine/adapter.py": 10,
    "nyxos/core/ai_engine/router.py": 10,
    "nyxos/core/ai_engine/token_tracker.py": 10,
    "nyxos/core/ai_engine/cache.py": 10,
    "nyxos/core/ai_engine/system_prompts.py": 10,
    "nyxos/core/memory/session_memory.py": 10,
    "nyxos/core/memory/project_memory.py": 10,
    "nyxos/core/memory/user_memory.py": 10,
    "nyxos/core/memory/memory_manager.py": 10,
    "nyxos/skills/base_skill.py": 5,
    "nyxos/skills/skill_manager.py": 10,
    "nyxos/skills/nmap/nmap_skill.py": 10,
}

for filepath, min_lines in core_files.items():
    check(f"File: {filepath}", file_has_content(filepath, min_lines))

# ============================================================
# CORE IMPORTS
# ============================================================
section("CORE — Import Tests")

core_imports = [
    ("nyxos.core.config.settings", "NyxConfig, get_config"),
    ("nyxos.core.security.encryption", "EncryptionManager"),
    ("nyxos.core.security.auth", "AuthManager"),
    ("nyxos.core.security.safety_guard", "SafetyGuard"),
    ("nyxos.core.security.audit_logger", "AuditLogger"),
    ("nyxos.core.security.rate_limiter", "RateLimiter"),
    ("nyxos.core.ai_engine.adapter", None),
    ("nyxos.core.ai_engine.router", "AIRouter"),
    ("nyxos.core.ai_engine.token_tracker", "TokenTracker"),
    ("nyxos.core.ai_engine.cache", "ResponseCache"),
    ("nyxos.core.ai_engine.system_prompts", "get_system_prompt"),
    ("nyxos.core.memory.session_memory", "SessionMemory"),
    ("nyxos.core.memory.project_memory", "ProjectMemory"),
    ("nyxos.core.memory.user_memory", "UserMemory"),
    ("nyxos.core.memory.memory_manager", "MemoryManager"),
    ("nyxos.skills.base_skill", "BaseSkill"),
    ("nyxos.skills.skill_manager", "SkillManager"),
]

for mod_path, class_name in core_imports:
    mod, err = try_import(mod_path)
    if class_name:
        has_class = mod is not None and hasattr(mod, class_name.split(",")[0].strip())
        check(f"import {mod_path} → {class_name}", has_class)
    else:
        check(f"import {mod_path}", mod is not None)

# ============================================================
# AGENT 1 — Shell + main.py
# ============================================================
section("AGENT 1 — AI Shell + Entry Point")

check("File: nyxos/core/shell/nyxsh.py", file_has_content("nyxos/core/shell/nyxsh.py", 50))
check("File: main.py", file_has_content("main.py", 10))

mod, err = try_import("nyxos.core.shell.nyxsh")
check(f"import nyxos.core.shell.nyxsh", mod is not None, warn_only=True)
if mod:
    check("NyxShell class exists", hasattr(mod, "NyxShell"), warn_only=True)
    shell_cls = getattr(mod, "NyxShell", None)
    if shell_cls:
        for method in ["_classify_input", "_cmd_help", "_cmd_scan", "_cmd_analyze",
                       "_cmd_memory", "_cmd_project", "_cmd_report", "_cmd_skills",
                       "_cmd_stats", "_cmd_config", "_cmd_exit", "_handle_natural_language",
                       "_execute_shell_command", "run"]:
            check(f"  NyxShell.{method}() exists", hasattr(shell_cls, method), warn_only=True)

# ============================================================
# AGENT 2 — Onboarding
# ============================================================
section("AGENT 2 — Onboarding Wizard")

agent2_files = [
    "nyxos/onboarding/__init__.py",
    "nyxos/onboarding/wizard.py",
    "nyxos/onboarding/role_selector.py",
    "nyxos/onboarding/api_key_setup.py",
    "nyxos/onboarding/first_boot.py",
]
for f in agent2_files:
    check(f"File: {f}", file_has_content(f, 5))

for mod_name in ["nyxos.onboarding.wizard", "nyxos.onboarding.role_selector",
                 "nyxos.onboarding.api_key_setup", "nyxos.onboarding.first_boot"]:
    mod, err = try_import(mod_name)
    check(f"import {mod_name}", mod is not None, warn_only=True)

# ============================================================
# AGENT 3 — Web Skill + Forensics Skill
# ============================================================
section("AGENT 3 — Web Skill + Forensics Skill")

check("File: nyxos/skills/web/web_skill.py", file_has_content("nyxos/skills/web/web_skill.py", 20))
check("File: nyxos/skills/forensics/forensics_skill.py", file_has_content("nyxos/skills/forensics/forensics_skill.py", 20))

mod, err = try_import("nyxos.skills.web.web_skill")
check("import nyxos.skills.web.web_skill", mod is not None, warn_only=True)
if mod:
    check("  WebSkill class exists", hasattr(mod, "WebSkill"), warn_only=True)

mod, err = try_import("nyxos.skills.forensics.forensics_skill")
check("import nyxos.skills.forensics.forensics_skill", mod is not None, warn_only=True)
if mod:
    check("  ForensicsSkill class exists", hasattr(mod, "ForensicsSkill"), warn_only=True)

# ============================================================
# AGENT 4 — Recon + CTF + Password Skills
# ============================================================
section("AGENT 4 — Recon + CTF + Password Skills")

check("File: nyxos/skills/recon/recon_skill.py", file_has_content("nyxos/skills/recon/recon_skill.py", 20))
check("File: nyxos/skills/ctf/ctf_skill.py", file_has_content("nyxos/skills/ctf/ctf_skill.py", 20))
check("File: nyxos/skills/password/password_skill.py", file_has_content("nyxos/skills/password/password_skill.py", 20))

for mod_name, cls_name in [
    ("nyxos.skills.recon.recon_skill", "ReconSkill"),
    ("nyxos.skills.ctf.ctf_skill", "CTFSkill"),
    ("nyxos.skills.password.password_skill", "PasswordSkill"),
]:
    mod, err = try_import(mod_name)
    check(f"import {mod_name}", mod is not None, warn_only=True)
    if mod:
        check(f"  {cls_name} class exists", hasattr(mod, cls_name), warn_only=True)

# ============================================================
# AGENT 5 — Reporting Engine
# ============================================================
section("AGENT 5 — Reporting Engine")

agent5_files = [
    "nyxos/reporting/report_engine.py",
    "nyxos/reporting/templates/pentest_report.html",
    "nyxos/reporting/templates/bug_bounty_report.html",
    "nyxos/reporting/templates/executive_summary.html",
    "nyxos/reporting/exporters/pdf_exporter.py",
    "nyxos/reporting/exporters/markdown_exporter.py",
]
for f in agent5_files:
    check(f"File: {f}", file_has_content(f, 5))

mod, err = try_import("nyxos.reporting.report_engine")
check("import nyxos.reporting.report_engine", mod is not None, warn_only=True)
if mod:
    check("  ReportEngine class exists", hasattr(mod, "ReportEngine"), warn_only=True)

# ============================================================
# AGENT 6 — Dashboard Backend
# ============================================================
section("AGENT 6 — Dashboard Backend")

agent6_files = [
    "nyxos/dashboard/backend/server.py",
    "nyxos/dashboard/backend/api/routes.py",
    "nyxos/dashboard/backend/api/websocket.py",
    "nyxos/dashboard/backend/api/auth_routes.py",
    "nyxos/dashboard/backend/models/schemas.py",
]
for f in agent6_files:
    check(f"File: {f}", file_has_content(f, 5))

mod, err = try_import("nyxos.dashboard.backend.server")
check("import nyxos.dashboard.backend.server", mod is not None, warn_only=True)

mod, err = try_import("nyxos.dashboard.backend.models.schemas")
check("import nyxos.dashboard.backend.models.schemas", mod is not None, warn_only=True)

# ============================================================
# AGENT 7 — Dashboard Frontend
# ============================================================
section("AGENT 7 — Dashboard Frontend")

agent7_files = [
    "nyxos/dashboard/frontend/index.html",
    "nyxos/dashboard/frontend/assets/style.css",
    "nyxos/dashboard/frontend/assets/app.js",
    "nyxos/dashboard/frontend/components/terminal.js",
    "nyxos/dashboard/frontend/components/scan_viewer.js",
    "nyxos/dashboard/frontend/components/findings_panel.js",
]
for f in agent7_files:
    check(f"File: {f}", file_has_content(f, 5))

# Check HTML has required structure
index_path = Path("nyxos/dashboard/frontend/index.html")
if index_path.exists():
    html = index_path.read_text(encoding="utf-8", errors="replace")
    check("  index.html has <html> tag", "<html" in html.lower(), warn_only=True)
    check("  index.html has WebSocket reference", "websocket" in html.lower() or "ws://" in html.lower() or "app.js" in html.lower(), warn_only=True)

# ============================================================
# AGENT 8 — AI Agent Orchestration
# ============================================================
section("AGENT 8 — AI Agent Orchestration")

agent8_files = [
    "nyxos/agents/task_planner.py",
    "nyxos/agents/attack_chain.py",
    "nyxos/agents/recon_agent.py",
    "nyxos/agents/exploit_agent.py",
    "nyxos/agents/reporting_agent.py",
]
for f in agent8_files:
    check(f"File: {f}", file_has_content(f, 10))

for mod_name, cls_name in [
    ("nyxos.agents.task_planner", "TaskPlanner"),
    ("nyxos.agents.attack_chain", "AttackChain"),
    ("nyxos.agents.recon_agent", "ReconAgent"),
    ("nyxos.agents.exploit_agent", "ExploitAgent"),
    ("nyxos.agents.reporting_agent", "ReportingAgent"),
]:
    mod, err = try_import(mod_name)
    check(f"import {mod_name}", mod is not None, warn_only=True)
    if mod:
        check(f"  {cls_name} class exists", hasattr(mod, cls_name), warn_only=True)

# ============================================================
# AGENT 9 — Plugin System + Build Scripts
# ============================================================
section("AGENT 9 — Plugin System + Build Scripts")

agent9_py_files = [
    "nyxos/plugins/__init__.py",
    "nyxos/plugins/plugin_manager.py",
    "nyxos/plugins/plugin_loader.py",
    "nyxos/plugins/example_plugin/plugin.py",
]
for f in agent9_py_files:
    check(f"File: {f}", file_has_content(f, 5))
    if f.endswith(".py"):
        check(f"  Syntax: {f}", python_syntax_ok(f))

agent9_sh_files = [
    "nyxos/build/kali_remaster.sh",
    "nyxos/build/build_iso.sh",
    "nyxos/build/inject_nyxos.sh",
]
for f in agent9_sh_files:
    check(f"File: {f}", file_has_content(f, 20))
    check(f"  Bash syntax: {f}", bash_syntax_ok(f))

check("File: nyxos/build/preseed.cfg", file_has_content("nyxos/build/preseed.cfg", 20))

# Plugin functional test
mod, err = try_import("nyxos.plugins.plugin_manager")
check("import nyxos.plugins.plugin_manager", mod is not None)
if mod:
    check("  PluginManager class exists", hasattr(mod, "PluginManager"))
    check("  PluginInfo class exists", hasattr(mod, "PluginInfo"))
    try:
        pm = mod.PluginManager()
        loaded = pm.load_all()
        check(f"  PluginManager.load_all() works ({len(loaded)} plugins)", True)
        pm.fire_event("on_finding", finding={"title": "test", "severity": "info", "description": "verify"})
        check("  fire_event() works without crash", True)
    except Exception as e:
        check(f"  PluginManager functional test: {e}", False)

mod, err = try_import("nyxos.plugins.plugin_loader")
check("import nyxos.plugins.plugin_loader", mod is not None)
if mod:
    loader = mod.PluginLoader()
    ok, _ = loader.validate_manifest({"name": "t", "version": "1", "author": "a", "hooks": []})
    check("  validate_manifest() accepts valid manifest", ok)
    ok2, _ = loader.validate_manifest({"name": "t"})
    check("  validate_manifest() rejects invalid manifest", not ok2)

# ============================================================
# AGENT 10 — Tests + Docs + Packaging
# ============================================================
section("AGENT 10 — Tests, Docs, Packaging")

agent10_tests = [
    "nyxos/tests/test_shell.py",
    "nyxos/tests/test_skills.py",
    "nyxos/tests/test_memory.py",
    "nyxos/tests/test_reporting.py",
    "nyxos/tests/test_integration.py",
]
# Also accept tests/ at project root
for f in agent10_tests:
    alt = f.replace("nyxos/tests/", "tests/")
    exists = file_has_content(f, 5) or file_has_content(alt, 5)
    check(f"File: {f}", exists, warn_only=True)

agent10_docs = [
    "docs/README.md",
    "docs/INSTALL.md",
    "docs/CONTRIBUTING.md",
    "docs/SKILLS.md",
    "docs/AGENTS.md",
]
# Also check root level
for f in agent10_docs:
    alt = f.split("/")[-1]  # e.g., README.md at root
    exists = file_has_content(f, 5) or file_has_content(alt, 5)
    check(f"File: {f}", exists, warn_only=True)

agent10_packaging = [
    "setup.py",
    "requirements.txt",
    "LICENSE",
]
for f in agent10_packaging:
    check(f"File: {f}", file_has_content(f, 3), warn_only=True)

# ============================================================
# INTEGRATION CHECKS
# ============================================================
section("INTEGRATION — Cross-Agent Checks")

# Check main.py can at least be syntax-checked
if file_exists("main.py"):
    check("main.py syntax valid", python_syntax_ok("main.py"))

# Check all __init__.py files exist for proper package structure
init_files = [
    "nyxos/__init__.py",
    "nyxos/core/__init__.py",
    "nyxos/core/config/__init__.py",
    "nyxos/core/security/__init__.py",
    "nyxos/core/ai_engine/__init__.py",
    "nyxos/core/memory/__init__.py",
    "nyxos/core/shell/__init__.py",
    "nyxos/onboarding/__init__.py",
    "nyxos/skills/__init__.py",
    "nyxos/skills/nmap/__init__.py",
    "nyxos/skills/web/__init__.py",
    "nyxos/skills/forensics/__init__.py",
    "nyxos/skills/recon/__init__.py",
    "nyxos/skills/ctf/__init__.py",
    "nyxos/skills/password/__init__.py",
    "nyxos/reporting/__init__.py",
    "nyxos/reporting/exporters/__init__.py",
    "nyxos/dashboard/__init__.py",
    "nyxos/dashboard/backend/__init__.py",
    "nyxos/dashboard/backend/api/__init__.py",
    "nyxos/dashboard/backend/models/__init__.py",
    "nyxos/agents/__init__.py",
    "nyxos/plugins/__init__.py",
]
missing_inits = [f for f in init_files if not file_exists(f)]
check(f"Package __init__.py files ({len(init_files) - len(missing_inits)}/{len(init_files)})",
      len(missing_inits) == 0, warn_only=True)
if missing_inits:
    for f in missing_inits[:10]:
        results.append(f"    Missing: {f}")

# Count total Python files
py_count = len(list(Path("nyxos").rglob("*.py")))
check(f"Total Python files in nyxos/: {py_count}", py_count >= 30, warn_only=True)

# Count total lines of code
total_lines = 0
for py_file in Path("nyxos").rglob("*.py"):
    try:
        total_lines += len(py_file.read_text(encoding="utf-8", errors="replace").split("\n"))
    except Exception:
        pass
if file_exists("main.py"):
    try:
        total_lines += len(Path("main.py").read_text(encoding="utf-8").split("\n"))
    except Exception:
        pass

results.append(f"\n  📊 Total lines of Python code: {total_lines:,}")

# ============================================================
# SUMMARY
# ============================================================
results.append(f"\n{HEADER}{'='*60}")
results.append(f"  VERIFICATION SUMMARY")
results.append(f"{'='*60}{RESET}")

for line in results:
    print(line)

print(f"\n  ✅ Passed:  {total_pass}")
print(f"  ❌ Failed:  {total_fail}")
print(f"  ⚠️  Warned:  {total_warn}")
print(f"  📦 Total:   {total_pass + total_fail + total_warn}")
print()

if total_fail == 0:
    print(f"  {HEADER}🎉 ALL CHECKS PASSED — NyxOS is ready to build!{RESET}")
elif total_fail <= 5:
    print(f"  \033[93m⚡ Minor issues found — mostly complete.{RESET}")
else:
    print(f"  \033[91m🚨 Significant gaps — review FAIL items above.{RESET}")

print()

# Return exit code
sys.exit(0 if total_fail == 0 else 1)
