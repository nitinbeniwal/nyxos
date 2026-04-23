"""
NyxOS Task Planner — AI-powered task planning for multi-step operations.

Takes a high-level objective (e.g., "full pentest on 192.168.1.1") and breaks
it into ordered, dependency-aware sub-tasks that can be executed by the AttackChain.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from loguru import logger

from nyxos.core.ai_engine.router import AIRouter
from nyxos.core.security.safety_guard import SafetyGuard, Scope
from nyxos.skills.base_skill import SkillResult
from nyxos.skills.skill_manager import SkillManager


class TaskPriority(str, Enum):
    """Task execution priority."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class Task:
    """Represents a single step in an attack chain plan."""

    name: str
    skill: str
    params: Dict[str, Any]
    depends_on: List[str] = field(default_factory=list)
    status: str = "pending"  # pending | running | complete | failed | skipped
    priority: TaskPriority = TaskPriority.MEDIUM
    result: Optional[Any] = None
    error: Optional[str] = None
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    description: str = ""

    @property
    def duration_seconds(self) -> float:
        """Return execution duration in seconds."""
        if self.started_at and self.completed_at:
            return self.completed_at - self.started_at
        return 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Serialize task to dictionary."""
        return {
            "name": self.name,
            "skill": self.skill,
            "params": self.params,
            "depends_on": self.depends_on,
            "status": self.status,
            "priority": self.priority.value,
            "error": self.error,
            "description": self.description,
            "duration_seconds": self.duration_seconds,
        }


# Default methodology templates keyed by objective type
_METHODOLOGY_TEMPLATES: Dict[str, List[Dict[str, Any]]] = {
    "pentest": [
        {"name": "recon", "skill": "recon", "description": "OSINT and passive reconnaissance"},
        {"name": "port_scan", "skill": "nmap", "description": "Full TCP/UDP port scan with service detection"},
        {"name": "service_enum", "skill": "nmap", "description": "Detailed service enumeration and version detection"},
        {"name": "web_scan", "skill": "web", "description": "Web application vulnerability scanning", "depends_on": ["port_scan"]},
        {"name": "vuln_scan", "skill": "nmap", "description": "NSE vulnerability scripts", "depends_on": ["service_enum"]},
        {"name": "report", "skill": "report", "description": "Generate penetration test report", "depends_on": ["vuln_scan", "web_scan"]},
    ],
    "recon_only": [
        {"name": "whois_lookup", "skill": "recon", "description": "WHOIS and domain information"},
        {"name": "dns_enum", "skill": "recon", "description": "DNS enumeration"},
        {"name": "subdomain_discovery", "skill": "recon", "description": "Subdomain discovery"},
        {"name": "email_harvest", "skill": "recon", "description": "Email harvesting", "depends_on": ["whois_lookup"]},
        {"name": "port_scan", "skill": "nmap", "description": "Port scan for open services"},
        {"name": "report", "skill": "report", "description": "Generate recon report", "depends_on": ["port_scan", "email_harvest"]},
    ],
    "web_audit": [
        {"name": "fingerprint", "skill": "web", "description": "Web technology fingerprinting"},
        {"name": "dir_enum", "skill": "web", "description": "Directory and file enumeration"},
        {"name": "vuln_scan", "skill": "web", "description": "Web vulnerability scanning", "depends_on": ["fingerprint"]},
        {"name": "sqli_test", "skill": "web", "description": "SQL injection testing", "depends_on": ["dir_enum"]},
        {"name": "report", "skill": "report", "description": "Generate web audit report", "depends_on": ["vuln_scan", "sqli_test"]},
    ],
    "ctf": [
        {"name": "initial_recon", "skill": "recon", "description": "Initial target reconnaissance"},
        {"name": "port_scan", "skill": "nmap", "description": "Port scan"},
        {"name": "web_enum", "skill": "web", "description": "Web enumeration if HTTP found", "depends_on": ["port_scan"]},
        {"name": "file_analysis", "skill": "ctf", "description": "Analyze downloaded files"},
    ],
}

# AI prompt for generating task plans
_PLAN_PROMPT = """You are a cybersecurity task planner for NyxOS.
Given a high-level objective and available skills, generate an ordered list of tasks.

Available skills: {skills}
Scope: targets={targets}, excluded={excluded}
Objective: {objective}

Respond ONLY with a valid JSON array of task objects. Each task:
{{
    "name": "unique_task_name",
    "skill": "skill_name",
    "params": {{"param": "value"}},
    "depends_on": ["task_name"],
    "priority": "critical|high|medium|low",
    "description": "What this task does"
}}

Rules:
- Only use skills from the available list
- All targets must be within scope
- Order tasks logically (recon before scanning, scanning before exploitation)
- Include a report task at the end
- Be thorough but efficient
- Never include exploitation without explicit confirmation steps
"""

_ADAPT_PROMPT = """You are a cybersecurity task planner for NyxOS.
Based on findings from completed tasks, suggest additional tasks to add to the plan.

Completed tasks: {completed}
Current findings: {findings}
Available skills: {skills}
Remaining tasks: {remaining}

Respond ONLY with a valid JSON array of NEW task objects to insert.
Only add tasks that make sense given the findings. For example:
- Port 80/443 open → add web scanning tasks
- SMB (445) open → add SMB enumeration
- SSH open → note it but do NOT add brute force without explicit request
- Known vulnerable versions → add specific vuln check

If no new tasks needed, return an empty array: []
"""


class TaskPlanner:
    """
    AI-powered task planner that breaks high-level objectives into
    ordered, dependency-aware sub-tasks.
    """

    def __init__(
        self,
        ai_router: AIRouter,
        skills: SkillManager,
        safety: SafetyGuard,
    ) -> None:
        """
        Initialize the TaskPlanner.

        Args:
            ai_router: AI router for generating plans.
            skills: Skill manager with available skills.
            safety: Safety guard for validating tasks.
        """
        self.ai_router = ai_router
        self.skills = skills
        self.safety = safety
        logger.debug("TaskPlanner initialized")

    def plan(self, objective: str, scope: Scope) -> List[Task]:
        """
        Generate an ordered task list from a high-level objective.

        Uses AI to interpret the objective and map it to available skills,
        falling back to methodology templates if AI is unavailable.

        Args:
            objective: High-level objective string (e.g., "full pentest on 192.168.1.1").
            scope: Scope defining allowed targets and tools.

        Returns:
            Ordered list of Task objects ready for execution.
        """
        logger.info("Planning tasks for objective: {}", objective)

        # Extract target from objective
        target = self._extract_target(objective)

        # Validate target is in scope
        if target and not self._target_in_scope(target, scope):
            logger.warning("Target {} not in scope", target)
            raise ValueError(f"Target '{target}' is not within the defined scope: {scope.targets}")

        # Try AI-generated plan first
        tasks = self._ai_plan(objective, scope)

        # Fall back to template-based plan if AI fails
        if not tasks:
            logger.info("AI planning unavailable, falling back to templates")
            tasks = self._template_plan(objective, target, scope)

        # Validate the plan
        valid, warnings = self.validate_plan(tasks, scope)
        if warnings:
            for warning in warnings:
                logger.warning("Plan validation warning: {}", warning)

        if not valid:
            logger.error("Plan validation failed, returning empty plan")
            return []

        logger.info("Generated plan with {} tasks", len(tasks))
        return tasks

    def adapt_plan(
        self,
        completed_tasks: List[Task],
        findings: List[Dict[str, Any]],
        remaining_tasks: List[Task],
        scope: Scope,
    ) -> List[Task]:
        """
        Re-plan remaining tasks based on findings from completed tasks.

        Analyzes discoveries (open ports, services, etc.) and suggests
        additional tasks to add to the execution plan.

        Args:
            completed_tasks: Tasks that have already completed.
            findings: All findings discovered so far.
            remaining_tasks: Tasks still pending execution.
            scope: Current scope constraints.

        Returns:
            List of new Task objects to insert into the plan.
        """
        logger.info("Adapting plan based on {} findings", len(findings))

        new_tasks: List[Task] = []

        # Try AI-based adaptation
        ai_tasks = self._ai_adapt(completed_tasks, findings, remaining_tasks)
        if ai_tasks:
            new_tasks.extend(ai_tasks)
        else:
            # Fallback: rule-based adaptation
            new_tasks.extend(self._rule_based_adapt(findings, remaining_tasks, scope))

        # Validate new tasks
        validated = []
        for task in new_tasks:
            is_safe, reason, _ = self.safety.check(
                f"{task.skill} {json.dumps(task.params)}", scope
            )
            if is_safe:
                validated.append(task)
            else:
                logger.warning("Adapted task '{}' blocked by SafetyGuard: {}", task.name, reason)

        logger.info("Adaptation added {} new tasks", len(validated))
        return validated

    def validate_plan(self, tasks: List[Task], scope: Scope) -> Tuple[bool, List[str]]:
        """
        Validate every task in the plan against SafetyGuard.

        Args:
            tasks: List of tasks to validate.
            scope: Scope constraints.

        Returns:
            Tuple of (all_valid, list_of_warnings).
        """
        warnings: List[str] = []
        all_valid = True

        task_names = {t.name for t in tasks}

        for task in tasks:
            # Check dependencies exist
            for dep in task.depends_on:
                if dep not in task_names:
                    warnings.append(f"Task '{task.name}' depends on unknown task '{dep}'")
                    all_valid = False

            # Check skill exists
            available = self.skills.list_skills()
            skill_names = [s if isinstance(s, str) else getattr(s, "name", str(s)) for s in available]
            if task.skill not in skill_names and task.skill != "report":
                warnings.append(f"Task '{task.name}' uses unknown skill '{task.skill}'")

            # SafetyGuard check on params
            command_repr = f"{task.skill} {json.dumps(task.params)}"
            is_safe, reason, risk_level = self.safety.check(command_repr, scope)
            if not is_safe:
                warnings.append(f"Task '{task.name}' blocked: {reason}")
                all_valid = False
            elif risk_level in ("HIGH", "CRITICAL"):
                warnings.append(
                    f"Task '{task.name}' is {risk_level} risk: {reason} — will require confirmation"
                )

        # Check for circular dependencies
        if self._has_circular_deps(tasks):
            warnings.append("Plan contains circular dependencies")
            all_valid = False

        return all_valid, warnings

    # ─── Private helpers ───────────────────────────────────────────────

    def _ai_plan(self, objective: str, scope: Scope) -> List[Task]:
        """Generate plan via AI."""
        try:
            available_skills = self.skills.list_skills()
            skill_info = [
                s if isinstance(s, str) else getattr(s, "name", str(s))
                for s in available_skills
            ]

            prompt = _PLAN_PROMPT.format(
                skills=", ".join(skill_info),
                targets=scope.targets,
                excluded=scope.excluded_ranges,
                objective=objective,
            )

            response = self.ai_router.route(
                prompt=prompt,
                system_prompt="You are a cybersecurity task planner. Respond only with valid JSON.",
                history=[],
                task_type="complex",
            )

            return self._parse_tasks_json(response.text)
        except Exception as exc:
            logger.warning("AI planning failed: {}", exc)
            return []

    def _ai_adapt(
        self,
        completed_tasks: List[Task],
        findings: List[Dict[str, Any]],
        remaining_tasks: List[Task],
    ) -> List[Task]:
        """Generate adaptation via AI."""
        try:
            available_skills = self.skills.list_skills()
            skill_info = [
                s if isinstance(s, str) else getattr(s, "name", str(s))
                for s in available_skills
            ]

            prompt = _ADAPT_PROMPT.format(
                completed=json.dumps([t.to_dict() for t in completed_tasks], indent=2),
                findings=json.dumps(findings[:50], indent=2),  # limit context size
                skills=", ".join(skill_info),
                remaining=json.dumps([t.to_dict() for t in remaining_tasks], indent=2),
            )

            response = self.ai_router.route(
                prompt=prompt,
                system_prompt="You are a cybersecurity task planner. Respond only with valid JSON.",
                history=[],
                task_type="complex",
            )

            return self._parse_tasks_json(response.text)
        except Exception as exc:
            logger.warning("AI adaptation failed: {}", exc)
            return []

    def _template_plan(
        self, objective: str, target: Optional[str], scope: Scope
    ) -> List[Task]:
        """Fall back to methodology templates."""
        objective_lower = objective.lower()

        # Select template
        if any(kw in objective_lower for kw in ("pentest", "penetration", "full scan", "full audit")):
            template_key = "pentest"
        elif any(kw in objective_lower for kw in ("recon", "osint", "reconnaissance", "information gathering")):
            template_key = "recon_only"
        elif any(kw in objective_lower for kw in ("web", "website", "http", "application")):
            template_key = "web_audit"
        elif any(kw in objective_lower for kw in ("ctf", "capture the flag", "challenge")):
            template_key = "ctf"
        else:
            template_key = "pentest"  # default

        template = _METHODOLOGY_TEMPLATES[template_key]
        target = target or (scope.targets[0] if scope.targets else "unknown")

        tasks: List[Task] = []
        for entry in template:
            params: Dict[str, Any] = {"target": target}
            skill = entry["skill"]

            # Add skill-specific params
            if skill == "nmap":
                if "vuln" in entry["name"]:
                    params["scan_type"] = "vuln"
                elif "service" in entry["name"]:
                    params["scan_type"] = "service"
                else:
                    params["scan_type"] = "full"
            elif skill == "web":
                params["url"] = f"http://{target}"
                params["intent"] = entry.get("description", "vulnerability scan")
            elif skill == "recon":
                params["intent"] = entry.get("description", "full recon")
            elif skill == "report":
                params["type"] = template_key

            tasks.append(
                Task(
                    name=entry["name"],
                    skill=skill,
                    params=params,
                    depends_on=entry.get("depends_on", []),
                    priority=TaskPriority(entry.get("priority", "medium")),
                    description=entry.get("description", ""),
                )
            )

        return tasks

    def _rule_based_adapt(
        self,
        findings: List[Dict[str, Any]],
        remaining_tasks: List[Task],
        scope: Scope,
    ) -> List[Task]:
        """Rule-based plan adaptation from findings."""
        new_tasks: List[Task] = []
        remaining_names = {t.name for t in remaining_tasks}

        # Collect discovered ports/services
        open_ports: Dict[str, List[int]] = {}  # host -> [ports]
        services: List[Dict[str, Any]] = []

        for finding in findings:
            host = finding.get("host", finding.get("target", ""))
            port = finding.get("port")
            service = finding.get("service", "")

            if host and port:
                open_ports.setdefault(host, []).append(int(port))
                services.append(finding)

        for host, ports in open_ports.items():
            # HTTP/HTTPS found → add web scan if not already planned
            http_ports = [p for p in ports if p in (80, 443, 8080, 8443, 8000, 3000)]
            if http_ports and "web_scan" not in remaining_names:
                for p in http_ports:
                    scheme = "https" if p in (443, 8443) else "http"
                    new_tasks.append(
                        Task(
                            name=f"web_scan_{host}_{p}",
                            skill="web",
                            params={"url": f"{scheme}://{host}:{p}", "intent": "vulnerability scan"},
                            depends_on=["port_scan"],
                            priority=TaskPriority.HIGH,
                            description=f"Web vulnerability scan on {host}:{p}",
                        )
                    )

            # SMB found → add nmap smb scripts
            if any(p in ports for p in (139, 445)) and "smb_enum" not in remaining_names:
                new_tasks.append(
                    Task(
                        name=f"smb_enum_{host}",
                        skill="nmap",
                        params={
                            "target": host,
                            "scan_type": "script",
                            "scripts": "smb-enum-shares,smb-enum-users,smb-vuln*",
                            "ports": "139,445",
                        },
                        depends_on=["port_scan"],
                        priority=TaskPriority.HIGH,
                        description=f"SMB enumeration on {host}",
                    )
                )

        return new_tasks

    def _parse_tasks_json(self, text: str) -> List[Task]:
        """Parse JSON task array from AI response text."""
        # Extract JSON from response (handle markdown code blocks)
        cleaned = text.strip()
        if "```json" in cleaned:
            cleaned = cleaned.split("```json")[1].split("```")[0].strip()
        elif "```" in cleaned:
            cleaned = cleaned.split("```")[1].split("```")[0].strip()

        # Find array boundaries
        start = cleaned.find("[")
        end = cleaned.rfind("]")
        if start == -1 or end == -1:
            logger.warning("No JSON array found in AI response")
            return []

        try:
            raw_tasks = json.loads(cleaned[start : end + 1])
        except json.JSONDecodeError as exc:
            logger.warning("Failed to parse AI plan JSON: {}", exc)
            return []

        tasks: List[Task] = []
        for entry in raw_tasks:
            if not isinstance(entry, dict):
                continue
            try:
                tasks.append(
                    Task(
                        name=entry.get("name", f"task_{len(tasks)}"),
                        skill=entry.get("skill", ""),
                        params=entry.get("params", {}),
                        depends_on=entry.get("depends_on", []),
                        priority=TaskPriority(entry.get("priority", "medium")),
                        description=entry.get("description", ""),
                    )
                )
            except (ValueError, KeyError) as exc:
                logger.warning("Skipping malformed task entry: {} — {}", entry, exc)

        return tasks

    def _extract_target(self, objective: str) -> Optional[str]:
        """Extract a target IP/domain from the objective string."""
        import re

        # Match IP addresses
        ip_match = re.search(
            r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)\b", objective
        )
        if ip_match:
            return ip_match.group(1)

        # Match domain names
        domain_match = re.search(
            r"\b([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?)\b",
            objective,
        )
        if domain_match:
            return domain_match.group(1)

        return None

    def _target_in_scope(self, target: str, scope: Scope) -> bool:
        """Check if target is within scope."""
        if not scope.targets:
            return True  # No scope restrictions
        for allowed in scope.targets:
            if target == allowed or target.startswith(allowed.rstrip("/")):
                return True
            # CIDR matching (simple)
            if "/" in allowed and target.startswith(allowed.split("/")[0].rsplit(".", 1)[0]):
                return True
        return False

    def _has_circular_deps(self, tasks: List[Task]) -> bool:
        """Check for circular dependencies using DFS."""
        task_map = {t.name: t for t in tasks}
        visited: set = set()
        rec_stack: set = set()

        def _dfs(name: str) -> bool:
            visited.add(name)
            rec_stack.add(name)
            task = task_map.get(name)
            if task:
                for dep in task.depends_on:
                    if dep not in visited:
                        if _dfs(dep):
                            return True
                    elif dep in rec_stack:
                        return True
            rec_stack.discard(name)
            return False

        for t in tasks:
            if t.name not in visited:
                if _dfs(t.name):
                    return True
        return False
