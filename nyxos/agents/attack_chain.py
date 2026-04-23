"""
NyxOS Attack Chain — Multi-step execution engine.

Executes a TaskPlanner plan step-by-step, handling dependencies,
failure recovery, user confirmation checkpoints, and adaptive re-planning.
"""

from __future__ import annotations

import json
import time
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from loguru import logger
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from nyxos.agents.task_planner import Task, TaskPlanner
from nyxos.core.memory.memory_manager import MemoryManager
from nyxos.core.security.audit_logger import AuditLogger
from nyxos.core.security.safety_guard import SafetyGuard, Scope
from nyxos.skills.base_skill import SkillResult
from nyxos.skills.skill_manager import SkillManager


console = Console()


@dataclass
class ChainResult:
    """Result of executing an entire attack chain."""

    tasks: List[Task]
    findings: List[Dict[str, Any]]
    duration_seconds: float
    success: bool
    report_path: Optional[str] = None
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "tasks": [t.to_dict() for t in self.tasks],
            "total_findings": len(self.findings),
            "duration_seconds": self.duration_seconds,
            "success": self.success,
            "report_path": self.report_path,
            "errors": self.errors,
        }


class AttackChain:
    """
    Executes a task plan step by step with dependency resolution,
    adaptive re-planning, and failure recovery.
    """

    def __init__(
        self,
        planner: TaskPlanner,
        skills: SkillManager,
        memory: MemoryManager,
        safety: SafetyGuard,
        audit: AuditLogger,
        scope: Optional[Scope] = None,
    ) -> None:
        """
        Initialize the AttackChain executor.

        Args:
            planner: TaskPlanner for adaptive re-planning.
            skills: SkillManager to execute skill tasks.
            memory: MemoryManager for persisting findings.
            safety: SafetyGuard for pre-execution checks.
            audit: AuditLogger for logging all actions.
            scope: Scope constraints for the engagement.
        """
        self.planner = planner
        self.skills = skills
        self.memory = memory
        self.safety = safety
        self.audit = audit
        self.scope = scope or Scope(targets=[], excluded_ranges=[], allowed_tools=[])
        self._broadcast_fn: Optional[Callable[[str, Dict[str, Any]], None]] = None
        self._paused = False
        self._aborted = False
        self._confirm_fn: Optional[Callable[[str], bool]] = None
        logger.debug("AttackChain initialized")

    def set_broadcast(self, fn: Callable[[str, Dict[str, Any]], None]) -> None:
        """Set a broadcast callback for real-time dashboard updates."""
        self._broadcast_fn = fn

    def set_confirm_fn(self, fn: Callable[[str], bool]) -> None:
        """Set a custom confirmation function (default: console prompt)."""
        self._confirm_fn = fn

    def pause(self) -> None:
        """Pause chain execution after current task completes."""
        self._paused = True
        logger.info("Attack chain paused")

    def resume(self) -> None:
        """Resume paused chain execution."""
        self._paused = False
        logger.info("Attack chain resumed")

    def abort(self) -> None:
        """Abort chain execution."""
        self._aborted = True
        logger.warning("Attack chain aborted")

    def execute(
        self,
        plan: List[Task],
        auto_confirm: bool = False,
    ) -> ChainResult:
        """
        Execute a task plan step by step.

        Steps:
        1. Validate all tasks via SafetyGuard
        2. Show plan to user and ask approval (unless auto_confirm)
        3. Execute tasks in dependency order
        4. Pass findings from task N to task N+1 (context chaining)
        5. After each task: update memory, broadcast to dashboard
        6. After port_scan: call adapt_plan() to dynamically add tasks
        7. On failure: ask AI whether to continue/abort/retry
        8. Return complete results

        Args:
            plan: Ordered list of Task objects.
            auto_confirm: Skip user confirmation prompts if True.

        Returns:
            ChainResult with all tasks, findings, and metadata.
        """
        start_time = time.time()
        all_findings: List[Dict[str, Any]] = []
        errors: List[str] = []

        self._paused = False
        self._aborted = False

        self.audit.log("COMMAND", "attack_chain_start", "system", {
            "task_count": len(plan),
            "tasks": [t.name for t in plan],
        })

        # Step 1: Validate plan
        valid, warnings = self.planner.validate_plan(plan, self.scope)
        for w in warnings:
            logger.warning(w)

        if not valid:
            console.print("[bold red]Plan validation failed:[/bold red]")
            for w in warnings:
                console.print(f"  • {w}")
            return ChainResult(
                tasks=plan,
                findings=[],
                duration_seconds=time.time() - start_time,
                success=False,
                errors=warnings,
            )

        # Step 2: Show plan and get approval
        if not auto_confirm:
            self._display_plan(plan)
            if not self._checkpoint("Execute this plan?"):
                logger.info("User declined plan execution")
                return ChainResult(
                    tasks=plan,
                    findings=[],
                    duration_seconds=time.time() - start_time,
                    success=False,
                    errors=["User declined execution"],
                )

        self._broadcast("chain_started", {"tasks": [t.name for t in plan]})

        # Step 3: Execute in dependency order
        completed_names: set = set()

        while True:
            # Check abort
            if self._aborted:
                logger.warning("Chain aborted by user")
                errors.append("Chain aborted by user")
                break

            # Check pause
            while self._paused:
                time.sleep(0.5)
                if self._aborted:
                    break

            # Find next executable task(s)
            ready_tasks = self._get_ready_tasks(plan, completed_names)
            if not ready_tasks:
                # Check if we're done or stuck
                pending = [t for t in plan if t.status == "pending"]
                if not pending:
                    break  # All done
                # Check for unresolvable dependencies
                stuck = all(
                    any(d not in completed_names for d in t.depends_on)
                    for t in pending
                )
                if stuck:
                    logger.error("Chain stuck: unresolvable dependencies")
                    errors.append("Unresolvable task dependencies")
                    for t in pending:
                        t.status = "skipped"
                    break
                continue

            # Execute ready tasks (sequentially for safety)
            for task in ready_tasks:
                if self._aborted:
                    break

                context = self._build_context(
                    [t for t in plan if t.status == "complete"]
                )

                self._broadcast("task_started", {"task": task.name, "skill": task.skill})

                self._execute_task(task, context)

                if task.status == "complete":
                    completed_names.add(task.name)

                    # Extract findings from result
                    task_findings = self._extract_findings(task)
                    all_findings.extend(task_findings)

                    # Store in memory
                    for finding in task_findings:
                        self.memory.session.record_finding(finding)
                        self.memory.project.add_finding(finding)

                    self._broadcast("task_completed", {
                        "task": task.name,
                        "findings_count": len(task_findings),
                    })

                    # Adaptive re-planning after port scan
                    if "port_scan" in task.name or "scan" in task.skill:
                        remaining = [t for t in plan if t.status == "pending"]
                        completed = [t for t in plan if t.status == "complete"]
                        new_tasks = self.planner.adapt_plan(
                            completed, all_findings, remaining, self.scope
                        )
                        if new_tasks:
                            logger.info("Adaptive planning added {} tasks", len(new_tasks))
                            if not auto_confirm:
                                self._display_new_tasks(new_tasks)
                                if self._checkpoint("Add these tasks to the plan?"):
                                    plan.extend(new_tasks)
                                    self._broadcast("plan_adapted", {
                                        "new_tasks": [t.name for t in new_tasks]
                                    })
                            else:
                                plan.extend(new_tasks)
                                self._broadcast("plan_adapted", {
                                    "new_tasks": [t.name for t in new_tasks]
                                })

                elif task.status == "failed":
                    errors.append(f"Task '{task.name}' failed: {task.error}")
                    decision = self._handle_failure(task, task.error or "Unknown error")

                    if decision == "abort":
                        self._aborted = True
                        break
                    elif decision == "retry":
                        task.status = "pending"
                        task.error = None
                    elif decision == "skip":
                        task.status = "skipped"
                        completed_names.add(task.name)  # Allow dependents to proceed
                    # "continue" → just move on, dependents may be skipped

        duration = time.time() - start_time
        success = all(
            t.status in ("complete", "skipped") for t in plan
        ) and not self._aborted

        self.audit.log("COMMAND", "attack_chain_complete", "system", {
            "success": success,
            "duration": duration,
            "findings": len(all_findings),
            "errors": errors,
        })

        self._broadcast("chain_completed", {
            "success": success,
            "findings_count": len(all_findings),
            "duration": duration,
        })

        result = ChainResult(
            tasks=plan,
            findings=all_findings,
            duration_seconds=duration,
            success=success,
            errors=errors,
        )

        # Save to project memory
        self.memory.project.add_note(
            f"Attack chain completed: {len(all_findings)} findings in {duration:.1f}s"
        )
        self.memory.project.save()

        return result

    def _execute_task(self, task: Task, context: Dict[str, Any]) -> None:
        """
        Execute a single task, updating its status and result.

        Args:
            task: Task to execute.
            context: Aggregated context from completed tasks.
        """
        task.status = "running"
        task.started_at = time.time()

        logger.info("Executing task: {} (skill: {})", task.name, task.skill)

        self.audit.log("SKILL_USE", f"task_execute:{task.name}", "system", {
            "skill": task.skill,
            "params": task.params,
        })

        try:
            # Safety check
            command_repr = f"{task.skill} {json.dumps(task.params)}"
            is_safe, reason, risk_level = self.safety.check(command_repr, self.scope)

            if not is_safe:
                task.status = "failed"
                task.error = f"SafetyGuard blocked: {reason}"
                task.completed_at = time.time()
                return

            if risk_level in ("HIGH", "CRITICAL"):
                logger.warning("High-risk task: {} — {}", task.name, reason)

            # Handle report tasks specially
            if task.skill == "report":
                task.result = {"type": "report_requested", "params": task.params}
                task.status = "complete"
                task.completed_at = time.time()
                return

            # Merge context into params
            enriched_params = {**task.params}
            if context.get("discovered_targets"):
                enriched_params.setdefault("context", {})["targets"] = context["discovered_targets"]
            if context.get("open_ports"):
                enriched_params.setdefault("context", {})["ports"] = context["open_ports"]

            # Execute via SkillManager
            result: SkillResult = self.skills.execute(task.skill, enriched_params)

            task.result = result
            task.status = "complete" if result.success else "failed"
            if not result.success:
                task.error = result.output[:500] if result.output else "Skill execution failed"

        except Exception as exc:
            logger.error("Task '{}' raised exception: {}", task.name, exc)
            task.status = "failed"
            task.error = str(exc)

        task.completed_at = time.time()

    def _handle_failure(self, task: Task, error: str) -> str:
        """
        Handle a failed task by asking AI for a decision.

        Args:
            task: The failed task.
            error: Error message.

        Returns:
            Decision string: "continue" | "abort" | "retry" | "skip"
        """
        logger.warning("Task '{}' failed: {}", task.name, error)

        console.print(Panel(
            f"[bold red]Task Failed:[/bold red] {task.name}\n"
            f"[red]Error:[/red] {error}",
            title="⚠ Task Failure",
            border_style="red",
        ))

        # Try AI-based decision
        try:
            prompt = (
                f"A task in our attack chain failed.\n"
                f"Task: {task.name} (skill: {task.skill})\n"
                f"Error: {error}\n\n"
                f"Should we: continue (skip this task), abort (stop everything), "
                f"retry (try again), or skip (mark as done and continue)?\n"
                f"Respond with exactly one word: continue, abort, retry, or skip."
            )
            response = self.planner.ai_router.route(
                prompt=prompt,
                system_prompt="You are a cybersecurity task executor. Respond with exactly one word.",
                history=[],
                task_type="simple",
            )
            decision = response.text.strip().lower().split()[0]
            if decision in ("continue", "abort", "retry", "skip"):
                logger.info("AI recommends: {}", decision)
                console.print(f"[yellow]AI recommends:[/yellow] {decision}")

                if self._checkpoint(f"Accept AI recommendation to {decision}?"):
                    return decision
        except Exception as exc:
            logger.warning("AI failure analysis failed: {}", exc)

        # Fall back to user choice
        console.print("\nOptions: [c]ontinue / [a]bort / [r]etry / [s]kip")
        try:
            choice = input("Choice [c/a/r/s]: ").strip().lower()
            mapping = {"c": "continue", "a": "abort", "r": "retry", "s": "skip"}
            return mapping.get(choice, "continue")
        except (EOFError, KeyboardInterrupt):
            return "abort"

    def _checkpoint(self, message: str) -> bool:
        """
        Pause and ask user for confirmation.

        Args:
            message: Confirmation message.

        Returns:
            True if user confirms.
        """
        if self._confirm_fn:
            return self._confirm_fn(message)

        try:
            response = input(f"\n[?] {message} [Y/n]: ").strip().lower()
            return response in ("", "y", "yes")
        except (EOFError, KeyboardInterrupt):
            return False

    def _get_ready_tasks(
        self, plan: List[Task], completed_names: set
    ) -> List[Task]:
        """Get tasks whose dependencies are all satisfied."""
        ready = []
        for task in plan:
            if task.status != "pending":
                continue
            deps_met = all(d in completed_names for d in task.depends_on)
            if deps_met:
                ready.append(task)
        return ready

    def _build_context(self, completed: List[Task]) -> Dict[str, Any]:
        """
        Aggregate findings from completed tasks into a context dict.

        Args:
            completed: List of completed tasks.

        Returns:
            Context dictionary with discovered targets, ports, services, etc.
        """
        context: Dict[str, Any] = {
            "discovered_targets": [],
            "open_ports": {},
            "services": [],
            "findings": [],
            "technologies": [],
        }

        for task in completed:
            if not task.result:
                continue

            result = task.result
            if isinstance(result, SkillResult):
                findings = result.findings or []
            elif isinstance(result, dict):
                findings = result.get("findings", [])
            else:
                continue

            for finding in findings:
                context["findings"].append(finding)
                host = finding.get("host", "")
                port = finding.get("port")
                service = finding.get("service", "")

                if host and host not in context["discovered_targets"]:
                    context["discovered_targets"].append(host)

                if host and port:
                    context["open_ports"].setdefault(host, []).append({
                        "port": port,
                        "service": service,
                        "version": finding.get("version", ""),
                    })

                if service:
                    context["services"].append({
                        "host": host,
                        "port": port,
                        "service": service,
                    })

                tech = finding.get("technology")
                if tech and tech not in context["technologies"]:
                    context["technologies"].append(tech)

        return context

    def _extract_findings(self, task: Task) -> List[Dict[str, Any]]:
        """Extract findings list from a task result."""
        if not task.result:
            return []

        if isinstance(task.result, SkillResult):
            return task.result.findings or []
        elif isinstance(task.result, dict):
            return task.result.get("findings", [])
        return []

    def _display_plan(self, plan: List[Task]) -> None:
        """Display the execution plan in a rich table."""
        table = Table(title="🗺 Attack Chain Plan", border_style="cyan")
        table.add_column("#", style="dim", width=4)
        table.add_column("Task", style="bold")
        table.add_column("Skill", style="cyan")
        table.add_column("Description")
        table.add_column("Depends On", style="dim")
        table.add_column("Priority", style="yellow")

        for i, task in enumerate(plan, 1):
            deps = ", ".join(task.depends_on) if task.depends_on else "—"
            table.add_row(
                str(i),
                task.name,
                task.skill,
                task.description or "—",
                deps,
                task.priority.value,
            )

        console.print(table)

    def _display_new_tasks(self, tasks: List[Task]) -> None:
        """Display newly discovered tasks from adaptive planning."""
        console.print("\n[bold yellow]📡 Adaptive Planning — New Tasks Discovered:[/bold yellow]")
        for task in tasks:
            console.print(f"  [cyan]+ {task.name}[/cyan] ({task.skill}) — {task.description}")

    def _broadcast(self, event_type: str, data: Dict[str, Any]) -> None:
        """Broadcast event to dashboard if callback is set."""
        if self._broadcast_fn:
            try:
                self._broadcast_fn(event_type, data)
            except Exception as exc:
                logger.debug("Broadcast failed: {}", exc)
