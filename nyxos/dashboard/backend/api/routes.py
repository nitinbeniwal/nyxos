"""
NyxOS Dashboard — REST API Routes

All REST endpoints for the NyxOS web dashboard.
Every endpoint (except auth) requires a valid Bearer token.

Actual method signatures matched:
    AIRouter.generate(prompt, system_prompt='', max_tokens=4096, temperature=0.3,
                      provider_override=None, use_cache=True, task_type='general') -> AIResponse
    TokenTracker(config: TokenConfig) / .record_usage(provider, model, input_tokens, output_tokens, total_tokens)
                                       / .get_stats() -> dict / .check_budget(estimated_tokens=0) -> (bool, str)
    SkillManager.find_skill_for_task(user_input) -> Optional[BaseSkill]
    SkillManager.list_skills() -> List[dict]
    SkillManager.get_skill(name) -> Optional[BaseSkill]
    BaseSkill.execute(user_input: str, context: Dict[str, Any]) -> SkillResult
    AuthManager(encryption: EncryptionManager) / .authenticate(username, password) -> Optional[Session]
    MemoryManager(username='default', project_name='default')
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from loguru import logger

from nyxos.dashboard.backend.api.auth_routes import get_current_user
from nyxos.dashboard.backend.api.websocket import manager as ws_manager
from nyxos.dashboard.backend.models.schemas import (
    CommandRequest,
    CommandResponse,
    FindingSchema,
    FindingsListResponse,
    MessageResponse,
    ProjectSchema,
    ProjectsListResponse,
    ReportRequest,
    ReportResponse,
    ScanSchema,
    ScansListResponse,
    SessionMemoryResponse,
    SkillInfo,
    SkillsListResponse,
    StatsResponse,
    StatusResponse,
)

# ---------------------------------------------------------------------------
# Lazy-loaded singletons (each wrapped in try/except for resilience)
# ---------------------------------------------------------------------------

_config = None
_memory_manager = None
_ai_router = None
_token_tracker = None
_skill_manager = None
_safety_guard = None
_audit_logger = None
_encryption = None
_server_start_time: float = time.time()

# In-memory scan history
_scan_history: List[Dict[str, Any]] = []


def _get_config():
    """Lazy-load NyxOS config."""
    global _config
    if _config is None:
        try:
            from nyxos.core.config.settings import get_config
            _config = get_config()
        except Exception as exc:
            logger.warning(f"Could not load NyxOS config: {exc}")
    return _config


def _get_encryption():
    """Lazy-load encryption manager."""
    global _encryption
    if _encryption is None:
        try:
            from nyxos.core.security.encryption import EncryptionManager
            _encryption = EncryptionManager()
        except Exception as exc:
            logger.warning(f"Could not load EncryptionManager: {exc}")
    return _encryption


def _get_memory_manager():
    """Lazy-load memory manager.  MemoryManager(username, project_name)."""
    global _memory_manager
    if _memory_manager is None:
        try:
            from nyxos.core.memory.memory_manager import MemoryManager
            config = _get_config()
            username = "default"
            if config and hasattr(config, "user") and hasattr(config.user, "name"):
                username = config.user.name or "default"
            _memory_manager = MemoryManager(username=username, project_name="default")
        except Exception as exc:
            logger.warning(f"Could not load MemoryManager: {exc}")
    return _memory_manager


def _get_ai_router():
    """Lazy-load AI router.  AIRouter(config: NyxConfig, encryption: EncryptionManager)."""
    global _ai_router
    if _ai_router is None:
        try:
            from nyxos.core.ai_engine.router import AIRouter
            config = _get_config()
            enc = _get_encryption()
            if config and enc:
                _ai_router = AIRouter(config=config, encryption=enc)
        except Exception as exc:
            logger.warning(f"Could not load AIRouter: {exc}")
    return _ai_router


def _get_token_tracker():
    """Lazy-load token tracker.  TokenTracker(config: TokenConfig)."""
    global _token_tracker
    if _token_tracker is None:
        try:
            from nyxos.core.ai_engine.token_tracker import TokenTracker
            config = _get_config()
            if config and hasattr(config, "tokens"):
                _token_tracker = TokenTracker(config=config.tokens)
            else:
                logger.warning("TokenConfig not available, skipping TokenTracker")
        except Exception as exc:
            logger.warning(f"Could not load TokenTracker: {exc}")
    return _token_tracker


def _get_skill_manager():
    """Lazy-load skill manager.  SkillManager() — auto-discovers skills."""
    global _skill_manager
    if _skill_manager is None:
        try:
            from nyxos.skills.skill_manager import SkillManager
            _skill_manager = SkillManager()
        except Exception as exc:
            logger.warning(f"Could not load SkillManager: {exc}")
    return _skill_manager


def _get_safety_guard():
    """Lazy-load safety guard."""
    global _safety_guard
    if _safety_guard is None:
        try:
            from nyxos.core.security.safety_guard import SafetyGuard
            _safety_guard = SafetyGuard()
        except Exception as exc:
            logger.warning(f"Could not load SafetyGuard: {exc}")
    return _safety_guard


def _get_audit_logger():
    """Lazy-load audit logger."""
    global _audit_logger
    if _audit_logger is None:
        try:
            from nyxos.core.security.audit_logger import AuditLogger
            _audit_logger = AuditLogger()
        except Exception as exc:
            logger.warning(f"Could not load AuditLogger: {exc}")
    return _audit_logger


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _findings_to_schemas(findings: List[Dict[str, Any]]) -> List[FindingSchema]:
    """Convert raw finding dicts into validated FindingSchema instances."""
    schemas: List[FindingSchema] = []
    valid_severities = {"critical", "high", "medium", "low", "info"}
    for idx, f in enumerate(findings):
        finding_id = f.get("id") or hashlib.md5(
            f"{f.get('title', '')}{f.get('timestamp', '')}{idx}".encode()
        ).hexdigest()[:12]

        severity = f.get("severity", "info")
        if severity not in valid_severities:
            severity = "info"

        schemas.append(FindingSchema(
            id=finding_id,
            type=f.get("type", "unknown"),
            title=f.get("title", "Untitled Finding"),
            severity=severity,
            description=f.get("description", ""),
            evidence=f.get("evidence", ""),
            timestamp=f.get("timestamp", datetime.utcnow().isoformat() + "Z"),
            url=f.get("url"),
            host=f.get("host"),
            port=f.get("port"),
            service=f.get("service"),
            recommendation=f.get("recommendation"),
            tool_used=f.get("tool_used"),
            false_positive=f.get("false_positive", False),
        ))
    return schemas


def _count_by_severity(findings: List[FindingSchema]) -> Dict[str, int]:
    """Count findings per severity level."""
    counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def _record_scan(
    skill: str, target: str, command: str,
    success: bool, findings_count: int, start: float,
) -> Dict[str, Any]:
    """Create a scan record and append to history."""
    record: Dict[str, Any] = {
        "id": uuid.uuid4().hex[:8],
        "skill": skill,
        "target": target,
        "command": command,
        "status": "complete" if success else "failed",
        "started_at": datetime.utcfromtimestamp(start).isoformat() + "Z",
        "completed_at": datetime.utcnow().isoformat() + "Z",
        "findings_count": findings_count,
        "duration_seconds": round(time.time() - start, 2),
    }
    _scan_history.append(record)
    return record


def _get_memory_context() -> Dict[str, Any]:
    """Build context dict from memory for AI prompts."""
    memory = _get_memory_manager()
    if not memory:
        return {}
    try:
        ctx = memory.get_full_context()
        return ctx if isinstance(ctx, dict) else {}
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------
router = APIRouter(tags=["api"])


# ===========================  GET /api/status  =============================
@router.get("/status", response_model=StatusResponse, summary="System status overview")
async def get_status(user: str = Depends(get_current_user)) -> StatusResponse:
    """Return the current NyxOS system status."""
    config = _get_config()
    memory = _get_memory_manager()
    tracker = _get_token_tracker()

    active_provider = "none"
    active_model: Optional[str] = None
    current_project = "default"
    session_commands = 0
    session_findings = 0
    token_remaining = 0
    role: Optional[str] = None
    username = user
    daily_budget = 0

    if config:
        active_provider = getattr(config, "active_provider", "none") or "none"
        if hasattr(config, "ai_providers") and isinstance(config.ai_providers, dict):
            prov_cfg = config.ai_providers.get(active_provider)
            if prov_cfg:
                active_model = getattr(prov_cfg, "model", None)
        if hasattr(config, "user"):
            role = getattr(config.user, "role", None)
            username = getattr(config.user, "name", user) or user
        if hasattr(config, "tokens"):
            daily_budget = getattr(config.tokens, "daily_budget", 0)

    if memory:
        try:
            sess = memory.session
            session_commands = len(getattr(sess, "commands", []))
            session_findings = len(getattr(sess, "findings", []))
        except Exception:
            pass

    # TokenTracker.get_stats() -> dict
    token_remaining = daily_budget
    if tracker:
        try:
            stats = tracker.get_stats()
            if isinstance(stats, dict):
                today_used = stats.get("today", stats.get("tokens_today", 0))
                token_remaining = max(0, daily_budget - today_used)
        except Exception:
            pass

    return StatusResponse(
        active_provider=active_provider,
        active_model=active_model,
        current_project=current_project,
        session_commands=session_commands,
        session_findings=session_findings,
        token_budget_remaining=token_remaining,
        uptime_seconds=round(time.time() - _server_start_time, 2),
        version="0.1.0",
        user=username,
        role=role,
    )


# ===========================  GET /api/findings  ===========================
@router.get("/findings", response_model=FindingsListResponse, summary="All project findings")
async def get_findings(user: str = Depends(get_current_user)) -> FindingsListResponse:
    """Return all findings from the current project, sorted by severity."""
    memory = _get_memory_manager()
    raw: List[Dict[str, Any]] = []

    if memory:
        try:
            project = memory.project
            if hasattr(project, "findings"):
                raw.extend(project.findings)
            sess = memory.session
            if hasattr(sess, "findings"):
                seen = {(f.get("title", ""), f.get("host", "")) for f in raw}
                for f in sess.findings:
                    key = (f.get("title", ""), f.get("host", ""))
                    if key not in seen:
                        raw.append(f)
                        seen.add(key)
        except Exception as exc:
            logger.error(f"Error fetching findings: {exc}")

    schemas = _findings_to_schemas(raw)
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    schemas.sort(key=lambda f: sev_order.get(f.severity, 5))

    return FindingsListResponse(
        findings=schemas, total=len(schemas), by_severity=_count_by_severity(schemas),
    )


# ========================  GET /api/findings/{id}  =========================
@router.get("/findings/{finding_id}", response_model=FindingSchema, summary="Single finding")
async def get_finding(finding_id: str, user: str = Depends(get_current_user)) -> FindingSchema:
    """Return a single finding by ID."""
    all_resp = await get_findings(user)
    for finding in all_resp.findings:
        if finding.id == finding_id:
            return finding
    raise HTTPException(status_code=404, detail=f"Finding '{finding_id}' not found.")


# ===========================  GET /api/scans  ==============================
@router.get("/scans", response_model=ScansListResponse, summary="Scan history")
async def get_scans(user: str = Depends(get_current_user)) -> ScansListResponse:
    """Return all scans executed this session."""
    scans = [
        ScanSchema(
            id=s.get("id", uuid.uuid4().hex[:8]),
            skill=s.get("skill", "unknown"),
            target=s.get("target", "unknown"),
            command=s.get("command", ""),
            status=s.get("status", "complete"),
            started_at=s.get("started_at", datetime.utcnow().isoformat() + "Z"),
            completed_at=s.get("completed_at"),
            findings_count=s.get("findings_count", 0),
            duration_seconds=s.get("duration_seconds"),
        )
        for s in _scan_history
    ]
    return ScansListResponse(scans=scans, total=len(scans))


# =======================  GET /api/memory/session  =========================
@router.get("/memory/session", response_model=SessionMemoryResponse, summary="Session memory")
async def get_session_memory(user: str = Depends(get_current_user)) -> SessionMemoryResponse:
    """Return the current session's in-memory state."""
    memory = _get_memory_manager()
    commands: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []
    targets: List[str] = []
    started_at: Optional[str] = None

    if memory:
        try:
            sess = memory.session
            commands = list(getattr(sess, "commands", []))
            findings = list(getattr(sess, "findings", []))
            targets = list(getattr(sess, "targets", []))
            started_at = getattr(sess, "started_at", None)
        except Exception as exc:
            logger.error(f"Error reading session memory: {exc}")

    return SessionMemoryResponse(
        commands=commands, findings=findings, targets=targets, started_at=started_at,
    )


# =====================  DELETE /api/memory/session  ========================
@router.delete("/memory/session", response_model=MessageResponse, summary="Clear session memory")
async def clear_session_memory(user: str = Depends(get_current_user)) -> MessageResponse:
    """Clear all session memory. Project and user memory are unaffected."""
    memory = _get_memory_manager()
    if memory:
        try:
            sess = memory.session
            for attr in ("commands", "findings", "targets"):
                lst = getattr(sess, attr, None)
                if isinstance(lst, list):
                    lst.clear()
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Failed to clear: {exc}")

    audit = _get_audit_logger()
    if audit:
        try:
            audit.log("CONFIG", "clear_session_memory", user, {"source": "dashboard"})
        except Exception:
            pass

    return MessageResponse(success=True, message="Session memory cleared.")


# ===========================  GET /api/stats  ==============================

# ===========================  GET /api/stats  ==============================
@router.get("/stats", response_model=StatsResponse, summary="Token and usage stats")
async def get_stats(user: str = Depends(get_current_user)) -> StatsResponse:
    """Return token consumption and usage statistics."""
    tracker = _get_token_tracker()
    config = _get_config()
    memory = _get_memory_manager()

    tokens_today = 0
    tokens_month = 0
    tokens_total = 0
    budget_daily = 0
    budget_monthly = 0
    budget_ok = True
    budget_warning: Optional[str] = None
    sessions_total = 0
    commands_total = 0
    providers_usage: Dict[str, int] = {}

    if config and hasattr(config, "tokens"):
        budget_daily = getattr(config.tokens, "daily_budget", 0)
        budget_monthly = getattr(config.tokens, "monthly_budget", 0)

    if tracker:
        try:
            stats = tracker.get_stats()
            if isinstance(stats, dict):
                today_data = stats.get("today", {})
                if isinstance(today_data, dict):
                    tokens_today = today_data.get("tokens_used", 0)
                elif isinstance(today_data, (int, float)):
                    tokens_today = int(today_data)

                month_data = stats.get("this_month", {})
                if isinstance(month_data, dict):
                    tokens_month = month_data.get("tokens_used", 0)
                elif isinstance(month_data, (int, float)):
                    tokens_month = int(month_data)

                alltime_data = stats.get("all_time", {})
                if isinstance(alltime_data, dict):
                    tokens_total = alltime_data.get("total_tokens", 0)
                elif isinstance(alltime_data, (int, float)):
                    tokens_total = int(alltime_data)

                by_provider = stats.get("by_provider", {})
                if isinstance(by_provider, dict):
                    for prov_name, prov_data in by_provider.items():
                        if isinstance(prov_data, dict):
                            providers_usage[prov_name] = prov_data.get("total_tokens", 0)
                        elif isinstance(prov_data, (int, float)):
                            providers_usage[prov_name] = int(prov_data)
        except Exception as exc:
            logger.warning(f"Error reading token stats: {exc}")

        try:
            budget_ok, budget_warning = tracker.check_budget(estimated_tokens=0)
        except Exception as exc:
            logger.warning(f"Error checking budget: {exc}")

    if memory:
        try:
            um = memory.user
            if hasattr(um, "stats"):
                st = um.stats
                if isinstance(st, dict):
                    sessions_total = st.get("total_sessions", 0)
                    commands_total = st.get("total_commands", 0)
                else:
                    sessions_total = getattr(st, "total_sessions", 0)
                    commands_total = getattr(st, "total_commands", 0)
        except Exception:
            pass

    return StatsResponse(
        tokens_today=tokens_today,
        tokens_month=tokens_month,
        tokens_total=tokens_total,
        budget_daily=budget_daily,
        budget_monthly=budget_monthly,
        budget_ok=budget_ok,
        budget_warning=budget_warning,
        sessions_total=sessions_total,
        commands_total=commands_total,
        providers_usage=providers_usage,
    )
@router.get("/skills", response_model=SkillsListResponse, summary="Available skills")
async def get_skills(user: str = Depends(get_current_user)) -> SkillsListResponse:
    """Return all registered NyxOS skills.  SkillManager.list_skills() -> List[dict]."""
    sm = _get_skill_manager()
    skills: List[SkillInfo] = []

    if sm:
        try:
            # list_skills() -> List[dict]
            skill_list = sm.list_skills()
            for item in skill_list:
                if isinstance(item, dict):
                    skills.append(SkillInfo(
                        name=item.get("name", "unknown"),
                        description=item.get("description", ""),
                        requires_tools=item.get("requires_tools", []),
                        intents=item.get("intents", []),
                        available=item.get("available", True),
                    ))
                elif isinstance(item, str):
                    skills.append(SkillInfo(name=item))
                else:
                    skills.append(SkillInfo(
                        name=getattr(item, "name", "unknown"),
                        description=getattr(item, "description", ""),
                        requires_tools=getattr(item, "requires_tools", []),
                        available=True,
                    ))
        except Exception as exc:
            logger.warning(f"Error listing skills: {exc}")

    return SkillsListResponse(skills=skills, total=len(skills))


# ==========================  GET /api/projects  ============================
@router.get("/projects", response_model=ProjectsListResponse, summary="List projects")
async def get_projects(user: str = Depends(get_current_user)) -> ProjectsListResponse:
    """Return all NyxOS projects."""
    projects_dir = Path.home() / ".nyxos" / "projects"
    projects: List[ProjectSchema] = []
    current_project = "default"

    memory = _get_memory_manager()
    if memory and hasattr(memory, "project"):
        try:
            current_project = getattr(memory.project, "name", "default")
        except Exception:
            pass

    if projects_dir.exists():
        for p in sorted(projects_dir.iterdir()):
            if not p.is_dir():
                continue
            project_json = p / "project.json"
            findings_count = 0
            created_at: Optional[str] = None
            targets: List[str] = []

            if project_json.exists():
                try:
                    data = json.loads(project_json.read_text(encoding="utf-8"))
                    findings_count = len(data.get("findings", []))
                    targets = data.get("targets", [])
                    created_at = data.get("created_at")
                except Exception:
                    pass

            projects.append(ProjectSchema(
                name=p.name, targets=targets,
                findings_count=findings_count, created_at=created_at,
            ))

    return ProjectsListResponse(projects=projects, current=current_project)


# ===========================  POST /api/command  ===========================
@router.post("/command", response_model=CommandResponse, summary="Execute a command")
async def execute_command(
    request: CommandRequest,
    user: str = Depends(get_current_user),
) -> CommandResponse:
    """
    Execute a command or natural-language input through NyxOS.

    Flow:
    1. Try SkillManager.find_skill_for_task(text) → BaseSkill
    2. If skill found: skill.execute(user_input, context) → SkillResult
    3. If no skill: AIRouter.generate(prompt, system_prompt, task_type) → AIResponse
    """
    text = request.text.strip()
    if not text:
        raise HTTPException(status_code=400, detail="Empty command text.")

    # Audit
    audit = _get_audit_logger()
    if audit:
        try:
            audit.log("COMMAND", "dashboard_execute", user, {"text": text})
        except Exception:
            pass

    await ws_manager.broadcast_command_started(text, source="dashboard")

    t0 = time.time()
    ai_router = _get_ai_router()
    memory = _get_memory_manager()
    sm = _get_skill_manager()

    findings: List[Dict[str, Any]] = []
    output = ""
    command_executed: Optional[str] = None
    ai_explanation: Optional[str] = None
    success = False

    # ------------------------------------------------------------------
    # STEP 1: Try skill manager
    # SkillManager.find_skill_for_task(user_input) -> Optional[BaseSkill]
    # BaseSkill.execute(user_input: str, context: Dict[str, Any]) -> SkillResult
    # ------------------------------------------------------------------
    skill_handled = False
    if sm:
        try:
            skill = sm.find_skill_for_task(text)
            if skill is not None:
                await ws_manager.broadcast_ai_thinking("executing_skill")

                # Build context for the skill
                context = _get_memory_context()

                # Execute: skill.execute(user_input, context) -> SkillResult
                result = skill.execute(text, context)

                if result:
                    success = getattr(result, "success", False)
                    output = getattr(result, "output", "")
                    findings = list(getattr(result, "findings", []) or [])
                    cmds = getattr(result, "commands_run", [])
                    command_executed = cmds[0] if cmds else getattr(skill, "name", "skill")
                    skill_handled = True

                    # Record scan
                    _record_scan(
                        skill=getattr(skill, "name", "unknown"),
                        target=text,
                        command=command_executed or "",
                        success=success,
                        findings_count=len(findings),
                        start=t0,
                    )

                    # Store in memory
                    if memory:
                        try:
                            memory.session.record_command(text, getattr(skill, "name", "skill"))
                            for f in findings:
                                memory.session.record_finding(f)
                                memory.project.add_finding(f)
                        except Exception:
                            pass

                    # Broadcast each finding
                    for f in findings:
                        await ws_manager.broadcast_finding(f)
        except HTTPException:
            raise
        except Exception as exc:
            logger.debug(f"Skill routing fell through: {exc}")

    # ------------------------------------------------------------------
    # STEP 2: AI router fallback
    # AIRouter.generate(prompt, system_prompt='', max_tokens=4096,
    #     temperature=0.3, provider_override=None, use_cache=True,
    #     task_type='general') -> AIResponse
    # ------------------------------------------------------------------
    if not skill_handled:
        if ai_router:
            await ws_manager.broadcast_ai_thinking("thinking")
            try:
                from nyxos.core.ai_engine.system_prompts import get_system_prompt

                config = _get_config()
                role = "pentester"
                skill_level = "intermediate"
                if config and hasattr(config, "user"):
                    role = getattr(config.user, "role", "pentester") or "pentester"
                    skill_level = (
                        getattr(config.user, "skill_level", "intermediate")
                        or "intermediate"
                    )

                system_prompt = get_system_prompt(role, skill_level)

                # Attach memory context
                context = _get_memory_context()
                context_str = ""
                if context:
                    context_str = json.dumps(context, indent=2, default=str)[:2000]

                full_prompt = (
                    f"Context:\n{context_str}\n\nUser request: {text}"
                    if context_str else text
                )

                # AIRouter.generate(prompt, system_prompt, ..., task_type)
                ai_response = ai_router.generate(
                    prompt=full_prompt,
                    system_prompt=system_prompt,
                    task_type="general",
                )

                await ws_manager.broadcast_ai_thinking("responding")

                if ai_response:
                    output = getattr(ai_response, "text", str(ai_response))
                    ai_explanation = output
                    success = True

                    # Track tokens
                    # TokenTracker.record_usage(provider, model, input_tokens, output_tokens, total_tokens)
                    tokens_used = getattr(ai_response, "tokens_used", 0)
                    provider_name = getattr(ai_response, "provider", "unknown")
                    model_name = getattr(ai_response, "model", "unknown")
                    tracker = _get_token_tracker()

                    if tokens_used and tracker:
                        try:
                            tracker.record_usage(
                                provider=provider_name,
                                model=model_name,
                                input_tokens=0,
                                output_tokens=0,
                                total_tokens=tokens_used,
                            )
                        except Exception:
                            pass

                        # Broadcast token update
                        budget_daily = 0
                        cfg = _get_config()
                        if cfg and hasattr(cfg, "tokens"):
                            budget_daily = getattr(cfg.tokens, "daily_budget", 0)
                        try:
                            stats = tracker.get_stats()
                            today_used = stats.get("today", 0) if isinstance(stats, dict) else 0
                            remaining = max(0, budget_daily - today_used)
                        except Exception:
                            remaining = 0
                        await ws_manager.broadcast_token_update(
                            tokens_used, remaining, provider_name,
                        )

                    # Record in memory
                    if memory:
                        try:
                            memory.session.record_command(text, "ai_query")
                        except Exception:
                            pass

            except Exception as exc:
                logger.error(f"AI routing failed: {exc}")
                output = f"AI processing error: {exc}"
                success = False
        else:
            output = (
                "No AI provider configured. "
                "Run the onboarding wizard or set an API key in config."
            )
            success = False

    # ------------------------------------------------------------------
    # Finalise
    # ------------------------------------------------------------------
    duration = round(time.time() - t0, 2)

    await ws_manager.broadcast_command_completed(
        command_executed or text, success, output[:2000], len(findings), duration,
    )

    return CommandResponse(
        success=success,
        output=output,
        findings=_findings_to_schemas(findings),
        command_executed=command_executed,
        ai_explanation=ai_explanation,
        duration_seconds=duration,
    )


# ===========================  POST /api/report  ============================
@router.post("/report", response_model=ReportResponse, summary="Generate a report")
async def generate_report(
    request: ReportRequest,
    user: str = Depends(get_current_user),
) -> ReportResponse:
    """Generate a security report from the current project findings."""
    memory = _get_memory_manager()
    ai_router = _get_ai_router()
    config = _get_config()

    if not memory:
        raise HTTPException(status_code=503, detail="Memory manager not available.")

    # Check for findings
    try:
        proj_findings = list(getattr(memory.project, "findings", []))
        sess_findings = list(getattr(memory.session, "findings", []))
        if not proj_findings and not sess_findings:
            return ReportResponse(
                success=False, message="No findings to report. Run some scans first.",
            )
    except Exception:
        pass

    try:
        from nyxos.reporting.report_engine import ReportEngine

        engine = ReportEngine(
            project=memory.project, ai_router=ai_router, config=config,
        )

        project_name = getattr(memory.project, "name", "default")
        reports_dir = Path.home() / ".nyxos" / "projects" / project_name / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)

        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        ext_map = {"pdf": "pdf", "markdown": "md", "html": "html"}
        ext = ext_map.get(request.output_format, "pdf")
        output_path = str(reports_dir / f"{request.report_type}_{ts}.{ext}")

        result_path = engine.generate(
            report_type=request.report_type, output_path=output_path,
        )

        audit = _get_audit_logger()
        if audit:
            try:
                audit.log("COMMAND", "report_generated", user, {
                    "type": request.report_type, "format": request.output_format,
                    "path": result_path, "source": "dashboard",
                })
            except Exception:
                pass

        return ReportResponse(
            success=True, file_path=result_path,
            message=f"Report generated: {result_path}",
        )

    except ImportError:
        return ReportResponse(
            success=False,
            message="ReportEngine not available. Install nyxos/reporting/report_engine.py.",
        )
    except Exception as exc:
        logger.error(f"Report generation failed: {exc}")
        return ReportResponse(success=False, message=f"Report generation failed: {exc}")
