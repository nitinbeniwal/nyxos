"""
NyxOS Dashboard — Pydantic Schemas

All request/response models for the dashboard REST API and WebSocket messages.
Every endpoint uses these schemas for validation and serialization.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# =============================================================================
# Authentication Schemas
# =============================================================================

class AuthRequest(BaseModel):
    """Login request body."""
    username: str = Field(..., min_length=1, max_length=128, description="Username")
    password: str = Field(..., min_length=1, description="Password")


class AuthResponse(BaseModel):
    """Login response with JWT token."""
    token: str = Field(..., description="JWT session token")
    username: str = Field(..., description="Authenticated username")
    expires_at: str = Field(..., description="ISO-8601 expiration timestamp")


class AuthVerifyResponse(BaseModel):
    """Token verification response."""
    valid: bool = Field(..., description="Whether the token is valid")
    username: Optional[str] = Field(None, description="Username if token is valid")
    expires_at: Optional[str] = Field(None, description="Expiration if token is valid")


# =============================================================================
# Finding Schemas
# =============================================================================

class FindingSchema(BaseModel):
    """A single security finding."""
    id: str = Field(..., description="Unique finding identifier")
    type: str = Field(..., description="Finding type: vulnerability, directory_found, etc.")
    title: str = Field(..., description="Short title of the finding")
    severity: str = Field(
        ...,
        description="Severity level: critical|high|medium|low|info",
        pattern=r"^(critical|high|medium|low|info)$",
    )
    description: str = Field(..., description="Detailed description")
    evidence: str = Field(default="", description="Supporting evidence or raw output")
    timestamp: str = Field(..., description="ISO-8601 discovery timestamp")
    url: Optional[str] = Field(None, description="Affected URL if applicable")
    host: Optional[str] = Field(None, description="Affected host/IP")
    port: Optional[int] = Field(None, description="Affected port number")
    service: Optional[str] = Field(None, description="Service name")
    recommendation: Optional[str] = Field(None, description="Remediation recommendation")
    tool_used: Optional[str] = Field(None, description="Tool that produced this finding")
    false_positive: bool = Field(default=False, description="Marked as false positive")


class FindingsListResponse(BaseModel):
    """Response containing a list of findings."""
    findings: List[FindingSchema] = Field(default_factory=list)
    total: int = Field(default=0, description="Total number of findings")
    by_severity: Dict[str, int] = Field(
        default_factory=dict,
        description="Count of findings per severity level",
    )


# =============================================================================
# Command Schemas
# =============================================================================

class CommandRequest(BaseModel):
    """Request to execute a command via the dashboard."""
    text: str = Field(..., min_length=1, description="Command or natural language input")
    project: Optional[str] = Field(None, description="Project context for the command")


class CommandResponse(BaseModel):
    """Response from command execution."""
    success: bool = Field(..., description="Whether the command succeeded")
    output: str = Field(default="", description="Raw command output")
    findings: List[FindingSchema] = Field(
        default_factory=list,
        description="Findings produced by the command",
    )
    command_executed: Optional[str] = Field(
        None,
        description="Actual shell command that was executed",
    )
    ai_explanation: Optional[str] = Field(
        None,
        description="AI explanation of results (if applicable)",
    )
    duration_seconds: Optional[float] = Field(
        None,
        description="Execution time in seconds",
    )


# =============================================================================
# Scan Schemas
# =============================================================================

class ScanSchema(BaseModel):
    """A recorded scan execution."""
    id: str = Field(..., description="Unique scan identifier")
    skill: str = Field(..., description="Skill that was used")
    target: str = Field(..., description="Scan target")
    command: str = Field(..., description="Exact command executed")
    status: str = Field(
        ...,
        description="Scan status: running|complete|failed",
        pattern=r"^(running|complete|failed)$",
    )
    started_at: str = Field(..., description="ISO-8601 start timestamp")
    completed_at: Optional[str] = Field(None, description="ISO-8601 completion timestamp")
    findings_count: int = Field(default=0, description="Number of findings produced")
    duration_seconds: Optional[float] = Field(None, description="Scan duration")


class ScansListResponse(BaseModel):
    """Response containing list of scans."""
    scans: List[ScanSchema] = Field(default_factory=list)
    total: int = Field(default=0)


# =============================================================================
# Status and Stats Schemas
# =============================================================================

class StatusResponse(BaseModel):
    """System status overview."""
    active_provider: str = Field(..., description="Currently active AI provider")
    active_model: Optional[str] = Field(None, description="Currently active model")
    current_project: str = Field(..., description="Current project name")
    session_commands: int = Field(default=0, description="Commands run this session")
    session_findings: int = Field(default=0, description="Findings this session")
    token_budget_remaining: int = Field(
        default=0,
        description="Remaining token budget for today",
    )
    uptime_seconds: float = Field(default=0.0, description="Server uptime in seconds")
    version: str = Field(default="0.1.0", description="NyxOS version")
    user: Optional[str] = Field(None, description="Current username")
    role: Optional[str] = Field(None, description="Current user role")


class StatsResponse(BaseModel):
    """Token and usage statistics."""
    tokens_today: int = Field(default=0, description="Tokens used today")
    tokens_month: int = Field(default=0, description="Tokens used this month")
    tokens_total: int = Field(default=0, description="Total tokens used")
    budget_daily: int = Field(default=0, description="Daily token budget")
    budget_monthly: int = Field(default=0, description="Monthly token budget")
    budget_ok: bool = Field(default=True, description="Whether within budget")
    budget_warning: Optional[str] = Field(
        None,
        description="Budget warning message if approaching limit",
    )
    sessions_total: int = Field(default=0, description="Total sessions")
    commands_total: int = Field(default=0, description="Total commands executed")
    providers_usage: Dict[str, int] = Field(
        default_factory=dict,
        description="Tokens used per provider",
    )


# =============================================================================
# Memory Schemas
# =============================================================================

class SessionMemoryResponse(BaseModel):
    """Current session memory state."""
    commands: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Commands executed this session",
    )
    findings: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Findings this session",
    )
    targets: List[str] = Field(
        default_factory=list,
        description="Targets interacted with",
    )
    started_at: Optional[str] = Field(None, description="Session start timestamp")


# =============================================================================
# Skills Schemas
# =============================================================================

class SkillInfo(BaseModel):
    """Information about an available skill."""
    name: str = Field(..., description="Skill name")
    description: str = Field(default="", description="What the skill does")
    requires_tools: List[str] = Field(
        default_factory=list,
        description="External tools required",
    )
    intents: List[str] = Field(
        default_factory=list,
        description="Intents this skill handles",
    )
    available: bool = Field(
        default=True,
        description="Whether required tools are installed",
    )


class SkillsListResponse(BaseModel):
    """List of all available skills."""
    skills: List[SkillInfo] = Field(default_factory=list)
    total: int = Field(default=0)


# =============================================================================
# Report Schemas
# =============================================================================

class ReportRequest(BaseModel):
    """Request to generate a report."""
    report_type: str = Field(
        default="pentest",
        description="Report type: pentest|bug_bounty|executive|ctf_writeup",
        pattern=r"^(pentest|bug_bounty|executive|ctf_writeup)$",
    )
    output_format: str = Field(
        default="pdf",
        description="Output format: pdf|markdown|html",
        pattern=r"^(pdf|markdown|html)$",
    )
    title: Optional[str] = Field(None, description="Custom report title")


class ReportResponse(BaseModel):
    """Response from report generation."""
    success: bool = Field(..., description="Whether generation succeeded")
    file_path: Optional[str] = Field(None, description="Path to generated report")
    message: str = Field(default="", description="Status message")


# =============================================================================
# Project Schemas
# =============================================================================

class ProjectSchema(BaseModel):
    """Project information."""
    name: str = Field(..., description="Project name")
    targets: List[str] = Field(default_factory=list, description="Project targets")
    findings_count: int = Field(default=0, description="Number of findings")
    created_at: Optional[str] = Field(None, description="Creation timestamp")
    last_accessed: Optional[str] = Field(None, description="Last access timestamp")


class ProjectsListResponse(BaseModel):
    """List of projects."""
    projects: List[ProjectSchema] = Field(default_factory=list)
    current: Optional[str] = Field(None, description="Currently active project")


# =============================================================================
# WebSocket Event Schemas
# =============================================================================

class WebSocketEvent(BaseModel):
    """A WebSocket event message."""
    event: str = Field(..., description="Event type identifier")
    data: Dict[str, Any] = Field(default_factory=dict, description="Event payload")
    timestamp: str = Field(
        default_factory=lambda: datetime.utcnow().isoformat() + "Z",
        description="Event timestamp",
    )


# =============================================================================
# Generic Response
# =============================================================================

class MessageResponse(BaseModel):
    """Generic message response."""
    success: bool = Field(..., description="Operation success")
    message: str = Field(default="", description="Human-readable message")
