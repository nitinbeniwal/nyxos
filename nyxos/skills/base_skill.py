"""
NyxOS Base Skill
Location: nyxos/core/skills/base_skill.py

Every skill in NyxOS inherits from this base class.
Skills are modular AI capabilities that optimize token usage
by loading only relevant context for each task.
"""

import os
import json
from abc import ABC, abstractmethod
from typing import Optional, Dict, List, Any
from dataclasses import dataclass, field
from datetime import datetime
from loguru import logger


@dataclass
class SkillResult:
    """Standardized result from skill execution"""
    success: bool
    output: str
    structured_data: Dict[str, Any] = field(default_factory=dict)
    commands_executed: List[str] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    suggestions: List[str] = field(default_factory=list)
    tokens_used: int = 0
    execution_time: float = 0.0
    error: Optional[str] = None


@dataclass
class SkillMetadata:
    """Metadata about a skill"""
    name: str
    version: str
    description: str
    author: str
    category: str  # recon, web, network, exploit, etc.
    tags: List[str] = field(default_factory=list)
    min_model_capability: str = "any"  # any, medium, advanced
    requires_tools: List[str] = field(default_factory=list)
    requires_root: bool = False
    risk_level: str = "low"  # low, medium, high
    estimated_tokens: int = 500  # Average tokens per use
    license: str = "Apache-2.0"


class BaseSkill(ABC):
    """
    Abstract base class for all NyxOS skills.
    
    Every skill must implement:
    - metadata: Skill information
    - system_prompt: Optimized prompt for this specific skill
    - execute(): Main skill logic
    - parse_output(): Parse tool output into structured data
    
    Skills keep their own context, so the main system
    only loads what's needed — saving tokens.
    """

    def __init__(self):
        self._metadata = self.get_metadata()
        self._context: Dict[str, Any] = {}
        self._history: List[Dict] = []

    @abstractmethod
    def get_metadata(self) -> SkillMetadata:
        """Return skill metadata"""
        pass

    @abstractmethod
    def get_system_prompt(self) -> str:
        """
        Return the optimized system prompt for this skill.
        
        This is the KEY to token optimization.
        Instead of loading a massive generic prompt,
        each skill has a focused prompt with only
        the knowledge needed for its domain.
        """
        pass

    @abstractmethod
    def execute(self, user_input: str, context: Dict[str, Any]) -> SkillResult:
        """Execute the skill based on user input"""
        pass

    @abstractmethod
    def parse_output(self, raw_output: str) -> Dict[str, Any]:
        """Parse raw tool output into structured data"""
        pass

    def get_prompt_context(self) -> str:
        """
        Return minimal context needed for AI prompt.
        Only includes what this specific skill needs.
        """
        context_parts = []

        if self._context.get("target"):
            context_parts.append(f"Target: {self._context['target']}")

        if self._context.get("findings"):
            recent_findings = self._context["findings"][-5:]  # Last 5 only
            context_parts.append(f"Recent findings: {json.dumps(recent_findings)}")

        if self._context.get("scope"):
            context_parts.append(f"Scope: {self._context['scope']}")

        return "\n".join(context_parts)

    def update_context(self, key: str, value: Any):
        """Update skill-specific context"""
        self._context[key] = value

    def add_finding(self, finding: Dict[str, Any]):
        """Add a finding to skill context"""
        finding["timestamp"] = datetime.now().isoformat()
        finding["skill"] = self._metadata.name

        if "findings" not in self._context:
            self._context["findings"] = []
        self._context["findings"].append(finding)

    def check_tool_available(self, tool_name: str) -> bool:
        """Check if a required tool is installed"""
        import shutil
        return shutil.which(tool_name) is not None

    def check_requirements(self) -> List[str]:
        """Check if all skill requirements are met"""
        missing = []
        for tool in self._metadata.requires_tools:
            if not self.check_tool_available(tool):
                missing.append(tool)
        return missing

    def to_dict(self) -> dict:
        """Serialize skill info for display"""
        meta = self._metadata
        return {
            "name": meta.name,
            "version": meta.version,
            "description": meta.description,
            "category": meta.category,
            "tags": meta.tags,
            "risk_level": meta.risk_level,
            "min_model": meta.min_model_capability,
            "requires_tools": meta.requires_tools,
            "requires_root": meta.requires_root
        }

