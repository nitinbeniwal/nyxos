"""
NyxOS Skill Manager
Location: nyxos/core/skills/skill_manager.py

Discovers, loads, validates, and manages all skills.
"""

import os
import importlib
import inspect
from typing import Dict, List, Optional
from pathlib import Path
from loguru import logger
from .base_skill import BaseSkill, SkillMetadata



# ---------------------------------------------------------------------------
# Skill Registry Decorator
# ---------------------------------------------------------------------------
# Skills discovered from nyxos/skills/*/ subdirectories use this decorator
# to register themselves with the SkillManager at import time.

_REGISTERED_SKILLS: Dict[str, type] = {}


def skill_registry(cls):
    """
    Decorator that registers a skill class for auto-discovery.
    
    Usage:
        @skill_registry
        class MySkill(BaseSkill):
            ...
    """
    if hasattr(cls, 'name') and cls.name:
        _REGISTERED_SKILLS[cls.name] = cls
    else:
        _REGISTERED_SKILLS[cls.__name__] = cls
    logger.debug("Registered skill: {}", cls.__name__)
    return cls


def get_registered_skills() -> Dict[str, type]:
    """Return all skills registered via @skill_registry."""
    return dict(_REGISTERED_SKILLS)


class SkillManager:
    """
    Central skill management system.
    
    Responsibilities:
    - Discover skills from the skills directory
    - Load and validate skills
    - Route user requests to appropriate skills
    - Track skill usage for optimization
    """

    BUILTIN_SKILLS_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "skills")
    USER_SKILLS_DIR = os.path.expanduser("~/.nyxos/skills")

    def __init__(self):
        self._skills: Dict[str, BaseSkill] = {}
        self._skill_keywords: Dict[str, List[str]] = {}
        self._load_all_skills()

    def _load_all_skills(self):
        """Discover and load all available skills"""
        # Load built-in skills
        self._discover_skills(self.BUILTIN_SKILLS_DIR, "nyxos.skills")

        # Load user-installed skills
        if os.path.exists(self.USER_SKILLS_DIR):
            self._discover_skills(self.USER_SKILLS_DIR, "user_skills")

        logger.info(f"Loaded {len(self._skills)} skills")

    def _discover_skills(self, directory: str, package_prefix: str):
        """Discover skills in a directory"""
        if not os.path.exists(directory):
            return

        for category_dir in os.listdir(directory):
            category_path = os.path.join(directory, category_dir)
            if not os.path.isdir(category_path):
                continue

            for filename in os.listdir(category_path):
                if filename.endswith("_skill.py") and not filename.startswith("_"):
                    module_name = filename[:-3]
                    try:
                        # Build module path
                        module_path = f"{package_prefix}.{category_dir}.{module_name}"
                        module = importlib.import_module(module_path)

                        # Find BaseSkill subclasses in module
                        for name, obj in inspect.getmembers(module, inspect.isclass):
                            if issubclass(obj, BaseSkill) and obj != BaseSkill:
                                skill_instance = obj()
                                skill_name = skill_instance.get_metadata().name
                                self._skills[skill_name] = skill_instance

                                # Index keywords for routing
                                meta = skill_instance.get_metadata()
                                self._skill_keywords[skill_name] = meta.tags

                                logger.debug(f"Loaded skill: {skill_name} ({category_dir})")

                    except Exception as e:
                        logger.warning(f"Failed to load skill {filename}: {e}")

    def get_skill(self, name: str) -> Optional[BaseSkill]:
        """Get a skill by name"""
        return self._skills.get(name)

    def find_skill_for_task(self, user_input: str) -> Optional[BaseSkill]:
        """
        Find the most appropriate skill for a user's request.
        Uses keyword matching — AI routing happens at a higher level.
        """
        user_lower = user_input.lower()
        best_match = None
        best_score = 0

        for skill_name, keywords in self._skill_keywords.items():
            score = sum(1 for kw in keywords if kw.lower() in user_lower)
            if score > best_score:
                best_score = score
                best_match = skill_name

        if best_match:
            return self._skills[best_match]
        return None

    def list_skills(self) -> List[dict]:
        """List all available skills"""
        return [skill.to_dict() for skill in self._skills.values()]

    def list_by_category(self) -> Dict[str, List[dict]]:
        """List skills grouped by category"""
        categories: Dict[str, List[dict]] = {}
        for skill in self._skills.values():
            cat = skill.get_metadata().category
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(skill.to_dict())
        return categories

    def check_all_requirements(self) -> Dict[str, List[str]]:
        """Check requirements for all skills"""
        issues = {}
        for name, skill in self._skills.items():
            missing = skill.check_requirements()
            if missing:
                issues[name] = missing
        return issues
