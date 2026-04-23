"""
NyxOS Global Configuration Manager
Location: nyxos/core/config/settings.py

Handles all configuration with security best practices:
- API keys are encrypted at rest
- Config files have restricted permissions
- No secrets in plaintext
"""

import os
import json
import yaml
from pathlib import Path
from typing import Optional, Dict, Any
from dataclasses import dataclass, field, asdict
from loguru import logger

# Default paths
NYXOS_HOME = os.environ.get("NYXOS_HOME", os.path.expanduser("~/.nyxos"))
CONFIG_DIR = os.path.join(NYXOS_HOME, "config")
DATA_DIR = os.path.join(NYXOS_HOME, "data")
MODELS_DIR = os.path.join(NYXOS_HOME, "models")
SKILLS_DIR = os.path.join(NYXOS_HOME, "skills")
MEMORY_DIR = os.path.join(NYXOS_HOME, "memory")
LOGS_DIR = os.path.join(NYXOS_HOME, "logs")
PROJECTS_DIR = os.path.join(NYXOS_HOME, "projects")
CACHE_DIR = os.path.join(NYXOS_HOME, "cache")


@dataclass
class AIProviderConfig:
    """Configuration for a single AI provider"""
    name: str = ""
    api_key_encrypted: str = ""  # Never store plaintext
    model: str = ""
    base_url: str = ""
    max_tokens: int = 4096
    temperature: float = 0.3
    timeout: int = 60
    is_local: bool = False


@dataclass
class UserProfile:
    """User profile and preferences"""
    username: str = ""
    role: str = "beginner"  # beginner, bounty_hunter, pentester, red_team, blue_team, forensics, ctf, devsecops, researcher, custom
    skill_level: str = "intermediate"  # new, beginner, intermediate, advanced, expert
    preferred_provider: str = "ollama"
    preferred_model: str = "mistral:7b-instruct-v0.2-q4_K_M"
    verbosity: str = "normal"  # minimal, normal, detailed, verbose
    auto_confirm: bool = False  # If True, skip confirmation prompts
    stealth_mode: bool = False  # Red team: prefer stealthy approaches
    theme: str = "dark"
    language: str = "en"


@dataclass
class SecurityConfig:
    """Security settings"""
    require_scope: bool = True  # Must define scope before scanning
    require_authorization: bool = True  # Must confirm authorization
    sandbox_enabled: bool = True  # Run risky commands in sandbox
    max_concurrent_scans: int = 5
    command_logging: bool = True  # Log all commands for audit
    sensitive_data_encryption: bool = True
    session_timeout_minutes: int = 60
    max_login_attempts: int = 5
    lockout_duration_minutes: int = 15
    allowed_networks: list = field(default_factory=list)
    blocked_commands: list = field(default_factory=lambda: [
        "rm -rf /",
        "mkfs",
        "dd if=.*of=/dev/sd",
        ":(){ :|:& };:",
    ])


@dataclass
class TokenConfig:
    """Token optimization settings"""
    daily_budget: int = 0  # 0 = unlimited
    monthly_budget: int = 0  # 0 = unlimited
    warning_threshold: float = 0.8  # Warn at 80% usage
    cache_enabled: bool = True
    cache_ttl_hours: int = 24
    use_local_for_simple: bool = True  # Use local model for simple tasks
    compress_context: bool = True  # Summarize old context


@dataclass
class NyxConfig:
    """Master NyxOS configuration"""
    version: str = "0.1.0"
    first_run: bool = True
    ai_providers: Dict[str, AIProviderConfig] = field(default_factory=dict)
    active_provider: str = "ollama"
    user: UserProfile = field(default_factory=UserProfile)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    tokens: TokenConfig = field(default_factory=TokenConfig)

    def save(self):
        """Save configuration to disk with secure permissions"""
        os.makedirs(CONFIG_DIR, mode=0o700, exist_ok=True)
        config_path = os.path.join(CONFIG_DIR, "nyxos.yaml")

        config_dict = asdict(self)

        with open(config_path, "w") as f:
            yaml.dump(config_dict, f, default_flow_style=False, sort_keys=False)

        # Set restrictive permissions (owner read/write only)
        os.chmod(config_path, 0o600)
        logger.info(f"Configuration saved to {config_path}")

    @classmethod
    def load(cls) -> "NyxConfig":
        """Load configuration from disk"""
        config_path = os.path.join(CONFIG_DIR, "nyxos.yaml")

        if not os.path.exists(config_path):
            logger.info("No config found, creating default")
            config = cls()
            config.save()
            return config

        with open(config_path, "r") as f:
            data = yaml.safe_load(f)

        if data is None:
            return cls()

        config = cls()

        # Map flat dict back to dataclasses
        if "user" in data:
            config.user = UserProfile(**data["user"])
        if "security" in data:
            config.security = SecurityConfig(**data["security"])
        if "tokens" in data:
            config.tokens = TokenConfig(**data["tokens"])
        if "ai_providers" in data:
            for name, provider_data in data["ai_providers"].items():
                config.ai_providers[name] = AIProviderConfig(**provider_data)

        config.version = data.get("version", "0.1.0")
        config.first_run = data.get("first_run", True)
        config.active_provider = data.get("active_provider", "ollama")

        return config


def get_config() -> NyxConfig:
    """Get or create the global configuration"""
    return NyxConfig.load()


def initialize_directories():
    """Create all required NyxOS directories with proper permissions"""
    dirs = [
        (NYXOS_HOME, 0o700),
        (CONFIG_DIR, 0o700),
        (DATA_DIR, 0o700),
        (MODELS_DIR, 0o755),
        (SKILLS_DIR, 0o755),
        (MEMORY_DIR, 0o700),  # Private — contains user data
        (LOGS_DIR, 0o700),    # Private — contains command logs
        (PROJECTS_DIR, 0o700),
        (CACHE_DIR, 0o700),
    ]

    for dir_path, permissions in dirs:
        os.makedirs(dir_path, mode=permissions, exist_ok=True)

    logger.info(f"NyxOS directories initialized at {NYXOS_HOME}")
