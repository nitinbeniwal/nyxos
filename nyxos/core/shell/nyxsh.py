#!/usr/bin/env python3
"""
NyxOS AI Shell (NyxSH)
======================

The primary user interface for NyxOS. This replaces bash as the default
interactive shell. It accepts three types of input:

1. Standard Linux / tool commands  → forwarded to subprocess
2. NyxOS builtins (scan, help …)   → handled internally
3. Natural language queries         → routed through the AI engine

Every command passes through SafetyGuard before execution.
Every significant action is recorded by AuditLogger.
All AI calls go through AIRouter — never direct provider calls.
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from loguru import logger

try:
    from rich.console import Console
    from rich.markdown import Markdown
    from rich.panel import Panel
    from rich.syntax import Syntax
    from rich.table import Table
    from rich.text import Text
except ImportError as exc:
    raise SystemExit(
        "NyxOS requires the 'rich' library. Install with: pip install rich"
    ) from exc

try:
    from prompt_toolkit import PromptSession
    from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
    from prompt_toolkit.completion import WordCompleter
    from prompt_toolkit.formatted_text import HTML
    from prompt_toolkit.history import FileHistory
except ImportError as exc:
    raise SystemExit(
        "NyxOS requires 'prompt_toolkit'. Install with: pip install prompt_toolkit"
    ) from exc


# ---------------------------------------------------------------------------
# NyxOS core imports — wrapped so the shell gives clear errors if missing
# ---------------------------------------------------------------------------

def _safe_import(module_path: str, name: str) -> Any:
    """Import a module and return it, or None with a warning."""
    try:
        import importlib
        return importlib.import_module(module_path)
    except ImportError:
        logger.warning(f"Could not import {module_path} — {name} unavailable")
        return None


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VERSION = "0.1.0"
CODENAME = "Nyx"

BANNER = r"""
[cyan]
    ███╗   ██╗██╗   ██╗██╗  ██╗ ██████╗ ███████╗
    ████╗  ██║╚██╗ ██╔╝╚██╗██╔╝██╔═══██╗██╔════╝
    ██╔██╗ ██║ ╚████╔╝  ╚███╔╝ ██║   ██║███████╗
    ██║╚██╗██║  ╚██╔╝   ██╔██╗ ██║   ██║╚════██║
    ██║ ╚████║   ██║   ██╔╝ ██╗╚██████╔╝███████║
    ╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
[/cyan]
[dim white]  AI-Native Cybersecurity Operating System
    Created by Nitin Beniwal (@nitinbeniwal)  v{version}[/dim white]
[dim]  Type [bold green]help[/bold green] to get started  •  [bold green]exit[/bold green] to quit[/dim]
"""

# Builtins: name → description
BUILTINS: Dict[str, str] = {
    "help":    "Show available commands and usage",
    "scan":    "Scan a target  — usage: scan <target> [--web|--full|--stealth|--udp]",
    "analyze": "Send last output (or given text) to AI for analysis",
    "memory":  "Manage memory  — subcommands: show | clear | export",
    "project": "Manage projects — subcommands: new | load | list | status | close",
    "report":  "Generate a report from current project findings",
    "skills":  "List available skills or show skill detail",
    "stats":   "Show token usage and session statistics",
    "config":  "Show/set configuration — subcommands: show | set <key> <val> | reset",
    "clear":   "Clear the terminal screen",
    "exit":    "Save session and exit NyxOS",
}

# Known shell command prefixes — used by input classifier
_KNOWN_COMMANDS: frozenset[str] = frozenset({
    # Core Linux
    "ls", "cd", "pwd", "cat", "echo", "grep", "find", "mkdir", "rmdir",
    "cp", "mv", "rm", "chmod", "chown", "ps", "kill", "top", "htop",
    "ifconfig", "ip", "ping", "traceroute", "netstat", "ss", "curl",
    "wget", "ssh", "scp", "tar", "gzip", "unzip", "apt", "dpkg",
    "systemctl", "service", "mount", "umount", "df", "du", "free",
    "whoami", "id", "uname", "hostname", "date", "nano", "vim", "vi",
    "less", "more", "head", "tail", "wc", "sort", "uniq", "awk", "sed",
    "touch", "ln",
    # Security tools
    "nmap", "nikto", "gobuster", "hydra", "john", "hashcat", "sqlmap",
    "msfconsole", "metasploit", "wireshark", "tcpdump",
    "aircrack-ng", "responder", "crackmapexec", "enum4linux", "ffuf",
    "wfuzz", "amass", "subfinder", "theHarvester", "shodan", "whois",
    "dig", "nslookup", "host", "volatility", "binwalk", "strings",
    "file", "exiftool", "foremost", "steghide",
    # Dev tools
    "docker", "git", "python", "python3", "pip", "pip3", "bash", "sh",
    "sudo", "su", "man", "which", "env", "export",
})

# Maximum lines of raw output to display before truncating
_MAX_DISPLAY_LINES = 80

# Default subprocess timeout in seconds
_DEFAULT_TIMEOUT = 300


# ---------------------------------------------------------------------------
# Background task dataclass
# ---------------------------------------------------------------------------

@dataclass
class BackgroundTask:
    """A task running in a background thread."""

    id: str
    name: str
    thread: threading.Thread
    started_at: float
    status: str = "running"       # running | complete | failed
    result: Any = None
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# NyxShell
# ---------------------------------------------------------------------------

class NyxShell:
    """
    The NyxOS interactive AI shell.

    Lifecycle:
        shell = NyxShell()
        shell.run()          # blocks until user exits

    All subsystems (config, encryption, AI router, memory, skills, security)
    are initialised inside ``initialize()`` which is called at the start of
    ``run()``.
    """

    # ------------------------------------------------------------------ init
    def __init__(
        self,
        config_path: Optional[str] = None,
        debug: bool = False,
    ) -> None:
        """
        Create a new NyxShell instance.

        Parameters
        ----------
        config_path:
            Path to a custom ``config.json``.  ``None`` uses the default
            ``~/.nyxos/config.json``.
        debug:
            If True, extra diagnostic output is shown.
        """
        self.console = Console()
        self.debug = debug
        self._config_path = config_path

        # Subsystems — populated by initialize()
        self.config: Any = None               # NyxConfig
        self.encryption: Any = None           # EncryptionManager
        self.ai_router: Any = None            # AIRouter
        self.safety: Any = None               # SafetyGuard
        self.audit: Any = None                # AuditLogger
        self.rate_limiter: Any = None         # RateLimiter
        self.skills: Any = None               # SkillManager
        self.memory: Any = None               # MemoryManager
        self.token_tracker: Any = None        # TokenTracker

        # Shell state
        self._running: bool = False
        self._last_output: str = ""
        self._last_command: str = ""
        self._cwd: Path = Path.cwd()
        self._background_tasks: Dict[str, BackgroundTask] = {}
        self._scope: Any = None               # Scope
        self._prompt_session: Optional[PromptSession] = None
        self._original_sigint: Any = None

    # ================================================================
    #  INITIALIZATION
    # ================================================================

    def initialize(self) -> bool:
        """
        Bootstrap all NyxOS subsystems in dependency order.

        Returns True on success, False if a critical subsystem fails.
        Non-critical failures (e.g. skills not loading) are logged but
        do not prevent the shell from starting.
        """
        try:
            # 1. Directories ------------------------------------------------
            self._init_directories()

            # 2. Config -----------------------------------------------------
            self._init_config()

            # 3. Encryption -------------------------------------------------
            self._init_encryption()

            # 4. Security ---------------------------------------------------
            self._init_security()

            # 5. AI engine --------------------------------------------------
            self._init_ai()

            # 6. Memory -----------------------------------------------------
            self._init_memory()

            # 7. Skills -----------------------------------------------------
            self._init_skills()

            # 8. Scope from project -----------------------------------------
            self._load_scope()

            # 9. Prompt toolkit session -------------------------------------
            self._init_prompt_session()

            logger.info("NyxOS shell initialized successfully")
            return True

        except Exception as init_err:
            logger.exception("Critical failure during initialization")
            self.console.print(
                f"[bold red]Initialization failed:[/bold red] {init_err}"
            )
            return False

    # --- individual init helpers ---

    def _init_directories(self) -> None:
        """Create the ~/.nyxos directory tree if needed."""
        try:
            settings_mod = _safe_import(
                "nyxos.core.config.settings", "config/settings"
            )
            if settings_mod and hasattr(settings_mod, "initialize_directories"):
                settings_mod.initialize_directories()
            else:
                # Fallback: create basic dirs manually
                base = Path.home() / ".nyxos"
                for subdir in [
                    "logs", "cache", "stats", "projects/default",
                    "sessions", "memory", "exports", "plugins",
                ]:
                    (base / subdir).mkdir(parents=True, exist_ok=True)
                logger.debug("Created ~/.nyxos directories (fallback)")
        except OSError as e:
            logger.error(f"Failed to create directories: {e}")
            raise

    def _init_config(self) -> None:
        """Load or create the NyxOS configuration."""
        settings_mod = _safe_import(
            "nyxos.core.config.settings", "config/settings"
        )
        if settings_mod is None:
            raise RuntimeError("Cannot load nyxos.core.config.settings — aborting")

        get_config_fn = getattr(settings_mod, "get_config", None)
        if get_config_fn is None:
            raise RuntimeError("get_config() not found in settings module")

        if self._config_path:
            self.config = get_config_fn(self._config_path)
        else:
            self.config = get_config_fn()

        logger.debug(f"Config loaded: first_run={getattr(self.config, 'first_run', '?')}")

    def _init_encryption(self) -> None:
        """Initialise the encryption manager for API key handling."""
        enc_mod = _safe_import(
            "nyxos.core.security.encryption", "encryption"
        )
        if enc_mod and hasattr(enc_mod, "EncryptionManager"):
            self.encryption = enc_mod.EncryptionManager()
        else:
            logger.warning("EncryptionManager unavailable — API keys won't decrypt")

    def _init_security(self) -> None:
        """Initialise SafetyGuard, AuditLogger, and RateLimiter."""
        # SafetyGuard
        sg_mod = _safe_import(
            "nyxos.core.security.safety_guard", "safety_guard"
        )
        if sg_mod and hasattr(sg_mod, "SafetyGuard"):
            self.safety = sg_mod.SafetyGuard(self.config)
        else:
            logger.warning("SafetyGuard unavailable — commands won't be safety-checked")

        # AuditLogger
        al_mod = _safe_import(
            "nyxos.core.security.audit_logger", "audit_logger"
        )
        if al_mod and hasattr(al_mod, "AuditLogger"):
            self.audit = al_mod.AuditLogger()
        else:
            logger.warning("AuditLogger unavailable — actions won't be audited")

        # RateLimiter
        rl_mod = _safe_import(
            "nyxos.core.security.rate_limiter", "rate_limiter"
        )
        if rl_mod and hasattr(rl_mod, "RateLimiter"):
            self.rate_limiter = rl_mod.RateLimiter(self.config)
        else:
            logger.warning("RateLimiter unavailable — no rate limiting active")

    def _init_ai(self) -> None:
        """Initialise the AI router and token tracker."""
        router_mod = _safe_import(
            "nyxos.core.ai_engine.router", "ai_router"
        )
        if router_mod and hasattr(router_mod, "AIRouter"):
            self.ai_router = router_mod.AIRouter(self.config, self.encryption)
        else:
            logger.warning("AIRouter unavailable — AI features disabled")

        tt_mod = _safe_import(
            "nyxos.core.ai_engine.token_tracker", "token_tracker"
        )
        if tt_mod and hasattr(tt_mod, "TokenTracker"):
            self.token_tracker = tt_mod.TokenTracker()
        else:
            logger.warning("TokenTracker unavailable")

    def _init_memory(self) -> None:
        """Initialise the three-tier memory system."""
        mem_mod = _safe_import(
            "nyxos.core.memory.memory_manager", "memory_manager"
        )
        if mem_mod and hasattr(mem_mod, "MemoryManager"):
            username = self._get_username()
            project = "default"
            # Try to get current project from config
            if self.config and hasattr(self.config, "user"):
                user_data = self.config.user
                if isinstance(user_data, dict):
                    project = user_data.get("current_project", "default")
                elif hasattr(user_data, "current_project"):
                    project = getattr(user_data, "current_project", "default")
            self.memory = mem_mod.MemoryManager(
                username=username, project_name=project
            )
        else:
            logger.warning("MemoryManager unavailable — no memory features")

    def _init_skills(self) -> None:
        """Load all available skills."""
        sm_mod = _safe_import(
            "nyxos.skills.skill_manager", "skill_manager"
        )
        if sm_mod and hasattr(sm_mod, "SkillManager"):
            self.skills = sm_mod.SkillManager()
            try:
                self.skills.load_skills()
                logger.debug("Skills loaded successfully")
            except Exception as e:
                logger.error(f"Error loading skills: {e}")
        else:
            logger.warning("SkillManager unavailable — no skills loaded")

    def _load_scope(self) -> None:
        """Build a Scope object from the current project, if available."""
        sg_mod = _safe_import(
            "nyxos.core.security.safety_guard", "safety_guard"
        )
        Scope = getattr(sg_mod, "Scope", None) if sg_mod else None

        if Scope is None:
            self._scope = None
            return

        targets: List[str] = []
        excluded: List[str] = []
        allowed_tools: List[str] = []

        if self.memory and hasattr(self.memory, "project"):
            proj = self.memory.project
            scope_data = getattr(proj, "scope", None)
            if isinstance(scope_data, dict):
                targets = scope_data.get("targets", [])
                excluded = scope_data.get("excluded_ranges", [])
                allowed_tools = scope_data.get("allowed_tools", [])

        self._scope = Scope(
            targets=targets,
            excluded_ranges=excluded,
            allowed_tools=allowed_tools,
        )

    def _init_prompt_session(self) -> None:
        """Set up prompt_toolkit with history and tab-completion."""
        history_path = Path.home() / ".nyxos" / "history"
        try:
            history_path.touch(exist_ok=True)
        except OSError as e:
            logger.warning(f"Cannot create history file: {e}")

        completer = WordCompleter(
            sorted(set(list(BUILTINS.keys()) + list(_KNOWN_COMMANDS))),
            ignore_case=True,
        )

        self._prompt_session = PromptSession(
            history=FileHistory(str(history_path)),
            auto_suggest=AutoSuggestFromHistory(),
            completer=completer,
        )

    # ================================================================
    #  FIRST-RUN ONBOARDING
    # ================================================================

    def _check_first_run(self) -> None:
        """Launch the onboarding wizard if this is the first boot."""
        first_run = getattr(self.config, "first_run", False)
        if not first_run:
            return

        logger.info("First run detected — launching onboarding wizard")
        wizard_mod = _safe_import("nyxos.onboarding.wizard", "onboarding")

        if wizard_mod and hasattr(wizard_mod, "OnboardingWizard"):
            try:
                wizard = wizard_mod.OnboardingWizard(self.config, self.encryption)
                wizard.run()
                # Reload config after onboarding modifies it
                self._init_config()
                self._init_ai()
                logger.info("Onboarding complete — config reloaded")
            except KeyboardInterrupt:
                self.console.print("\n[yellow]Onboarding interrupted.[/yellow]")
            except Exception as e:
                logger.error(f"Onboarding failed: {e}")
                self.console.print(
                    f"[yellow]Onboarding skipped due to error: {e}[/yellow]\n"
                    "[dim]You can configure later with: config set[/dim]"
                )
        else:
            self.console.print(
                "[yellow]Onboarding module not installed yet. "
                "Configure manually with: config set[/yellow]"
            )

    # ================================================================
    #  PROMPT
    # ================================================================

    def _build_prompt(self) -> HTML:
        """Build the styled shell prompt for prompt_toolkit."""
        username = self._get_username()
        short_cwd = str(self._cwd).replace(str(Path.home()), "~")

        return HTML(
            "<ansibrightcyan>[nyx]</ansibrightcyan> "
            f"<ansigreen>{username}@nyxos</ansigreen> "
            f"<ansiyellow>{short_cwd}</ansiyellow> "
            "<ansibrightcyan>❯</ansibrightcyan> "
        )

    # ================================================================
    #  BANNER
    # ================================================================

    def _show_banner(self) -> None:
        """Display the NyxOS startup banner and quick status."""
        self.console.print(BANNER.replace("{version}", VERSION))

        provider = getattr(self.config, "active_provider", None) or "none"
        role = "unknown"
        if self.config and hasattr(self.config, "user"):
            user_data = self.config.user
            if isinstance(user_data, dict):
                role = user_data.get("role", "unknown")
            elif hasattr(user_data, "role"):
                role = getattr(user_data, "role", "unknown")

        project_name = "default"
        if self.memory and hasattr(self.memory, "project"):
            project_name = getattr(self.memory.project, "name", "default")

        self.console.print(
            f"  [dim]Provider:[/dim] [cyan]{provider}[/cyan]  "
            f"[dim]Role:[/dim] [cyan]{role}[/cyan]  "
            f"[dim]Project:[/dim] [cyan]{project_name}[/cyan]\n"
        )

    # ================================================================
    #  INPUT CLASSIFICATION
    # ================================================================

    def _classify_input(self, text: str) -> str:
        """
        Classify user input into one of three categories.

        Parameters
        ----------
        text:
            Raw user input string (already stripped).

        Returns
        -------
        str
            ``"builtin"`` — a NyxOS built-in command.
            ``"shell"``   — a Linux / tool command for subprocess.
            ``"natural_language"`` — a query for the AI engine.
        """
        if not text:
            return "shell"

        # Bang prefix forces shell execution: !nmap -sV target
        if text.startswith("!"):
            return "shell"

        first_token = text.split()[0].lower()

        # 1. NyxOS builtins — highest priority
        if first_token in BUILTINS:
            return "builtin"

        # 2. Explicitly known commands / tools
        if first_token in _KNOWN_COMMANDS:
            return "shell"

        # 3. Path-based execution: ./script, /usr/bin/tool, ~/bin/thing
        if first_token.startswith(("./", "/", "~/")):
            return "shell"

        # 4. Contains shell operators → shell
        shell_operators = ("|", ">>", ">", "&&", "||", ";", "$(", "`")
        if any(op in text for op in shell_operators):
            return "shell"

        # 5. Check if first token is an executable on $PATH
        if self._command_exists(first_token):
            return "shell"

        # 6. Everything else → natural language for the AI
        return "natural_language"

    @staticmethod
    def _command_exists(name: str) -> bool:
        """Check whether *name* is an executable on ``$PATH``."""
        return shutil.which(name) is not None

    # ================================================================
    #  INPUT DISPATCHER
    # ================================================================

    def _process_input(self, text: str) -> None:
        """Route user input to the correct handler after classification."""
        text = text.strip()
        if not text:
            return

        # Strip bang prefix before passing to shell
        if text.startswith("!"):
            self._execute_shell_command(text[1:].strip())
            return

        category = self._classify_input(text)

        if category == "builtin":
            self._dispatch_builtin(text)
        elif category == "shell":
            self._execute_shell_command(text)
        elif category == "natural_language":
            self._handle_natural_language(text)

    def _dispatch_builtin(self, text: str) -> None:
        """Parse a builtin command and route to its handler method."""
        parts = text.strip().split(maxsplit=1)
        cmd_name = parts[0].lower()
        args = parts[1] if len(parts) > 1 else ""

        handler_map: Dict[str, Callable[[str], None]] = {
            "help":    self._cmd_help,
            "scan":    self._cmd_scan,
            "analyze": self._cmd_analyze,
            "memory":  self._cmd_memory,
            "project": self._cmd_project,
            "report":  self._cmd_report,
            "skills":  self._cmd_skills,
            "stats":   self._cmd_stats,
            "config":  self._cmd_config,
            "clear":   self._cmd_clear,
            "exit":    self._cmd_exit,
        }

        handler = handler_map.get(cmd_name)
        if handler is None:
            self.console.print(f"[red]Unknown builtin: {cmd_name}[/red]")
            return

        try:
            handler(args)
        except KeyboardInterrupt:
            self.console.print("\n[yellow]Command interrupted.[/yellow]")
        except Exception as exc:
            logger.exception(f"Error in builtin '{cmd_name}'")
            self.console.print(f"[red]Error in '{cmd_name}': {exc}[/red]")

    # ================================================================
    #  BUILTINS — PART A
    # ================================================================

    def _cmd_help(self, args: str) -> None:
        """Display all available commands with descriptions."""
        table = Table(
            title="NyxOS Commands",
            title_style="bold cyan",
            border_style="dim",
        )
        table.add_column("Command", style="green bold", min_width=12)
        table.add_column("Description", style="white")

        for name, desc in BUILTINS.items():
            table.add_row(name, desc)

        self.console.print()
        self.console.print(table)
        self.console.print(
            "\n[dim]  You can also type any Linux command directly, or ask in plain English."
            "\n  Prefix with [bold]![/bold] to force shell execution.  "
            "Example: [green]!nmap -sV 127.0.0.1[/green][/dim]\n"
        )

    def _cmd_scan(self, args: str) -> None:
        """
        Scan a target using an appropriate skill.

        Usage::

            scan <target>              Default nmap SYN scan
            scan <target> --web        Web vulnerability scan
            scan <target> --full       Full port + service scan
            scan <target> --stealth    Stealth SYN scan
            scan <target> --udp        UDP scan
        """
        if not args.strip():
            self.console.print(
                "[yellow]Usage: scan <target> [--web|--full|--stealth|--udp][/yellow]"
            )
            return

        tokens = args.strip().split()
        target = tokens[0]
        flags = {t.lower() for t in tokens[1:]}

        # Choose skill + params
        skill_name = "nmap"
        params: Dict[str, Any] = {"target": target}

        if "--web" in flags:
            skill_name = "web"
            params["url"] = target if target.startswith("http") else f"http://{target}"
            params["intent"] = "vulnerability scan"
        elif "--full" in flags:
            params["scan_type"] = "full"
        elif "--stealth" in flags:
            params["scan_type"] = "stealth"
        elif "--udp" in flags:
            params["scan_type"] = "udp"
        else:
            params["scan_type"] = "default"

        # Safety check
        if not self._safety_check(f"scan {target}"):
            return

        # Record target
        if self.memory and hasattr(self.memory, "session"):
            self.memory.session.add_target(target)

        self._audit("SKILL_USE", f"scan:{skill_name}", {"target": target})
        self.console.print(f"[cyan]Scanning {target} with [bold]{skill_name}[/bold] skill…[/cyan]\n")

        # Execute skill
        if self.skills is None:
            self.console.print("[red]SkillManager not loaded — cannot scan.[/red]")
            return

        try:
            result = self.skills.execute(skill_name, params)
        except KeyError:
            self.console.print(
                f"[red]Skill '{skill_name}' not found. Run [green]skills[/green] to see available skills.[/red]"
            )
            return
        except Exception as exc:
            logger.error(f"Skill execution failed: {exc}")
            self.console.print(f"[red]Scan failed: {exc}[/red]")
            return

        self._display_skill_result(result)
        self._record_skill_result(f"scan {args}", skill_name, result)

    def _cmd_analyze(self, args: str) -> None:
        """
        Send the last command output (or supplied text) to AI for analysis.

        Usage::

            analyze              Analyze last command output
            analyze <text>       Analyze the supplied text
        """
        text_to_analyze = args.strip() if args.strip() else self._last_output

        if not text_to_analyze:
            self.console.print(
                "[yellow]Nothing to analyze. Run a command first, or: analyze <text>[/yellow]"
            )
            return

        if self.ai_router is None:
            self.console.print("[red]AI engine not available. Check your provider config.[/red]")
            return

        if not self._rate_limit_check("ai_query"):
            return

        system_prompt = self._get_system_prompt()
        prompt = (
            "Analyze the following security tool output. "
            "Identify findings, risks, and recommended next steps.\n\n"
            f"```\n{text_to_analyze[:4000]}\n```"
        )

        response = self._ai_query(prompt, system_prompt, task_type="complex")
        if response is None:
            return

        self.console.print()
        self.console.print(Panel(
            Markdown(response.text),
            title="[bold cyan]AI Analysis[/bold cyan]",
            border_style="cyan",
        ))

        self._audit("AI_QUERY", "analyze", {"tokens": response.tokens_used})
        self._record_command("analyze", "ai")

    def _cmd_memory(self, args: str) -> None:
        """
        Manage NyxOS memory.

        Subcommands::

            memory show      Display session + project memory summary
            memory clear     Clear current session memory
            memory export    Export all memory to a JSON file
        """
        sub = args.strip().split()[0].lower() if args.strip() else "show"

        if self.memory is None:
            self.console.print("[red]Memory system not available.[/red]")
            return

        if sub == "show":
            self._memory_show()
        elif sub == "clear":
            self._memory_clear()
        elif sub == "export":
            self._memory_export()
        else:
            self.console.print("[yellow]Usage: memory show | clear | export[/yellow]")

    def _memory_show(self) -> None:
        """Display a summary table of current memory state."""
        table = Table(title="Memory Summary", border_style="dim")
        table.add_column("Key", style="green")
        table.add_column("Value", style="white")

        try:
            ctx = self.memory.get_full_context()
        except Exception as e:
            logger.error(f"Failed to read memory context: {e}")
            self.console.print(f"[red]Error reading memory: {e}[/red]")
            return

        session = ctx.get("session", {})
        table.add_row("Session commands", str(len(session.get("commands", []))))
        table.add_row("Session findings", str(len(session.get("findings", []))))
        table.add_row(
            "Session targets",
            ", ".join(session.get("targets", [])) or "—",
        )

        project = ctx.get("project", {})
        table.add_row("Project name", str(project.get("name", "default")))
        table.add_row("Project findings", str(len(project.get("findings", []))))

        user = ctx.get("user", {})
        total = user.get("stats", {}).get("total_commands", 0)
        table.add_row("Total commands (all-time)", str(total))

        self.console.print(table)

    def _memory_clear(self) -> None:
        """Clear session memory."""
        session_mod = _safe_import(
            "nyxos.core.memory.session_memory", "session_memory"
        )
        if session_mod and hasattr(session_mod, "SessionMemory"):
            self.memory.session = session_mod.SessionMemory()
            self.console.print("[green]Session memory cleared.[/green]")
        else:
            self.console.print("[red]Cannot clear — SessionMemory class not found.[/red]")

    def _memory_export(self) -> None:
        """Export full memory context to a JSON file."""
        export_dir = Path.home() / ".nyxos" / "exports"
        export_dir.mkdir(parents=True, exist_ok=True)
        export_path = export_dir / f"memory_{int(time.time())}.json"

        try:
            ctx = self.memory.get_full_context()
            export_path.write_text(
                json.dumps(ctx, indent=2, default=str), encoding="utf-8"
            )
            self.console.print(f"[green]Memory exported to {export_path}[/green]")
        except (OSError, TypeError, ValueError) as e:
            logger.error(f"Memory export failed: {e}")
            self.console.print(f"[red]Export failed: {e}[/red]")

    def _cmd_project(self, args: str) -> None:
        """
        Manage engagement projects.

        Subcommands::

            project new <name>    Create and switch to a new project
            project load <name>   Switch to an existing project
            project list          List all projects
            project status        Show current project info
            project close         Save and close current project
        """
        parts = args.strip().split(maxsplit=1)
        sub = parts[0].lower() if parts else "status"
        name = parts[1].strip() if len(parts) > 1 else ""

        if self.memory is None:
            self.console.print("[red]Memory system not available.[/red]")
            return

        if sub == "new":
            self._project_new(name)
        elif sub == "load":
            self._project_load(name)
        elif sub == "list":
            self._project_list()
        elif sub == "status":
            self._project_status()
        elif sub == "close":
            self._project_close()
        else:
            self.console.print(
                "[yellow]Usage: project new|load|list|status|close [name][/yellow]"
            )

    def _project_new(self, name: str) -> None:
        """Create a new project and switch to it."""
        if not name:
            self.console.print("[yellow]Usage: project new <name>[/yellow]")
            return

        mem_mod = _safe_import("nyxos.core.memory.memory_manager", "memory_manager")
        if mem_mod is None:
            self.console.print("[red]MemoryManager not available.[/red]")
            return

        self.memory = mem_mod.MemoryManager(
            username=self._get_username(), project_name=name
        )
        try:
            self.memory.project.save()
        except Exception as e:
            logger.error(f"Failed to save new project: {e}")

        self._load_scope()
        self.console.print(f"[green]Project '{name}' created and loaded.[/green]")

    def _project_load(self, name: str) -> None:
        """Load an existing project."""
        if not name:
            self.console.print("[yellow]Usage: project load <name>[/yellow]")
            return

        project_path = Path.home() / ".nyxos" / "projects" / name
        if not project_path.is_dir():
            self.console.print(f"[red]Project '{name}' not found.[/red]")
            return

        mem_mod = _safe_import("nyxos.core.memory.memory_manager", "memory_manager")
        if mem_mod is None:
            return

        self.memory = mem_mod.MemoryManager(
            username=self._get_username(), project_name=name
        )
        try:
            self.memory.project.load()
        except FileNotFoundError:
            logger.warning(f"Project file for '{name}' not found, starting fresh")
        except Exception as e:
            logger.error(f"Error loading project '{name}': {e}")

        self._load_scope()
        self.console.print(f"[green]Project '{name}' loaded.[/green]")

    def _project_list(self) -> None:
        """List all projects in ~/.nyxos/projects/."""
        projects_dir = Path.home() / ".nyxos" / "projects"
        if not projects_dir.exists():
            self.console.print("[dim]No projects yet.[/dim]")
            return

        projects = sorted(
            p.name for p in projects_dir.iterdir() if p.is_dir()
        )
        if not projects:
            self.console.print("[dim]No projects yet.[/dim]")
            return

        current = getattr(self.memory.project, "name", "default")
        for p in projects:
            marker = " [cyan]← active[/cyan]" if p == current else ""
            self.console.print(f"  • {p}{marker}")

    def _project_status(self) -> None:
        """Show info about the current project."""
        proj = self.memory.project
        table = Table(
            title=f"Project: {getattr(proj, 'name', 'default')}",
            border_style="dim",
        )
        table.add_column("Key", style="green")
        table.add_column("Value", style="white")

        table.add_row("Name", str(getattr(proj, "name", "default")))
        targets = getattr(proj, "targets", [])
        table.add_row("Targets", ", ".join(targets) if targets else "—")
        findings = getattr(proj, "findings", [])
        table.add_row("Findings", str(len(findings)))

        # Show severity breakdown if there are findings
        if findings:
            counts: Dict[str, int] = {}
            for f in findings:
                sev = f.get("severity", "info").lower() if isinstance(f, dict) else "info"
                counts[sev] = counts.get(sev, 0) + 1
            breakdown = "  ".join(
                f"{s}: {c}" for s, c in sorted(counts.items())
            )
            table.add_row("Severity breakdown", breakdown)

        self.console.print(table)

    def _project_close(self) -> None:
        """Save and close the current project, switch to default."""
        proj_name = getattr(self.memory.project, "name", "default")
        try:
            self.memory.project.save()
        except Exception as e:
            logger.error(f"Error saving project on close: {e}")

        mem_mod = _safe_import("nyxos.core.memory.memory_manager", "memory_manager")
        if mem_mod:
            self.memory = mem_mod.MemoryManager(
                username=self._get_username(), project_name="default"
            )
        self._load_scope()
        self.console.print(f"[green]Project '{proj_name}' saved and closed.[/green]")

    # ================================================================
    #  BUILTINS — PART B
    # ================================================================

    def _cmd_report(self, args: str) -> None:
        """
        Generate a report from current project findings.

        Usage::

            report                          Default pentest report
            report --type bug_bounty        Bug bounty report
            report --type executive         Executive summary
            report --type ctf_writeup       CTF writeup
            report --output /path/file.pdf  Custom output path
        """
        # Parse flags
        tokens = args.strip().split()
        report_type = "pentest"
        output_path: Optional[str] = None

        i = 0
        while i < len(tokens):
            if tokens[i] == "--type" and i + 1 < len(tokens):
                report_type = tokens[i + 1]
                i += 2
            elif tokens[i] == "--output" and i + 1 < len(tokens):
                output_path = tokens[i + 1]
                i += 2
            else:
                i += 1

        # Check we have findings
        if self.memory is None:
            self.console.print("[red]Memory system not available.[/red]")
            return

        findings = getattr(self.memory.project, "findings", [])
        if not findings:
            self.console.print(
                "[yellow]No findings to report. Run some scans first.[/yellow]"
            )
            return

        # Default output path
        if not output_path:
            reports_dir = (
                Path.home()
                / ".nyxos"
                / "projects"
                / getattr(self.memory.project, "name", "default")
                / "reports"
            )
            reports_dir.mkdir(parents=True, exist_ok=True)
            output_path = str(
                reports_dir / f"{report_type}_{int(time.time())}.pdf"
            )

        # Try to import and use ReportEngine
        report_mod = _safe_import("nyxos.reporting.report_engine", "reporting")
        if report_mod is None or not hasattr(report_mod, "ReportEngine"):
            self.console.print(
                "[yellow]Reporting module not available yet. (Needs Agent 5)[/yellow]"
            )
            return

        try:
            engine = report_mod.ReportEngine(
                project=self.memory.project,
                ai_router=self.ai_router,
                config=self.config,
            )
            with self.console.status("[cyan]Generating report…[/cyan]", spinner="dots"):
                result_path = engine.generate(report_type, output_path)

            self.console.print(f"[green]Report saved to {result_path}[/green]")
            self._audit("COMMAND", "report_generated", {
                "type": report_type, "path": str(result_path),
            })
        except Exception as exc:
            logger.error(f"Report generation failed: {exc}")
            self.console.print(f"[red]Report generation failed: {exc}[/red]")

    def _cmd_skills(self, args: str) -> None:
        """
        List all available skills or show detail for a specific one.

        Usage::

            skills             List all loaded skills
            skills nmap        Show details for the nmap skill
        """
        if self.skills is None:
            self.console.print("[red]SkillManager not loaded.[/red]")
            return

        try:
            skill_list = self.skills.list_skills()
        except Exception as e:
            logger.error(f"Error listing skills: {e}")
            self.console.print(f"[red]Error: {e}[/red]")
            return

        # Detail for one skill
        if args.strip():
            name = args.strip().lower()
            matched = [
                s for s in skill_list
                if s.get("name", "").lower() == name
            ]
            if matched:
                s = matched[0]
                self.console.print(Panel(
                    f"[bold]{s['name']}[/bold]\n\n"
                    f"{s.get('description', 'No description.')}\n\n"
                    f"[dim]Required tools:[/dim] {', '.join(s.get('requires_tools', []))}",
                    title=f"Skill: {s['name']}",
                    border_style="cyan",
                ))
            else:
                self.console.print(f"[red]Skill '{name}' not found.[/red]")
            return

        # List all
        if not skill_list:
            self.console.print("[dim]No skills loaded.[/dim]")
            return

        table = Table(title="Available Skills", border_style="dim")
        table.add_column("Skill", style="green bold")
        table.add_column("Description", style="white")
        table.add_column("Tools", style="dim")

        for s in skill_list:
            table.add_row(
                s.get("name", "?"),
                s.get("description", "—"),
                ", ".join(s.get("requires_tools", [])),
            )
        self.console.print(table)

    def _cmd_stats(self, args: str) -> None:
        """Display token usage and session statistics."""
        table = Table(title="NyxOS Statistics", border_style="dim")
        table.add_column("Metric", style="green")
        table.add_column("Value", style="white")

        # Token usage
        if self.token_tracker is not None:
            try:
                today = self.token_tracker.get_today()
                month = self.token_tracker.get_this_month()
                table.add_row("Tokens today", f"{today:,}")
                table.add_row("Tokens this month", f"{month:,}")

                ok, warning = self.token_tracker.check_budget()
                if not ok:
                    table.add_row("Budget warning", f"[red]{warning}[/red]")
            except Exception as e:
                logger.debug(f"Token stats unavailable: {e}")
                table.add_row("Token stats", "[dim]unavailable[/dim]")
        else:
            table.add_row("Token stats", "[dim]tracker not loaded[/dim]")

        # Session stats
        if self.memory and hasattr(self.memory, "session"):
            session = self.memory.session
            table.add_row(
                "Session commands",
                str(len(getattr(session, "commands", []))),
            )
            table.add_row(
                "Session findings",
                str(len(getattr(session, "findings", []))),
            )
            table.add_row(
                "Session targets",
                ", ".join(getattr(session, "targets", [])) or "—",
            )

        # Provider
        provider = getattr(self.config, "active_provider", "—") or "—"
        table.add_row("Active provider", provider)

        # Background tasks
        running = sum(
            1 for t in self._background_tasks.values()
            if t.status == "running"
        )
        table.add_row("Background tasks", str(running))

        self.console.print(table)

    def _cmd_config(self, args: str) -> None:
        """
        View or modify NyxOS configuration.

        Subcommands::

            config show                 Display current config
            config set <key> <value>    Set a config value (dot notation)
            config reset                Reset to defaults
        """
        parts = args.strip().split(maxsplit=2)
        sub = parts[0].lower() if parts else "show"

        if sub == "show":
            self._config_show()
        elif sub == "set" and len(parts) >= 3:
            self._config_set(parts[1], parts[2])
        elif sub == "reset":
            self._config_reset()
        else:
            self.console.print(
                "[yellow]Usage: config show | set <key> <value> | reset[/yellow]"
            )

    def _config_show(self) -> None:
        """Pretty-print the current config (redacting sensitive fields)."""
        safe_config = {
            "user": getattr(self.config, "user", {}),
            "active_provider": getattr(self.config, "active_provider", None),
            "tokens": getattr(self.config, "tokens", {}),
            "security": getattr(self.config, "security", {}),
            "first_run": getattr(self.config, "first_run", None),
        }
        rendered = json.dumps(safe_config, indent=2, default=str)
        self.console.print(Syntax(rendered, "json", theme="monokai"))

    def _config_set(self, key: str, value: str) -> None:
        """
        Set a config value using dot notation.

        Example: ``config set user.role pentester``
        """
        segments = key.split(".")
        obj: Any = self.config

        # Navigate to the parent of the final key
        for seg in segments[:-1]:
            if isinstance(obj, dict):
                obj = obj.setdefault(seg, {})
            elif hasattr(obj, seg):
                obj = getattr(obj, seg)
            else:
                self.console.print(f"[red]Invalid config key: {key}[/red]")
                return

        final_key = segments[-1]
        if isinstance(obj, dict):
            obj[final_key] = value
        elif hasattr(obj, final_key):
            setattr(obj, final_key, value)
        else:
            self.console.print(f"[red]Invalid config key: {key}[/red]")
            return

        try:
            self.config.save()
            self.console.print(f"[green]{key} = {value}[/green]")
        except Exception as e:
            logger.error(f"Failed to save config: {e}")
            self.console.print(f"[red]Config updated in memory but save failed: {e}[/red]")

    def _config_reset(self) -> None:
        """Reset configuration to defaults."""
        if not self._confirm("Reset ALL configuration to defaults?"):
            return

        config_file = Path.home() / ".nyxos" / "config.json"
        try:
            if config_file.exists():
                config_file.unlink()
            self._init_config()
            self.console.print("[green]Configuration reset to defaults.[/green]")
        except OSError as e:
            logger.error(f"Config reset failed: {e}")
            self.console.print(f"[red]Reset failed: {e}[/red]")

    def _cmd_clear(self, args: str) -> None:
        """Clear the terminal screen."""
        self.console.clear()

    def _cmd_exit(self, args: str) -> None:
        """Save session state and exit NyxOS gracefully."""
        self.console.print("[dim]Saving session…[/dim]")
        self._shutdown()
        self.console.print("[cyan]Goodbye from NyxOS. Stay sharp. 🛡️[/cyan]")
        self._running = False

    # ================================================================
    #  BACKGROUND TASKS
    # ================================================================

    def _start_background(self, name: str, fn: Callable[..., Any], *args: Any) -> str:
        """
        Run a function in a background thread.

        Parameters
        ----------
        name:
            Human-readable name for the task.
        fn:
            The callable to run.
        *args:
            Arguments passed to *fn*.

        Returns
        -------
        str
            The unique task ID.
        """
        task_id = uuid.uuid4().hex[:8]

        def _worker() -> None:
            task = self._background_tasks[task_id]
            try:
                task.result = fn(*args)
                task.status = "complete"
                self.console.print(
                    f"\n[green]✓ Background task '{name}' ({task_id}) completed.[/green]"
                )
            except Exception as worker_exc:
                task.status = "failed"
                task.error = str(worker_exc)
                logger.error(f"Background task '{name}' failed: {worker_exc}")
                self.console.print(
                    f"\n[red]✗ Background task '{name}' ({task_id}) failed: {worker_exc}[/red]"
                )

        thread = threading.Thread(target=_worker, daemon=True, name=f"nyx-bg-{task_id}")
        self._background_tasks[task_id] = BackgroundTask(
            id=task_id,
            name=name,
            thread=thread,
            started_at=time.time(),
        )
        thread.start()

        self.console.print(f"[dim]Started background task '{name}' (id: {task_id})[/dim]")
        return task_id

    def _list_background(self) -> None:
        """Display all background tasks and their status."""
        if not self._background_tasks:
            self.console.print("[dim]No background tasks.[/dim]")
            return

        table = Table(title="Background Tasks", border_style="dim")
        table.add_column("ID", style="green")
        table.add_column("Name")
        table.add_column("Status")
        table.add_column("Elapsed")

        status_colors = {"running": "yellow", "complete": "green", "failed": "red"}

        for task in self._background_tasks.values():
            elapsed = f"{time.time() - task.started_at:.1f}s"
            color = status_colors.get(task.status, "white")
            table.add_row(
                task.id,
                task.name,
                f"[{color}]{task.status}[/{color}]",
                elapsed,
            )

        self.console.print(table)

    def _kill_background(self, task_id: str) -> None:
        """Mark a background task as killed (best-effort — cannot truly kill threads)."""
        task = self._background_tasks.get(task_id)
        if task is None:
            self.console.print(f"[red]No task with id '{task_id}'.[/red]")
            return

        if task.status == "running":
            task.status = "failed"
            task.error = "Killed by user"
            self.console.print(
                f"[yellow]Task {task_id} marked as killed. "
                "(Thread may still be running in background.)[/yellow]"
            )
        else:
            self.console.print(f"[dim]Task {task_id} already {task.status}.[/dim]")

    # ================================================================
    #  NATURAL LANGUAGE → AI → EXECUTE
    # ================================================================

    def _handle_natural_language(self, text: str) -> None:
        """
        Process a natural-language query through the AI engine.

        Flow
        ----
        1. Check rate limit.
        2. Build a prompt incorporating user text + memory context.
        3. Route to AIRouter.
        4. Parse AI response for an executable command.
        5. If command found → show it → ask confirmation → safety check → execute.
        6. If no command → display AI response directly.
        7. Record everything in memory.
        """
        if self.ai_router is None:
            self.console.print(
                "[red]AI engine not available. "
                "Run [green]config show[/green] to check your provider setup.[/red]"
            )
            return

        # 1. Rate limit
        if not self._rate_limit_check("ai_query"):
            return

        # 2. Build prompt
        system_prompt = self._get_system_prompt()

        context: Dict[str, Any] = {}
        if self.memory:
            try:
                context = self.memory.get_full_context()
            except Exception as e:
                logger.debug(f"Could not load memory context: {e}")

        recent_cmds = [
            c.get("command", "") if isinstance(c, dict) else str(c)
            for c in context.get("session", {}).get("commands", [])[-5:]
        ]
        targets = context.get("session", {}).get("targets", [])

        # User preference hints (from long-term memory)
        preference_hints = ""
        if self.memory and hasattr(self.memory, "user"):
            try:
                preference_hints = self.memory.user.get_ai_preference_hints()
            except (AttributeError, Exception):
                pass

        full_prompt = (
            f"User request: {text}\n\n"
            f"Current targets in scope: {targets}\n"
            f"Recent commands: {recent_cmds}\n"
        )
        if preference_hints:
            full_prompt += f"User preferences: {preference_hints}\n"

        full_prompt += (
            "\nIf this request requires running a terminal command, "
            "respond with EXACTLY this format:\n"
            "COMMAND: <the exact command to run>\n"
            "EXPLANATION: <brief explanation of what it does>\n\n"
            "If no command is needed, respond with helpful information directly."
        )

        # 3. Route to AI
        response = self._ai_query(full_prompt, system_prompt, task_type="execute")
        if response is None:
            return

        self._audit("AI_QUERY", "natural_language", {
            "query": text[:200],
            "tokens": response.tokens_used,
        })

        # 4. Parse for command
        command, explanation = self._parse_ai_command(response.text)

        if command:
            # 5. Show + confirm + safety check + execute
            self.console.print()
            if explanation:
                self.console.print(f"  [dim]{explanation}[/dim]")
            self.console.print(
                f"  [bold cyan]Proposed:[/bold cyan] [green]{command}[/green]"
            )

            if not self._confirm("Execute this command?"):
                self.console.print("[dim]Skipped.[/dim]")
                return

            if not self._safety_check(command):
                return

            self._execute_shell_command(command)
            self._record_command(command, "ai_suggested")

            # Offer auto-analysis of substantial output
            if self._last_output and len(self._last_output.strip()) > 200:
                if self._confirm("Analyze output with AI?", default=True):
                    self._cmd_analyze("")
        else:
            # 6. No command — display response as-is
            self.console.print()
            self.console.print(Panel(
                Markdown(response.text),
                title="[bold cyan]NyxOS AI[/bold cyan]",
                border_style="cyan",
            ))

    @staticmethod
    def _parse_ai_command(text: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Extract ``COMMAND:`` and ``EXPLANATION:`` lines from an AI response.

        Returns
        -------
        tuple[str | None, str | None]
            (command, explanation) — either may be None.
        """
        command: Optional[str] = None
        explanation: Optional[str] = None

        for line in text.splitlines():
            stripped = line.strip()
            upper = stripped.upper()

            if upper.startswith("COMMAND:"):
                raw = stripped[len("COMMAND:"):].strip()
                # Remove markdown backtick wrapping
                command = raw.strip("`").strip()
            elif upper.startswith("EXPLANATION:"):
                explanation = stripped[len("EXPLANATION:"):].strip()

        return command, explanation

    # ================================================================
    #  SHELL COMMAND EXECUTION
    # ================================================================

    def _execute_shell_command(self, command: str) -> None:
        """
        Execute a shell command via subprocess and stream output to console.

        The ``cd`` command is handled in-process since it must modify the
        shell's working directory.
        """
        command = command.strip()
        if not command:
            return

        # Handle cd in-process
        if command == "cd" or command.startswith("cd "):
            self._handle_cd(command)
            return

        # Safety check
        if not self._safety_check(command):
            return

        self._audit("COMMAND", command, {})
        self._last_command = command

        try:
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                cwd=str(self._cwd),
                                env={**os.environ, "TERM": "xterm-256color"},
            )

            output_lines: List[str] = []

            # Stream output line by line
            try:
                for line in iter(process.stdout.readline, ""):
                    self.console.print(line, end="", highlight=False)
                    output_lines.append(line)
            except KeyboardInterrupt:
                self.console.print("\n[yellow]Interrupted — terminating process…[/yellow]")
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    logger.warning(f"Had to SIGKILL subprocess for: {command}")

            process.wait()

            full_output = "".join(output_lines)
            self._last_output = full_output

            if process.returncode != 0 and process.returncode is not None:
                self.console.print(
                    f"[dim red]Exit code: {process.returncode}[/dim red]"
                )

            # Record in memory
            self._record_command(command, "shell")

        except FileNotFoundError:
            first_token = command.split()[0] if command.split() else command
            self.console.print(f"[red]Command not found: {first_token}[/red]")
            self._last_output = ""
        except PermissionError:
            self.console.print(
                f"[red]Permission denied. Try prefixing with sudo.[/red]"
            )
            self._last_output = ""
        except OSError as e:
            logger.error(f"OS error executing command: {e}")
            self.console.print(f"[red]OS error: {e}[/red]")
            self._last_output = ""

    def _handle_cd(self, command: str) -> None:
        """
        Handle ``cd`` in-process since subprocess cannot change the parent CWD.

        Supports: ``cd``, ``cd ~``, ``cd /path``, ``cd ..``, ``cd -``
        """
        parts = command.split(maxsplit=1)
        target = parts[1].strip() if len(parts) > 1 else "~"

        # cd - : go to previous directory (basic support)
        if target == "-":
            # We don't track old dir, just go home as fallback
            target = "~"

        target = os.path.expanduser(target)
        target = os.path.expandvars(target)

        try:
            new_path = (self._cwd / target).resolve()
            if not new_path.exists():
                self.console.print(f"[red]No such directory: {new_path}[/red]")
                return
            if not new_path.is_dir():
                self.console.print(f"[red]Not a directory: {new_path}[/red]")
                return

            self._cwd = new_path
            os.chdir(new_path)

        except PermissionError:
            self.console.print(f"[red]Permission denied: {target}[/red]")
        except OSError as e:
            self.console.print(f"[red]cd failed: {e}[/red]")

    # ================================================================
    #  DISPLAY HELPERS
    # ================================================================

    def _display_skill_result(self, result: Any) -> None:
        """
        Pretty-print a SkillResult to the console.

        Displays: commands run, raw output (truncated), findings table,
        and duration.
        """
        if not getattr(result, "success", False):
            self.console.print("[red]Skill execution failed.[/red]")
            output = getattr(result, "output", "")
            if output:
                self.console.print(output, highlight=False)
            return

        # Commands that were run
        commands_run = getattr(result, "commands_run", [])
        if commands_run:
            for cmd in commands_run:
                self.console.print(f"[dim]$ {cmd}[/dim]")
            self.console.print()

        # Raw output — truncated
        output = getattr(result, "output", "")
        if output:
            lines = output.splitlines()
            if len(lines) > _MAX_DISPLAY_LINES:
                display = "\n".join(lines[:_MAX_DISPLAY_LINES])
                self.console.print(display, highlight=False)
                self.console.print(
                    f"[dim]… ({len(lines) - _MAX_DISPLAY_LINES} more lines — "
                    f"use [green]analyze[/green] to review full output)[/dim]"
                )
            else:
                self.console.print(output, highlight=False)

            self._last_output = output

        # Findings table
        findings = getattr(result, "findings", [])
        if findings:
            self.console.print()
            self._display_findings_table(findings)

        # Duration
        duration = getattr(result, "duration_seconds", None)
        if duration is not None:
            self.console.print(f"\n[dim]Completed in {duration:.1f}s[/dim]")

    def _display_findings_table(self, findings: List[Dict[str, Any]]) -> None:
        """Render a list of findings as a rich Table."""
        severity_colors = {
            "critical": "bright_red",
            "high": "red",
            "medium": "yellow",
            "low": "green",
            "info": "blue",
        }

        table = Table(title="Findings", border_style="dim")
        table.add_column("Severity", min_width=10, style="bold")
        table.add_column("Title")
        table.add_column("Details", style="dim")

        for finding in findings:
            if not isinstance(finding, dict):
                continue
            sev = finding.get("severity", "info").lower()
            color = severity_colors.get(sev, "white")
            table.add_row(
                f"[{color}]{sev.upper()}[/{color}]",
                finding.get("title", "—"),
                finding.get("description", "")[:80],
            )

        self.console.print(table)

    # ================================================================
    #  AI HELPERS
    # ================================================================

    def _ai_query(
        self,
        prompt: str,
        system_prompt: str,
        task_type: str = "simple",
    ) -> Any:
        """
        Send a query to the AI router with a spinner, handling errors.

        Returns the AIResponse on success, or None on failure.
        """
        context: Dict[str, Any] = {}
        if self.memory:
            try:
                context = self.memory.get_full_context()
            except Exception:
                pass

        history = context.get("recent_commands", [])

        with self.console.status("[cyan]AI is thinking…[/cyan]", spinner="dots"):
            try:
                response = self.ai_router.route(
                    prompt=prompt,
                    system_prompt=system_prompt,
                    history=history,
                    task_type=task_type,
                )
                return response
            except Exception as exc:
                self._handle_ai_error(exc)
                return None

    def _handle_ai_error(self, error: Exception) -> None:
        """Display a user-friendly error message based on the type of AI failure."""
        error_msg = str(error).lower()

        if any(kw in error_msg for kw in ("api key", "authentication", "401", "unauthorized")):
            self.console.print(
                "[red]AI authentication failed.[/red]\n"
                "[dim]Check your API key: [green]config show[/green] | "
                "Re-run setup: delete ~/.nyxos/config.json and restart[/dim]"
            )
        elif any(kw in error_msg for kw in ("rate limit", "429", "too many")):
            self.console.print(
                "[yellow]AI provider rate limit reached.[/yellow] "
                "Wait a moment and try again."
            )
        elif any(kw in error_msg for kw in ("timeout", "timed out")):
            self.console.print(
                "[yellow]AI request timed out.[/yellow] "
                "Try a simpler query or check your internet connection."
            )
        elif any(kw in error_msg for kw in ("connection", "network", "unreachable")):
            self.console.print(
                "[red]Cannot reach AI provider.[/red] "
                "Check your internet connection."
            )
        elif any(kw in error_msg for kw in ("quota", "billing", "payment")):
            self.console.print(
                "[red]AI provider quota exceeded or billing issue.[/red] "
                "Check your provider account."
            )
        else:
            self.console.print(f"[red]AI error:[/red] {error}")

        logger.error(f"AI error: {error}")

    def _get_system_prompt(self) -> str:
        """Build the system prompt based on user role and skill level."""
        role = "pentester"
        skill_level = "intermediate"

        if self.config and hasattr(self.config, "user"):
            user_data = self.config.user
            if isinstance(user_data, dict):
                role = user_data.get("role", "pentester")
                skill_level = user_data.get("skill_level", "intermediate")
            elif hasattr(user_data, "role"):
                role = getattr(user_data, "role", "pentester")
                skill_level = getattr(user_data, "skill_level", "intermediate")

        prompts_mod = _safe_import(
            "nyxos.core.ai_engine.system_prompts", "system_prompts"
        )
        if prompts_mod and hasattr(prompts_mod, "get_system_prompt"):
            return prompts_mod.get_system_prompt(role, skill_level)

        # Fallback system prompt if module not available
        return (
            f"You are NyxOS, an AI cybersecurity assistant. "
            f"The user's role is {role} at {skill_level} level. "
            f"Help them with security tasks. Be precise and professional."
        )

    # ================================================================
    #  SAFETY, AUDIT, RATE LIMIT WRAPPERS
    # ================================================================

    def _safety_check(self, command: str) -> bool:
        """
        Run a command through SafetyGuard.

        Returns True if the command is allowed to execute.
        Returns False (and prints a message) if blocked.
        Prompts for confirmation on HIGH/CRITICAL risk.
        """
        if self.safety is None:
            # No safety guard loaded — allow with warning
            logger.warning(f"SafetyGuard unavailable — allowing: {command}")
            return True

        try:
            is_safe, reason, risk_level = self.safety.check_command(
                command, self._scope
            )
        except TypeError:
            # Fallback: maybe check_command has different signature (check vs check_command)
            try:
                is_safe, reason, risk_level = self.safety.check(
                    command, self._scope
                )
            except Exception as e:
                logger.error(f"SafetyGuard error: {e}")
                return True  # fail open rather than block everything

        if not is_safe:
            self.console.print(f"[bold red]BLOCKED:[/bold red] {reason}")
            self._audit("COMMAND", f"BLOCKED: {command}", {"reason": reason})
            return False

        if risk_level in ("HIGH", "CRITICAL"):
            color = "red" if risk_level == "CRITICAL" else "yellow"
            if not self._confirm(
                f"[{color}]{risk_level} risk:[/{color}] {reason}. Continue?"
            ):
                self.console.print("[dim]Command cancelled.[/dim]")
                return False

        return True

    def _audit(self, event_type: str, action: str, details: Dict[str, Any]) -> None:
        """Log an action through AuditLogger if available."""
        if self.audit is None:
            return

        try:
            self.audit.log(
                event_type=event_type,
                action=action,
                user=self._get_username(),
                details=details,
            )
        except Exception as e:
            logger.debug(f"Audit log failed: {e}")

    def _rate_limit_check(self, action: str) -> bool:
        """
        Check rate limiter. Returns True if action is allowed.
        Prints a message and returns False if rate-limited.
        """
        if self.rate_limiter is None:
            return True

        try:
            allowed, wait_seconds = self.rate_limiter.check(
                self._get_username(), action
            )
        except Exception as e:
            logger.debug(f"Rate limiter error: {e}")
            return True  # fail open

        if not allowed:
            self.console.print(
                f"[yellow]Rate limited — please wait {wait_seconds}s before trying again.[/yellow]"
            )
            return False

        return True

    # ================================================================
    #  MEMORY RECORDING WRAPPERS
    # ================================================================

    def _record_command(self, command: str, source: str) -> None:
        """Record a command in both session and user memory."""
        if self.memory is None:
            return

        try:
            if hasattr(self.memory, "session") and self.memory.session:
                self.memory.session.record_command(command, source)
        except Exception as e:
            logger.debug(f"Failed to record command in session memory: {e}")

        try:
            if hasattr(self.memory, "user") and self.memory.user:
                self.memory.user.record_command(command)
        except (AttributeError, Exception) as e:
            logger.debug(f"Failed to record command in user memory: {e}")

    def _record_skill_result(
        self, command: str, skill_name: str, result: Any
    ) -> None:
        """Record a skill execution and its findings in memory."""
        self._record_command(command, skill_name)

        if self.memory is None:
            return

        findings = getattr(result, "findings", [])
        for finding in findings:
            try:
                if hasattr(self.memory, "session") and self.memory.session:
                    self.memory.session.record_finding(finding)
            except Exception as e:
                logger.debug(f"Failed to record finding in session: {e}")

            try:
                if hasattr(self.memory, "project") and self.memory.project:
                    self.memory.project.add_finding(finding)
            except Exception as e:
                logger.debug(f"Failed to record finding in project: {e}")

        # Save project after adding findings
        try:
            if hasattr(self.memory, "project") and self.memory.project:
                self.memory.project.save()
        except Exception as e:
            logger.debug(f"Failed to save project memory: {e}")

    # ================================================================
    #  UTILITY HELPERS
    # ================================================================

    def _get_username(self) -> str:
        """Return the current username from config, or system fallback."""
        if self.config and hasattr(self.config, "user"):
            user_data = self.config.user
            if isinstance(user_data, dict):
                return user_data.get("name", os.getenv("USER", "nyx"))
            elif hasattr(user_data, "name"):
                return getattr(user_data, "name", os.getenv("USER", "nyx"))
        return os.getenv("USER", "nyx")

    def _confirm(self, message: str, default: bool = False) -> bool:
        """
        Prompt the user for a yes/no confirmation.

        Parameters
        ----------
        message:
            The question to display.
        default:
            Default answer when user just presses Enter.

        Returns
        -------
        bool
            True if the user confirmed, False otherwise.
        """
        suffix = " [Y/n] " if default else " [y/N] "
        try:
            answer = input(f"{message}{suffix}").strip().lower()
        except (EOFError, KeyboardInterrupt):
            self.console.print()
            return False

        if not answer:
            return default
        return answer in ("y", "yes")

    # ================================================================
    #  SHUTDOWN
    # ================================================================

    def _shutdown(self) -> None:
        """
        Perform a clean shutdown: save memory, end session, restore signals.
        Called by ``_cmd_exit()`` and by the end of ``run()`` on EOF.
        """
        # Save session + memory
        if self.memory is not None:
            try:
                self.memory.end_session()
                logger.info("Session ended and memory saved")
            except AttributeError:
                # end_session() might not exist on all memory manager versions
                logger.debug("memory.end_session() not available")
                try:
                    if hasattr(self.memory, "project"):
                        self.memory.project.save()
                    if hasattr(self.memory, "user"):
                        self.memory.user.record_session_end()
                except Exception as e:
                    logger.warning(f"Fallback session save failed: {e}")
            except Exception as e:
                logger.warning(f"Error during session end: {e}")

        # Audit session end
        self._audit("AUTH", "session_end", {})

        # Restore original SIGINT handler
        if self._original_sigint is not None:
            try:
                signal.signal(signal.SIGINT, self._original_sigint)
            except (OSError, ValueError) as e:
                logger.debug(f"Could not restore SIGINT handler: {e}")

    # ================================================================
    #  MAIN RUN LOOP
    # ================================================================

    def run(self, skip_onboarding: bool = False) -> None:
        """
        The main REPL loop.

        Initialises all subsystems, optionally runs onboarding, shows the
        banner, then enters the read → classify → dispatch cycle until the
        user exits or sends EOF (Ctrl-D).

        Parameters
        ----------
        skip_onboarding:
            If True, the first-run wizard is skipped even if
            ``config.first_run`` is True.
        """
        # 1. Initialize all subsystems
        if not self.initialize():
            self.console.print("[bold red]Failed to initialize NyxOS. Exiting.[/bold red]")
            sys.exit(1)

        # 2. First-run onboarding
        if not skip_onboarding:
            self._check_first_run()

        # 3. Banner
        self._show_banner()

        # 4. Audit session start
        self._audit("AUTH", "session_start", {})

        # 5. Save original SIGINT handler, install ours
        self._original_sigint = signal.getsignal(signal.SIGINT)
        signal.signal(signal.SIGINT, signal.SIG_IGN)

        # 6. REPL loop
        self._running = True
        while self._running:
            try:
                # Re-enable SIGINT briefly for prompt_toolkit (it needs it)
                signal.signal(signal.SIGINT, self._original_sigint)
                user_input = self._prompt_session.prompt(self._build_prompt())
                # Ignore SIGINT again during command processing
                signal.signal(signal.SIGINT, signal.SIG_IGN)

                if user_input is None:
                    continue

                self._process_input(user_input)

            except KeyboardInterrupt:
                # Ctrl-C during input — just print a newline and re-prompt
                self.console.print()
                continue

            except EOFError:
                # Ctrl-D — exit cleanly
                self.console.print()
                self._shutdown()
                self.console.print("[cyan]Goodbye from NyxOS. Stay sharp. 🛡️[/cyan]")
                break

            except Exception as exc:
                logger.exception("Unhandled exception in REPL loop")
                self.console.print(f"[red]Unexpected error: {exc}[/red]")
                if self.debug:
                    import traceback
                    self.console.print(traceback.format_exc(), highlight=False)

        # 7. Final cleanup (only if _cmd_exit didn't already do it)
        #    We check if the session is still active by seeing if _running
        #    was set to False by _cmd_exit (which calls _shutdown) vs
        #    the EOF path above (which also calls _shutdown).
        #    _shutdown() is safe to call multiple times — it guards internally.
