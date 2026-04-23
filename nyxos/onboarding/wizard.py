"""
NyxOS Onboarding Wizard — Main Orchestrator
Runs Steps 1-5 of the first-boot experience: welcome, user creation,
role selection, AI provider setup, and completion summary.
"""

from __future__ import annotations

import getpass
import os
from typing import Dict, List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.prompt import Prompt, Confirm
from rich.align import Align
from loguru import logger

from nyxos.core.config.settings import NyxConfig, get_config
from nyxos.core.security.encryption import EncryptionManager
from nyxos.core.security.auth import AuthManager
from nyxos.onboarding.first_boot import FirstBootScreen
from nyxos.onboarding.role_selector import RoleSelector, get_role_name, get_role_icon
from nyxos.onboarding.api_key_setup import APIKeySetup


# Quick reference cards per role — shown at completion
QUICK_REFERENCE: Dict[str, List[tuple[str, str]]] = {
    "beginner": [
        ("help", "Show all available commands"),
        ("scan 127.0.0.1", "Run your first network scan"),
        ("what is a port scan?", "Ask the AI to explain concepts"),
        ("analyze", "AI explains the last command's output"),
        ("skills", "See all available security tools"),
    ],
    "bug_bounty": [
        ("scan dirs on http://target.com", "Directory enumeration"),
        ("scan http://target.com for vulns", "Web vulnerability scan"),
        ("test http://target.com/login for sqli", "SQL injection testing"),
        ("report", "Generate bug bounty report"),
        ("project new bounty-target", "Start tracking a new target"),
    ],
    "pentester": [
        ("scan 192.168.1.0/24", "Network-wide port scan"),
        ("full recon on target.com", "Comprehensive reconnaissance"),
        ("scan http://target.com for vulns", "Web vulnerability assessment"),
        ("report", "Generate professional pentest report"),
        ("project new client-engagement", "Start a new engagement project"),
    ],
    "red_team": [
        ("scan -sS -T2 target", "Stealth SYN scan"),
        ("full recon on target.com", "OSINT and recon chain"),
        ("analyze", "AI suggests next attack vectors"),
        ("chain full pentest on target", "Multi-step attack chain"),
        ("config set safety medium", "Adjust safety level"),
    ],
    "blue_team": [
        ("analyze /var/log/syslog", "AI analyzes log files"),
        ("find IOCs in this output", "Extract indicators of compromise"),
        ("what does this alert mean?", "Ask AI about security alerts"),
        ("report", "Generate incident report"),
        ("memory show", "Review session analysis history"),
    ],
    "forensics": [
        ("analyze memory dump /path/to/mem.raw", "Memory forensics"),
        ("show metadata of /path/to/file", "Extract file metadata"),
        ("recover deleted files from /path/to/image", "File carving"),
        ("verify integrity of /path/to/evidence", "Hash verification"),
        ("project new case-2024-001", "Start a new case project"),
    ],
    "ctf": [
        ("decode base64 SGVsbG8=", "Decode encoded strings"),
        ("analyze binary /path/to/challenge", "Binary analysis"),
        ("hint", "Get a hint without spoilers"),
        ("strings /path/to/challenge", "Extract strings from files"),
        ("scan http://ctf-challenge:8080", "Scan CTF web challenges"),
    ],
    "devsecops": [
        ("scan deps for vulns", "Dependency vulnerability check"),
        ("review this code for security", "AI code review"),
        ("scan http://localhost:3000", "Test local application"),
        ("what CVEs affect this version?", "CVE lookup"),
        ("report", "Generate security assessment report"),
    ],
    "researcher": [
        ("full recon on target.com", "Comprehensive target analysis"),
        ("analyze binary /path/to/sample", "Malware/binary analysis"),
        ("find CVEs for Apache 2.4.49", "CVE research"),
        ("explain this exploit", "AI explains exploit mechanics"),
        ("report", "Generate research findings report"),
    ],
}


class OnboardingWizard:
    """
    Main onboarding wizard for NyxOS first boot.
    Orchestrates all 5 steps of the setup process and saves the resulting
    configuration.
    """

    def __init__(
        self,
        config: NyxConfig,
        encryption: EncryptionManager,
        console: Console | None = None,
    ) -> None:
        """
        Initialize the onboarding wizard.

        Args:
            config: The NyxOS configuration instance (will be modified and saved).
            encryption: Encryption manager for API key handling.
            console: Rich Console instance. Created if not provided.
        """
        self.config = config
        self.encryption = encryption
        self.console = console or Console()
        self.username: str = ""
        self.role: str = ""
        self.skill_level: str = ""
        self.providers_configured: List[str] = []

    def run(self) -> None:
        """
        Run the complete onboarding wizard (all 5 steps).

        This is the main entry point called by nyxsh.py when
        config.first_run is True.

        On successful completion, config.first_run is set to False
        and config is saved. On Ctrl+C at any step, the wizard
        offers to cancel or resume.
        """
        logger.info("Starting NyxOS onboarding wizard")

        try:
            # Step 1: Welcome Screen
            self._step_welcome()

            # Step 2: Username + Password
            self._step_user_creation()

            # Step 3: Role Selection
            self._step_role_selection()

            # Step 4: AI Provider Setup
            self._step_ai_setup()

            # Step 5: Completion + Summary
            self._step_completion()

        except KeyboardInterrupt:
            self.console.print()
            self._handle_cancel()
        except Exception as e:
            logger.error(f"Onboarding wizard error: {e}")
            self.console.print(
                f"\n[bold red]An error occurred during setup: {e}[/bold red]"
            )
            self.console.print(
                "[yellow]Your progress has been saved. Run NyxOS again to resume.[/yellow]"
            )
            # Save whatever we have so far
            self._save_partial_config()
            raise

    def _step_welcome(self) -> None:
        """Step 1: Display the welcome screen."""
        logger.info("Onboarding Step 1: Welcome screen")
        welcome = FirstBootScreen(console=self.console)
        welcome.show()

    def _step_user_creation(self) -> None:
        """
        Step 2: Create user account with username and password.

        Asks for username (default: current system user), password with
        confirmation, and creates the user via AuthManager.
        """
        logger.info("Onboarding Step 2: User creation")

        self.console.print()
        header = Panel(
            "[bold white]Let's set up your NyxOS account. This username and password\n"
            "secure your API keys and session data.[/bold white]",
            title="[bold cyan]Step 2 — Create Your Account[/bold cyan]",
            border_style="cyan",
            padding=(1, 2),
        )
        self.console.print(header)
        self.console.print()

        # Get system username as default
        system_user = os.environ.get("USER", os.environ.get("USERNAME", "nyx"))

        # Ask for username
        while True:
            try:
                username = Prompt.ask(
                    "[bold yellow]Username[/bold yellow]",
                    default=system_user,
                )
                username = username.strip()
                if not username:
                    self.console.print("[red]Username cannot be empty.[/red]")
                    continue
                if len(username) < 2:
                    self.console.print(
                        "[red]Username must be at least 2 characters.[/red]"
                    )
                    continue
                if not username.replace("_", "").replace("-", "").isalnum():
                    self.console.print(
                        "[red]Username can only contain letters, numbers, hyphens, "
                        "and underscores.[/red]"
                    )
                    continue
                break
            except KeyboardInterrupt:
                raise

        self.username = username

        # Ask for password
        self.console.print()
        self.console.print(
            "[dim]Your password encrypts your API keys. Choose something strong.[/dim]"
        )

        while True:
            try:
                password = getpass.getpass("  Password: ")
                if len(password) < 4:
                    self.console.print(
                        "[red]  Password must be at least 4 characters.[/red]"
                    )
                    continue

                password_confirm = getpass.getpass("  Confirm password: ")
                if password != password_confirm:
                    self.console.print("[red]  Passwords don't match. Try again.[/red]")
                    continue
                break
            except (EOFError, KeyboardInterrupt):
                raise KeyboardInterrupt

        # Create the user
        try:
            auth = AuthManager()
            auth.create_user(username, password)
            self.console.print(
                f"\n[bold green]✓[/bold green] Account created for "
                f"[bold cyan]{username}[/bold cyan]"
            )
            logger.info(f"User account created: {username}")
        except Exception as e:
            # User might already exist — that's okay on re-run
            if "already exists" in str(e).lower() or "exists" in str(e).lower():
                self.console.print(
                    f"\n[yellow]ℹ[/yellow] User [cyan]{username}[/cyan] already exists, "
                    f"using existing account."
                )
                logger.info(f"User {username} already exists, continuing")
            else:
                self.console.print(
                    f"\n[yellow]⚠ Could not create user account: {e}[/yellow]"
                )
                self.console.print("[dim]Continuing with setup anyway...[/dim]")
                logger.warning(f"User creation issue: {e}")

        # Save username to config
        self.config.user.name = username

    def _step_role_selection(self) -> None:
        """
        Step 3: Select user role and skill level.

        Uses the RoleSelector class to present options and get user choices.
        """
        logger.info("Onboarding Step 3: Role selection")

        selector = RoleSelector(console=self.console)

        try:
            self.role, self.skill_level = selector.run()
        except KeyboardInterrupt:
            # Default to pentester/intermediate if cancelled
            self.console.print(
                "\n[yellow]Defaulting to Penetration Tester / Intermediate[/yellow]"
            )
            self.role = "pentester"
            self.skill_level = "intermediate"

        # Save to config
        self.config.user.role = self.role
        self.config.user.skill_level = self.skill_level

    def _step_ai_setup(self) -> None:
        """
        Step 4: Configure AI providers and API keys.

        Uses the APIKeySetup class to walk through provider selection,
        key input, testing, and encryption.
        """
        logger.info("Onboarding Step 4: AI provider setup")

        setup = APIKeySetup(
            config=self.config,
            encryption=self.encryption,
            console=self.console,
        )

        try:
            self.providers_configured = setup.run()
        except KeyboardInterrupt:
            if setup.configured_providers:
                self.providers_configured = setup.configured_providers
                self.console.print(
                    "\n[yellow]AI setup interrupted. "
                    f"{len(self.providers_configured)} provider(s) saved.[/yellow]"
                )
            else:
                self.console.print(
                    "\n[yellow]⚠ No AI provider configured. "
                    "NyxOS will have limited functionality.[/yellow]"
                )
                self.console.print(
                    "[dim]You can add a provider later with: config set provider <name>[/dim]"
                )

    def _step_completion(self) -> None:
        """
        Step 5: Show summary, save config, display quick reference card.

        Marks first_run as False and saves the complete configuration.
        """
        logger.info("Onboarding Step 5: Completion")

        self.console.print()
        self.console.print()

        # ── Summary Panel ──
        role_name = get_role_name(self.role)
        role_icon = get_role_icon(self.role)

        summary_lines = []
        summary_lines.append(f"[bold white]Username:[/bold white]    [cyan]{self.username}[/cyan]")
        summary_lines.append(
            f"[bold white]Role:[/bold white]        [cyan]{role_icon} {role_name}[/cyan]"
        )
        summary_lines.append(
            f"[bold white]Skill Level:[/bold white] [cyan]{self.skill_level.capitalize()}[/cyan]"
        )

        if self.providers_configured:
            providers_str = ", ".join(
                f"[cyan]{p}[/cyan]" for p in self.providers_configured
            )
            summary_lines.append(f"[bold white]AI Providers:[/bold white] {providers_str}")
            active = getattr(self.config, "active_provider", self.providers_configured[0])
            summary_lines.append(f"[bold white]Active:[/bold white]      [bold green]{active}[/bold green]")
        else:
            summary_lines.append("[bold white]AI Providers:[/bold white] [yellow]None configured[/yellow]")

        summary_panel = Panel(
            "\n".join(summary_lines),
            title="[bold green]✓ Setup Complete[/bold green]",
            border_style="green",
            padding=(1, 2),
        )
        self.console.print(summary_panel)
        self.console.print()

        # ── Quick Reference Card ──
        self._show_quick_reference()

        # ── Finalize config ──
        self.config.first_run = False
        try:
            self.config.save()
            logger.info("Configuration saved successfully after onboarding")
        except Exception as e:
            logger.error(f"Failed to save config: {e}")
            self.console.print(
                f"[yellow]⚠ Warning: Could not save config: {e}[/yellow]"
            )

        self.console.print()
        self.console.print(
            Align.center(
                Text(
                    "You're ready to go! Type 'help' to see available commands.",
                    style="bold green",
                )
            )
        )
        self.console.print()

        # Brief pause so user can read the summary
        try:
            self.console.print(
                Align.center(
                    Text("Press Enter to launch NyxOS shell...", style="dim yellow")
                )
            )
            input()
        except (EOFError, KeyboardInterrupt):
            pass

    def _show_quick_reference(self) -> None:
        """Display a quick reference card with the 5 most useful commands for the user's role."""
        # Get commands for the selected role, fallback to beginner
        commands = QUICK_REFERENCE.get(self.role, QUICK_REFERENCE["beginner"])

        table = Table(
            title=f"Quick Reference — {get_role_name(self.role)}",
            title_style="bold cyan",
            show_header=True,
            header_style="bold cyan",
            border_style="dim cyan",
            padding=(0, 2),
            expand=False,
        )
        table.add_column("Command", style="bold yellow", min_width=35)
        table.add_column("What It Does", style="white")

        for cmd, desc in commands:
            table.add_row(cmd, desc)

        self.console.print(table)

    def _handle_cancel(self) -> None:
        """Handle Ctrl+C during the wizard — offer to save partial progress or quit."""
        self.console.print()
        self.console.print(
            "[yellow]Setup was interrupted.[/yellow]"
        )

        try:
            save = Confirm.ask(
                "[yellow]Save your progress so far?[/yellow]",
                default=True,
            )
        except KeyboardInterrupt:
            save = False

        if save:
            self._save_partial_config()
            self.console.print(
                "[green]Progress saved. Run NyxOS again to resume setup.[/green]"
            )
        else:
            self.console.print(
                "[dim]No changes saved. Run NyxOS again to start fresh.[/dim]"
            )

        logger.info(f"Onboarding cancelled, progress saved: {save}")

    def _save_partial_config(self) -> None:
        """Save whatever configuration has been set so far (first_run stays True)."""
        try:
            # Keep first_run True so wizard runs again next time
            self.config.first_run = True

            # Save whatever we have
            if self.username:
                self.config.user.name = self.username
            if self.role:
                self.config.user.role = self.role
            if self.skill_level:
                self.config.user.skill_level = self.skill_level

            self.config.save()
            logger.info("Partial config saved during interrupted onboarding")
        except Exception as e:
            logger.error(f"Failed to save partial config: {e}")
